// download.go — download, verify, and extract release tarballs.
//
// These helpers are shared between the CLI (cmd/agentjail/update.go) and the
// daemon auto-update path.  All functions are exported so they can be called
// from either binary.
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/updater"
)

// MaxDownloadBytes is the maximum number of bytes allowed per download (100 MB).
const MaxDownloadBytes int64 = 100 * 1024 * 1024

// UpdateURLBaseFn returns the primary download base URL for a version.
// It is a package-level variable so tests can override it to point at a mock
// HTTP server without hitting the real network.
var UpdateURLBaseFn = UpdateURLBase

// UpdateURLBase is the default implementation of UpdateURLBaseFn.
// It routes through the Cloudflare Worker at releases.agentjail.io first; the
// Worker itself proxies to GitHub, providing integrity checks and analytics.
func UpdateURLBase(ver string) string {
	return fmt.Sprintf("https://releases.agentjail.io/download/%s", ver)
}

// UpdateURLBaseFallback returns the direct GitHub releases URL as a fallback
// when the Worker URL is unreachable.
func UpdateURLBaseFallback(ver string) string {
	return fmt.Sprintf("https://github.com/LuD1161/agentjail/releases/download/%s", ver)
}

// TarballName returns the tarball filename for the given version and platform.
// Matches install.sh: agentjail-${VERSION}-${PLATFORM}.tar.gz
func TarballName(ver, goos, goarch string) string {
	return fmt.Sprintf("agentjail-%s-%s-%s.tar.gz", ver, goos, goarch)
}

// DownloadFile fetches url via HTTP and writes the body to dst.
// maxBytes caps the download; pass MaxDownloadBytes for the production limit.
func DownloadFile(ctx context.Context, url, dst string, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "agentjail")

	hc := &http.Client{Timeout: 60 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer f.Close()

	// Enforce the download cap to prevent runaway/malicious responses.
	limited := io.LimitReader(resp.Body, maxBytes+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if n > maxBytes {
		return fmt.Errorf("download of %s exceeds %d MB limit; aborting", dst, maxBytes/(1024*1024))
	}
	return nil
}

// VerifyTarball checks that the file at tarballPath matches the expected hash
// listed in sumsPath for the entry named tarballName.
//
// Mirrors install.sh exactly:
//
//	EXPECTED=$(grep "  ${TARBALL}$" "$TMP/SHA256SUMS" | awk '{print $1}')
//	ACTUAL=$(sha256 "$TMP/$TARBALL" | awk '{print $1}')
//	[ "$ACTUAL" != "$EXPECTED" ] → fail
func VerifyTarball(tarballPath, tarballName, sumsPath string) error {
	return updater.VerifyHash(tarballPath, tarballName, sumsPath)
}

// VerifyManifest verifies the minisign signature on the SHA256SUMS file.
// It uses SigningPubKey from signingkey.go.  If SigningPubKey is empty,
// verification is skipped (matches dev build behaviour).
func VerifyManifest(sumsPath, sigPath string) error {
	if SigningPubKey == "" {
		return nil
	}
	return updater.VerifySignature(sumsPath, sigPath, SigningPubKey)
}

// ExtractTarball extracts a .tar.gz archive into destDir (pure-Go, no exec).
// Only regular files are extracted, and file names are stripped to their base
// component to prevent path-traversal attacks.
func ExtractTarball(tarballPath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return extractTarGzReader(f, destDir)
}

// extractTarGzReader is the testable inner implementation of ExtractTarball.
func extractTarGzReader(r io.Reader, destDir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		// Only regular files.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Strip any directory prefix: only the base file name is written.
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." {
			continue
		}
		dst := filepath.Join(destDir, name)
		out, err := os.Create(dst)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}
	return nil
}
