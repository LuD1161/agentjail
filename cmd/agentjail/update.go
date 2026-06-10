// update.go — `agentjail update` self-update subcommand.
//
// Downloads the latest release tarball from GitHub, verifies its SHA256
// checksum against the upstream SHA256SUMS manifest (mirroring install.sh
// exactly), atomically replaces the installed binaries, and restarts the
// daemon. The entire operation is gated behind an interactive-TTY check —
// if stdin is not a real terminal, the command refuses with an explicit
// message, preventing any agent-driven self-modification.
//
// Platform notes:
//   - macOS: daemon is managed via launchd (launchctlUnload / launchctlLoad).
//   - Linux: daemon stop/restart is skipped (no launchd); binaries are still
//     swapped atomically. The daemon must be restarted manually or via the
//     user's init system.
//
// Binary list: agentjail, agentjail-hook, agentjail-daemon,
//
//	agentjail-shield, agentjail-netproxy  (mirrors install.sh).
//
// Atomic swap: each binary is downloaded to a temp file in the SAME directory
// as the target (guarantees os.Rename is on the same filesystem), chmod 0755,
// then renamed over the live binary. A crash between renames leaves at most
// one stale temp file, never a half-written binary.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
)

// updateBinaries is the ordered list of binaries placed in $INSTALL_DIR,
// matching install.sh exactly.
var updateBinaries = []string{
	"agentjail",
	"agentjail-hook",
	"agentjail-daemon",
	"agentjail-shield",
	"agentjail-netproxy",
}

// updateURLBaseFn returns the GitHub releases download base URL for a version.
// It is a package-level variable so tests can override it to point at a mock
// HTTP server without hitting the real GitHub API.
// Mirrors install.sh: https://github.com/${REPO}/releases/download/${VERSION}
var updateURLBaseFn = updateURLBase

// updateURLBase is the default implementation of updateURLBaseFn.
func updateURLBase(ver string) string {
	return fmt.Sprintf("https://github.com/LuD1161/agentjail/releases/download/%s", ver)
}

// updateTarballName returns the tarball filename for the given version and
// platform. Matches install.sh: agentjail-${VERSION}-${PLATFORM}.tar.gz
func updateTarballName(ver, goos, goarch string) string {
	return fmt.Sprintf("agentjail-%s-%s-%s.tar.gz", ver, goos, goarch)
}

// defaultUpdateInstallDir returns the binary installation directory, honouring
// AGENTJAIL_HOME (default: ~/.agentjail/bin).
func defaultUpdateInstallDir() (string, error) {
	home := os.Getenv("AGENTJAIL_HOME")
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home dir: %w", err)
		}
		home = filepath.Join(home, ".agentjail")
	}
	return filepath.Join(home, "bin"), nil
}

// runUpdate is the entry point for `agentjail update`.
// Returns an exit code (0 = success, 1 = error).
func runUpdate(_ []string) int {
	// ── SECURITY GATE: interactive TTY required ──────────────────────────────
	// This operation replaces agentjail's own binaries and restarts its daemon.
	// An agent MUST NOT be able to trigger it. We open /dev/tty directly — the
	// same pattern as confirmDisableInteractive in policy.go — so piped stdin,
	// agent tool calls, and sub-shells cannot bypass the guard.
	if !isInteractiveTTY() {
		fmt.Fprintf(os.Stderr,
			"agentjail update: REFUSED — no interactive terminal detected.\n"+
				"  Self-update replaces agentjail's own binaries and restarts the daemon.\n"+
				"  It must be run in a terminal by a human.\n"+
				"  This restriction prevents agents from self-modifying the security tool.\n")
		return 1
	}

	installDir, err := defaultUpdateInstallDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: %v\n", err)
		return 1
	}

	return performUpdate(installDir, currentGOOS, runtime.GOARCH)
}

// isInteractiveTTY returns true when /dev/tty can be opened for read-write,
// meaning a real human terminal is attached. This is the same guard used by
// confirmDisableInteractive in policy.go and cannot be defeated by redirecting
// stdin or stdout.
func isInteractiveTTY() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

// performUpdate is the testable core of runUpdate. It accepts an explicit
// installDir (tests pass a t.TempDir()) and goos/goarch for platform detection.
// Returns 0 on success, non-zero on error.
func performUpdate(installDir, goos, goarch string) int {
	current := version
	if current == "" {
		current = "dev"
	}

	// Step 1: fetch the latest version from GitHub.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest := fetchLatestVersion(ctx)
	if latest == "" {
		fmt.Fprintln(os.Stderr, "agentjail update: could not fetch latest version (check your network).")
		return 1
	}

	// Step 2: gate on version comparison.
	if !isNewerVersion(current, latest) {
		if !isSemver(current) {
			fmt.Printf("agentjail update: current build is a development version (%s); skipping update.\n", current)
		} else {
			fmt.Printf("agentjail update: already up to date (%s).\n", current)
		}
		return 0
	}

	fmt.Printf("agentjail update: %s → %s\n", current, latest)

	// Step 3: download tarball + SHA256SUMS into a temp directory.
	tmpDir, err := os.MkdirTemp("", "agentjail-update-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: create temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	tarball := updateTarballName(latest, goos, goarch)
	urlBase := updateURLBaseFn(latest)

	fmt.Printf("  downloading %s …\n", tarball)
	tarballPath := filepath.Join(tmpDir, tarball)
	if err := downloadFile(ctx, urlBase+"/"+tarball, tarballPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: download tarball: %v\n", err)
		return 1
	}

	sumsPath := filepath.Join(tmpDir, "SHA256SUMS")
	if err := downloadFile(ctx, urlBase+"/SHA256SUMS", sumsPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: download SHA256SUMS: %v\n", err)
		return 1
	}

	// Step 4: verify SHA256 — mirrors install.sh exactly.
	if err := verifySHA256(tarballPath, tarball, sumsPath); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: %v\n", err)
		return 1
	}
	fmt.Println("  checksum verified")

	// Step 5: extract tarball.
	if err := extractTarGz(tarballPath, tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: extract: %v\n", err)
		return 1
	}

	// Step 6: stop the daemon before swapping its binary (macOS/launchd only).
	plistPath := ""
	if goos == "darwin" {
		home, herr := os.UserHomeDir()
		if herr == nil {
			plistPath = filepath.Join(home, "Library", "LaunchAgents", plistFilename)
			if err := launchctlUnload(plistPath); err != nil {
				// Non-fatal — warn and continue; the rename is still atomic.
				fmt.Fprintf(os.Stderr, "  warning: could not stop daemon: %v\n", err)
				plistPath = "" // skip restart attempt
			}
		}
	}

	// Step 7: atomically replace each binary in the install directory.
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail update: mkdir %s: %v\n", installDir, err)
		if goos == "darwin" && plistPath != "" {
			_ = launchctlLoad(plistPath)
		}
		return 1
	}

	installed := 0
	for _, binName := range updateBinaries {
		src := filepath.Join(tmpDir, binName)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			// This binary was not shipped in the tarball — skip gracefully.
			continue
		}
		dst := filepath.Join(installDir, binName)
		if err := atomicReplaceBinary(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "agentjail update: replace %s: %v\n", binName, err)
			// Restart daemon (best-effort) if we stopped it, then fail.
			if goos == "darwin" && plistPath != "" {
				_ = launchctlLoad(plistPath)
			}
			return 1
		}
		installed++
	}

	// Step 8: restart the daemon.
	if goos == "darwin" && plistPath != "" {
		if err := launchctlLoad(plistPath); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not restart daemon: %v\n", err)
		} else {
			fmt.Println("  daemon restarted")
		}
	} else if goos != "darwin" {
		fmt.Println("  note: restart the agentjail daemon manually (non-macOS).")
	}

	fmt.Printf("agentjail update: updated %d binaries  %s → %s\n", installed, current, latest)

	// Step 9: emit update telemetry (best-effort; respects opt-out).
	if tp, err := telemetry.DefaultPaths(); err == nil {
		tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tCancel()
		_ = telemetry.SendUpdate(tCtx, tp, os.Getenv, current, latest, goos, goarch)
	}

	return 0
}

// downloadFile fetches url via HTTP and writes the body to dst.
func downloadFile(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "agentjail/"+version)

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

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

// verifySHA256 checks that the file at tarballPath matches the expected hash
// listed in sumsPath for the entry named tarballName.
//
// Mirrors install.sh exactly:
//
//	EXPECTED=$(grep "  ${TARBALL}$" "$TMP/SHA256SUMS" | awk '{print $1}')
//	ACTUAL=$(sha256 "$TMP/$TARBALL" | awk '{print $1}')
//	[ "$ACTUAL" != "$EXPECTED" ] → fail
func verifySHA256(tarballPath, tarballName, sumsPath string) error {
	sumsBytes, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}

	// Format: "<hex>  <filename>\n"  (two spaces, as output by sha256sum / shasum -a 256)
	expected := ""
	needle := "  " + tarballName
	for _, line := range strings.Split(string(sumsBytes), "\n") {
		if strings.HasSuffix(line, needle) {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				expected = fields[0]
			}
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("no SHA256 entry for %q in checksum manifest — aborting", tarballName)
	}

	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open tarball for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))

	if actual != expected {
		return fmt.Errorf("SHA256 mismatch — aborting\n  expected: %s\n  actual:   %s", expected, actual)
	}
	return nil
}

// extractTarGz extracts a .tar.gz archive into destDir (pure-Go, no exec).
// Only regular files are extracted, and file names are stripped to their base
// component to prevent path-traversal attacks.
func extractTarGz(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return extractTarGzReader(f, destDir)
}

// extractTarGzReader is the testable inner implementation of extractTarGz.
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

// atomicReplaceBinary copies src to a temp file in the same directory as dst,
// sets mode 0755, then renames over dst. Crash-safe: dst is only swapped on a
// successful rename; a failure mid-flight leaves dst untouched.
func atomicReplaceBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentjail-update-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return os.Rename(tmpName, dst)
}
