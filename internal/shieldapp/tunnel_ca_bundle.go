package shieldapp

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// TunnelCABundleName is the filename of the combined trust bundle (the system
// roots plus this session's CA) written next to the CA cert in caDir.
const TunnelCABundleName = "bundle.crt"

// TunnelCABundlePath returns the combined bundle's path inside a caDir.
func TunnelCABundlePath(caDir string) string {
	return filepath.Join(caDir, TunnelCABundleName)
}

// WriteCABundle writes "system roots + this session's CA" into caDir and
// returns its path.
//
// SSL_CERT_FILE and REQUESTS_CA_BUNDLE *replace* their trust store rather than
// adding to it, so pointing them at the bare CA left the agent trusting only
// agentjail. Under full interception that mostly works -- every upstream is
// re-signed by us -- but it is load-bearing on an assumption that is not always
// true: any TLS we do not terminate (a non-443 port today) then has no roots to
// verify against. The fix is a bundle that contains both. AGE-221.
//
// The roots come from systemRootsPEM, which each OS backend defines; the
// assembly is shared so the two platforms cannot disagree about what the bundle
// is. ADR 0034-platform-backend-shared-contract.
func WriteCABundle(caDir string) (string, error) {
	caPEM, err := os.ReadFile(TunnelCACertPath(caDir))
	if err != nil {
		return "", fmt.Errorf("read session CA cert: %w", err)
	}

	roots, err := systemRootsPEM()
	if err != nil {
		return "", fmt.Errorf("read system roots: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(roots)
	if len(roots) > 0 && !bytes.HasSuffix(roots, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.Write(caPEM)

	// 0644: this is public certificate material only. The CA private key is
	// never written to disk (ADR 0077, retaining ADR 0076 condition 3) -- the
	// agent shares our uid, so a key on disk would let it mint trusted certs.
	path := TunnelCABundlePath(caDir)
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("write CA bundle: %w", err)
	}
	return path, nil
}

// firstReadableFile returns the contents of the first path that can be read.
func firstReadableFile(paths []string) ([]byte, string, error) {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b, p, nil
		}
	}
	return nil, "", fmt.Errorf("no readable system trust store in %v", paths)
}
