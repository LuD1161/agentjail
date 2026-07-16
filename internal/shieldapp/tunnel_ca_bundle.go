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
// returns its path. SSL_CERT_FILE and REQUESTS_CA_BUNDLE replace the trust
// store, so the bare CA leaves non-intercepted TLS unverifiable. Roots come
// from the per-OS systemRootsPEM; assembly is shared (ADR 0034). See AGE-221.
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

	// 0644: public certificate material only. The CA key never touches disk
	// (ADR 0076 S-C1).
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
