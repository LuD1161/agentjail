//go:build darwin

package shieldapp

import (
	"fmt"
	"os"
	"path/filepath"
)

// setupTunnelCADarwin configures per-process CA trust for the tunnel MITM CA
// on macOS. Unlike Linux, macOS has no mount-namespace mechanism, so this
// function returns environment variables that direct each TLS runtime at the
// CA certificate in caDir instead of bind-mounting it into a namespace:
//
//   - SSL_CERT_FILE:       overrides the system CA bundle for Go, curl, and
//     OpenSSL-linked tools. In tunnel mode, all TLS traffic flows through the
//     MITM proxy which re-signs upstream certs with this CA, so the agent only
//     needs to trust the tunnel CA rather than the full system bundle.
//   - NODE_EXTRA_CA_CERTS: adds the CA to Node.js's trust store (additive;
//     does not replace system CAs).
//   - REQUESTS_CA_BUNDLE:  overrides the CA bundle for Python's requests lib.
//
// Known gap: macOS system frameworks (URLSession, CFNetwork) ignore these env
// vars and require system-wide keychain trust via `security add-trusted-cert`.
// Tools that use native Apple frameworks will fail TLS verification in tunnel
// mode. This covers the common case (curl, Go HTTP client, Node.js, Python
// requests) without requiring a password prompt or persistent keychain changes.
//
// caDir must already contain root.crt written by mitm.GenerateCA before this
// function is called. The returned cleanup removes any additional temp files
// created by this function; caDir itself is owned by the caller and must
// remain on disk until the agent process exits (SSL_CERT_FILE points into it).
func setupTunnelCADarwin(caDir string) (envVars map[string]string, cleanup func(), err error) {
	certPath := filepath.Join(caDir, "root.crt")
	if _, statErr := os.Stat(certPath); statErr != nil {
		return nil, func() {}, fmt.Errorf("tunnel CA cert not found at %s: %w", certPath, statErr)
	}

	vars := map[string]string{
		"SSL_CERT_FILE":       certPath,
		"NODE_EXTRA_CA_CERTS": certPath,
		"REQUESTS_CA_BUNDLE":  certPath,
	}

	// cleanup is a no-op: caDir is owned by the caller who must keep it alive
	// until the agent exits. The caller removes caDir on the error path only.
	return vars, func() {}, nil
}
