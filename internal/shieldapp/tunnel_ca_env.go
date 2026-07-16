package shieldapp

import "path/filepath"

// TunnelCACertName is the filename the per-session MITM CA's public cert is
// written under, inside the caDir returned by the per-OS setup.
const TunnelCACertName = "root.crt"

// TunnelCAEnv is the OS-agnostic contract for pointing an agent's TLS runtimes
// at the tunnel's MITM CA: the env vars every backend must set. Backends
// translate it into their own primitive (Linux also bind-mounts the cert over
// the namespace trust store; macOS has env only) but neither may re-list the
// variables. See ADR 0034 and ADR 0077.
//
// The system trust store is not enough on its own: Node ships a compiled-in CA
// bundle and Python's requests uses certifi's, so both ignore
// /etc/ssl/certs/ca-certificates.crt entirely. A Linux backend that only
// bind-mounts leaves every Node agent -- Claude Code included -- unable to
// verify the MITM cert (AGE-113).
//
// Two paths because the vars differ: bundlePath (system roots + our CA) for the
// ones that REPLACE the store, certPath (bare CA) for the ones that ADD to it.
// See AGE-221.
func TunnelCAEnv(certPath, bundlePath string) map[string]string {
	return map[string]string{
		// Go, curl, OpenSSL-linked tools. REPLACES the store.
		"SSL_CERT_FILE": bundlePath,
		// Python requests/certifi. REPLACES certifi's bundle.
		"REQUESTS_CA_BUNDLE": bundlePath,
		// Node.js. ADDITIVE by Node's own semantics -- it keeps its compiled-in
		// roots and adds this one, so it takes the bare CA.
		"NODE_EXTRA_CA_CERTS": certPath,
	}
}

// TunnelCACertPath returns the CA cert path inside a caDir.
func TunnelCACertPath(caDir string) string {
	return filepath.Join(caDir, TunnelCACertName)
}
