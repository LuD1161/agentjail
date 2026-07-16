package shieldapp

import "testing"

// The CA-trust env is a shared contract, not a per-OS list. Linux regressed by
// omission here: it bind-mounted the cert over the namespace trust store and
// set no env at all, so Node (Claude Code's runtime) and Python requests --
// which ignore the system store and use bundled roots -- could not verify the
// MITM cert (AGE-113). macOS had the vars all along. ADR 0034.
func TestTunnelCAEnvCoversBundledRootRuntimes(t *testing.T) {
	const cert = "/tmp/agentjail-tunnel-ca-x/root.crt"
	env := TunnelCAEnv(cert)

	// Each entry is a runtime that would otherwise not trust the MITM CA.
	for _, key := range []string{
		"SSL_CERT_FILE",       // Go, curl, OpenSSL
		"NODE_EXTRA_CA_CERTS", // Node: bundled roots, ignores the system store
		"REQUESTS_CA_BUNDLE",  // Python requests/certifi: same
	} {
		got, ok := env[key]
		if !ok {
			t.Errorf("%s missing: that runtime cannot verify the tunnel CA", key)
			continue
		}
		if got != cert {
			t.Errorf("%s = %q, want the CA cert path %q", key, got, cert)
		}
	}
}

func TestTunnelCACertPath(t *testing.T) {
	if got, want := TunnelCACertPath("/tmp/ca"), "/tmp/ca/"+TunnelCACertName; got != want {
		t.Errorf("TunnelCACertPath = %q, want %q", got, want)
	}
}
