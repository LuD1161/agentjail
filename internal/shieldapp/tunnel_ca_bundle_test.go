package shieldapp

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/mitm"
)

// SSL_CERT_FILE and REQUESTS_CA_BUNDLE replace the trust store, so pointing
// them at the bare CA left the agent trusting only agentjail. AGE-221.
func TestTunnelCAEnvSplitsReplacingFromAdditive(t *testing.T) {
	env := TunnelCAEnv("/ca/root.crt", "/ca/bundle.crt")

	for _, v := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"} {
		if env[v] != "/ca/bundle.crt" {
			t.Errorf("%s = %q, want the combined bundle: this variable REPLACES the "+
				"trust store, so the bare CA would leave nothing to verify a "+
				"non-intercepted endpoint against", v, env[v])
		}
	}

	// Node keeps its compiled-in roots and adds this one, so the bare cert is
	// correct here -- handing it the bundle would be harmless but wrong in
	// intent, and would hide the distinction the next reader needs.
	if env["NODE_EXTRA_CA_CERTS"] != "/ca/root.crt" {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want the bare CA (it is additive)", env["NODE_EXTRA_CA_CERTS"])
	}
}

// The bundle must contain the public roots AND our CA -- that is the whole
// point of the ticket. Verified by parsing, not by counting bytes.
func TestWriteCABundleContainsSystemRootsAndSessionCA(t *testing.T) {
	roots, err := systemRootsPEM()
	if err != nil {
		t.Skipf("no system trust store readable on this host: %v", err)
	}

	caDir := t.TempDir()
	caPEM := writeProbeCA(t, caDir)

	path, err := WriteCABundle(caDir)
	if err != nil {
		t.Fatalf("WriteCABundle: %v", err)
	}

	bundle, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Our CA must be in there.
	if !strings.Contains(string(bundle), strings.TrimSpace(string(caPEM))) {
		t.Error("bundle does not contain the session CA — interception would fail")
	}

	// And it must still parse as a superset of the system roots: a pool built
	// from the bundle must accept at least as many roots as the system one.
	sysPool := x509.NewCertPool()
	sysPool.AppendCertsFromPEM(roots)
	bundlePool := x509.NewCertPool()
	if !bundlePool.AppendCertsFromPEM(bundle) {
		t.Fatal("bundle is not parseable PEM")
	}
	if got, want := len(bundlePool.Subjects()), len(sysPool.Subjects())+1; got != want { //nolint:staticcheck // Subjects is fine for a count
		t.Errorf("bundle has %d roots, want %d (system roots + our CA) — "+
			"a truncated bundle silently breaks verification of real endpoints", got, want)
	}
}

// New file writing next to the CA must not have introduced a key on disk. The
// agent shares our uid, so a persisted private key would let it mint trusted
// certs. ADR 0077 retains ADR 0076 condition 3.
func TestWriteCABundleLeavesNoPrivateKeyOnDisk(t *testing.T) {
	caDir := t.TempDir()
	writeProbeCA(t, caDir)

	if _, err := WriteCABundle(caDir); err != nil {
		t.Skipf("WriteCABundle unavailable here: %v", err)
	}

	entries, err := os.ReadDir(caDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(caDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Errorf("%s contains a private key — the CA key must never touch disk", e.Name())
		}
	}
}

// writeProbeCA drops a self-signed cert at caDir/root.crt and returns its PEM.
func writeProbeCA(t *testing.T, caDir string) []byte {
	t.Helper()
	// A real generated CA, so the bundle parses as genuine PEM.
	cert, _, certPEM, err := generateProbeCA()
	if err != nil {
		t.Fatalf("generate probe CA: %v", err)
	}
	_ = cert
	if err := os.WriteFile(TunnelCACertPath(caDir), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sanity: it must decode.
	if blk, _ := pem.Decode(certPEM); blk == nil {
		t.Fatal("probe CA is not PEM")
	}
	return certPEM
}

// generateProbeCA wraps the real CA generator so the test uses genuine PEM
// rather than a hand-rolled fixture.
func generateProbeCA() (cert interface{}, key interface{}, certPEM []byte, err error) {
	c, k, p, e := mitm.GenerateCAInMemory()
	return c, k, p, e
}
