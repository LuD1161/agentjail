package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// shortSocketDir returns a short-path temp dir. t.TempDir() on macOS lives under
// /var/folders/... which blows past the ~104-byte AF_UNIX sun_path limit, so
// unix bind() fails in tests only (the real ~/.agentjail/run path is short).
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ajnp")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestSessionRegistryLifecycle(t *testing.T) {
	r := newSessionRegistry()
	now := time.Unix(1_700_000_000, 0)
	tok := proxyctl.Token("sess-a")
	r.register(tok, proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com"}}, time.Hour, now)

	hosts, ok := r.lookup(tok, now.Add(time.Minute))
	if !ok || len(hosts) != 1 || hosts[0] != "api.github.com" {
		t.Fatalf("lookup within lease: got %v ok=%v", hosts, ok)
	}
	// Different token -> deny, no bleed.
	if _, ok := r.lookup(proxyctl.Token("sess-b"), now); ok {
		t.Error("unknown token must not resolve (no global fallback)")
	}
	// Empty token -> deny.
	if _, ok := r.lookup("", now); ok {
		t.Error("empty token must be denied")
	}
	// After lease expiry -> deny, then reaped.
	if _, ok := r.lookup(tok, now.Add(2*time.Hour)); ok {
		t.Error("expired lease must be denied")
	}
	reaped := r.reap(now.Add(2 * time.Hour))
	if len(reaped) != 1 || reaped[0] != tok {
		t.Errorf("reap expired: got %v", reaped)
	}
	if r.count() != 0 {
		t.Errorf("registry should be empty after reap, have %d", r.count())
	}
}

func TestSessionRegistryLeaseCapped(t *testing.T) {
	r := newSessionRegistry()
	now := time.Unix(1_700_000_000, 0)
	tok := proxyctl.Token("sess-cap")
	// Request an absurd TTL; it must be clamped to maxLease so a token cannot
	// live forever even if the registrar asks for it.
	r.register(tok, proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}, 1000*time.Hour, now)
	if _, ok := r.lookup(tok, now.Add(maxLease-time.Minute)); !ok {
		t.Error("should be live just before the hard cap")
	}
	if _, ok := r.lookup(tok, now.Add(maxLease+time.Minute)); ok {
		t.Error("must be expired past the hard lease cap regardless of requested TTL")
	}
	// Zero/negative TTL also clamps to the cap (never an immediate/never expiry surprise).
	r.register(tok, proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}, 0, now)
	if _, ok := r.lookup(tok, now.Add(time.Hour)); !ok {
		t.Error("zero TTL should clamp to the cap, not expire immediately")
	}
}

// startTestControlServer spins a control server on a temp socket and serves it
// until the returned cancel is called.
func startTestControlServer(t *testing.T) (*controlServer, string, context.CancelFunc) {
	t.Helper()
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "netproxy-ctl.sock")
	reg := newSessionRegistry()
	cs, err := newControlServer(sock, reg, audit.NopEmitter{}, "test-1.2.3", testLogger())
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go cs.serve(ctx)
	return cs, sock, func() { cancel(); cs.close() }
}

func controlRoundTrip(t *testing.T, sock string, req proxyctl.Request) proxyctl.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial control socket: %v", err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp proxyctl.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func TestControlServerFingerprint(t *testing.T) {
	_, sock, done := startTestControlServer(t)
	defer done()

	resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqFingerprint})
	if !resp.OK || resp.Fingerprint == nil {
		t.Fatalf("fingerprint response not ok: %+v", resp)
	}
	if resp.Fingerprint.ProtocolVersion != proxyctl.CurrentProtocolVersion {
		t.Errorf("protocol version = %d; want %d", resp.Fingerprint.ProtocolVersion, proxyctl.CurrentProtocolVersion)
	}
	if resp.Fingerprint.BinaryVersion != "test-1.2.3" {
		t.Errorf("binary version = %q; want test-1.2.3", resp.Fingerprint.BinaryVersion)
	}
}

func TestControlServerRegisterThenLookup(t *testing.T) {
	cs, sock, done := startTestControlServer(t)
	defer done()

	pol := proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com", "*.claude.ai"}}
	resp := controlRoundTrip(t, sock, proxyctl.Request{
		Type:       proxyctl.ReqRegister,
		Token:      "tok-xyz",
		Policy:     &pol,
		LeaseTTLMs: 3600000,
	})
	if !resp.OK {
		t.Fatalf("register failed: %+v", resp)
	}
	hosts, ok := cs.registry.lookup("tok-xyz", time.Now())
	if !ok || len(hosts) != 2 {
		t.Fatalf("registry lookup after register: %v ok=%v", hosts, ok)
	}
}

func TestControlServerRejectsBadRequests(t *testing.T) {
	_, sock, done := startTestControlServer(t)
	defer done()

	// Register without a token.
	pol := proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}
	if resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqRegister, Policy: &pol}); resp.OK {
		t.Error("register without token should fail")
	}
	// Register without a policy.
	if resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqRegister, Token: "t"}); resp.OK {
		t.Error("register without policy should fail")
	}
	// Grant is not served in Phase 1.
	if resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrant, Token: "t"}); resp.OK {
		t.Error("grant must be unsupported in Phase 1")
	}
}

func TestAcquireControlSocketSingleton(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "netproxy-ctl.sock")

	ln1, lock1, err := acquireControlSocket(sock, testLogger())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { ln1.Close(); lock1.Close() }()

	// Second acquire on the same path must fail (lock held) -- we never let two
	// proxies own the socket, and we never kill the first.
	if _, _, err := acquireControlSocket(sock, testLogger()); err == nil {
		t.Fatal("second acquire should fail while the first holds the lock")
	}
}

func TestAcquireControlSocketClearsStale(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "netproxy-ctl.sock")

	// Simulate a stale socket file left by a crashed predecessor: a socket path
	// that exists on disk but has no live listener.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("prep stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false) // leave the file behind, like a crash
	stale.Close()
	if _, statErr := os.Stat(sock); statErr != nil {
		t.Skipf("kernel unlinked the socket on close; cannot simulate stale (%v)", statErr)
	}

	// Acquire should detect nothing live answers, remove the stale file, and bind.
	ln, lock, err := acquireControlSocket(sock, testLogger())
	if err != nil {
		t.Fatalf("acquire over stale socket should succeed: %v", err)
	}
	ln.Close()
	lock.Close()
}
