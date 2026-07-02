package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	r.register(tok, "sess-id-a", "/tmp/proj-a", proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com"}}, time.Hour, now)

	s, ok := r.lookup(tok, now.Add(time.Minute))
	if !ok || !s.allowed("api.github.com", now) || s.allowed("evil.com", now) {
		t.Fatalf("lookup within lease: ok=%v session=%v", ok, s)
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
	res := r.reap(now.Add(2 * time.Hour))
	if len(res.ExpiredSessions) != 1 || res.ExpiredSessions[0] != tok {
		t.Errorf("reap expired: got %v", res.ExpiredSessions)
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
	r.register(tok, "sess-id-cap", "/tmp/proj-cap", proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}, 1000*time.Hour, now)
	if _, ok := r.lookup(tok, now.Add(maxLease-time.Minute)); !ok {
		t.Error("should be live just before the hard cap")
	}
	if _, ok := r.lookup(tok, now.Add(maxLease+time.Minute)); ok {
		t.Error("must be expired past the hard lease cap regardless of requested TTL")
	}
	// Zero/negative TTL also clamps to the cap (never an immediate/never expiry surprise).
	r.register(tok, "sess-id-cap", "/tmp/proj-cap", proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}, 0, now)
	if _, ok := r.lookup(tok, now.Add(time.Hour)); !ok {
		t.Error("zero TTL should clamp to the cap, not expire immediately")
	}
}

// startTestControlServer spins a control server on a temp socket and serves it
// until the returned cancel is called. durableAudit is forwarded to
// newControlServer so tests can exercise the fail-closed grant_approve gate.
func startTestControlServer(t *testing.T, emitter audit.Emitter, durableAudit bool) (*controlServer, string, context.CancelFunc) {
	t.Helper()
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "netproxy-ctl.sock")
	reg := newSessionRegistry()
	cs, err := newControlServer(sock, reg, emitter, durableAudit, "test-1.2.3", testLogger())
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
	_, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
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
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	pol := proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com", "*.claude.ai"}}
	resp := controlRoundTrip(t, sock, proxyctl.Request{
		Type:       proxyctl.ReqRegister,
		Token:      "tok-xyz",
		SessionID:  "sess-xyz",
		Cwd:        "/tmp/proj",
		Policy:     &pol,
		LeaseTTLMs: 3600000,
	})
	if !resp.OK {
		t.Fatalf("register failed: %+v", resp)
	}
	s, ok := cs.registry.lookup("tok-xyz", time.Now())
	if !ok || !s.allowed("api.github.com", time.Now()) || !s.allowed("foo.claude.ai", time.Now()) {
		t.Fatalf("registry lookup after register: ok=%v session=%v", ok, s)
	}
	if s.sessionID != "sess-xyz" || s.cwd != "/tmp/proj" {
		t.Errorf("session identity not stored: sessionID=%q cwd=%q", s.sessionID, s.cwd)
	}
}

func TestControlServerRejectsBadRequests(t *testing.T) {
	_, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
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

// ---- Runtime host grants (AGE-93): grant_list / grant_approve / grant_deny ----

func TestControlServerGrantList(t *testing.T) {
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	now := time.Now()
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: []string{"x.com"}}, time.Hour, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 3600000, "need it for tests", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantList})
	if !resp.OK {
		t.Fatalf("grant_list failed: %+v", resp)
	}
	if len(resp.Grants) != 1 {
		t.Fatalf("expected 1 pending grant, got %d: %+v", len(resp.Grants), resp.Grants)
	}
	g := resp.Grants[0]
	if g.GrantID != pg.GrantID || g.Host != "api.example.com" || g.Cwd != "/repo/a" || g.Reason != "need it for tests" {
		t.Errorf("grant_list entry mismatch: %+v", g)
	}
}

func TestControlServerGrantApprove_AppliesAndDoubleApproveIsNoop(t *testing.T) {
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	now := time.Now()
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 3600000, "", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantApprove, GrantID: pg.GrantID})
	if !resp.OK {
		t.Fatalf("grant_approve failed: %+v", resp)
	}
	s, ok := cs.registry.lookup("tok-a", now)
	if !ok || !s.allowed("api.example.com", now) {
		t.Fatalf("approved host not allowed: ok=%v", ok)
	}

	// Second approve of the same grant_id must be a no-op/error (one winner).
	resp2 := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantApprove, GrantID: pg.GrantID})
	if resp2.OK {
		t.Error("double approve should fail (grant already claimed)")
	}
	// Still only one granted entry.
	if len(s.granted) != 1 {
		t.Errorf("expected exactly 1 granted entry after double approve, got %d", len(s.granted))
	}
}

func TestControlServerGrantApprove_ExpiredGrantDeniedAfterTTL(t *testing.T) {
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	now := time.Now()
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 1000, "", now) // 1s TTL
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}
	if resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantApprove, GrantID: pg.GrantID}); !resp.OK {
		t.Fatalf("grant_approve failed: %+v", resp)
	}

	s, _ := cs.registry.lookup("tok-a", now)
	if !s.allowed("api.example.com", now) {
		t.Fatal("expected allowed immediately after approve")
	}
	if s.allowed("api.example.com", now.Add(2*time.Second)) {
		t.Error("expected denied after the granted TTL lapses")
	}
}

func TestControlServerGrantApprove_DeadLeaseSessionRefused(t *testing.T) {
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	now := time.Now()
	// Lease expires in 500ms; pending grant TTL is far longer so it survives.
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: nil}, 500*time.Millisecond, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 3600000, "", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	// Directly exercise approveGrant with a "later" now past the lease expiry
	// (the control socket path always uses time.Now(), so we drive the
	// registry method directly to simulate a dead lease deterministically).
	_, aerr := cs.registry.approveGrant(pg.GrantID, now.Add(time.Second), func(string) error { return nil })
	if aerr == nil {
		t.Fatal("expected approve to be refused for a dead-lease session")
	}
	_ = sock // control-socket wiring already covered by the other approve tests
}

func TestControlServerGrantApprove_AuditUnavailableRefusesAndDoesNotApply(t *testing.T) {
	// durableAudit=false: grant_approve must be refused outright, and the
	// grant must NOT be applied (fail-closed audit, ADR 0044).
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, false)
	defer done()

	now := time.Now()
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 3600000, "", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantApprove, GrantID: pg.GrantID})
	if resp.OK {
		t.Fatal("grant_approve must be refused when audit is unavailable")
	}

	s, ok := cs.registry.lookup("tok-a", now)
	if !ok || s.allowed("api.example.com", now) {
		t.Fatal("grant must not have been applied when audit is unavailable")
	}
	// Because approve was refused before ever touching the pending set, the
	// request remains pending and could be retried once audit is available.
	resp2 := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantList})
	if !resp2.OK || len(resp2.Grants) != 1 {
		t.Fatalf("expected the pending grant to remain untouched: %+v", resp2)
	}
}

func TestControlServerGrantDeny(t *testing.T) {
	cs, sock, done := startTestControlServer(t, audit.NopEmitter{}, true)
	defer done()

	now := time.Now()
	cs.registry.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, now)
	pg, err := cs.registry.requestGrant("tok-a", "api.example.com", 3600000, "", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	resp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantDeny, GrantID: pg.GrantID})
	if !resp.OK {
		t.Fatalf("grant_deny failed: %+v", resp)
	}
	s, _ := cs.registry.lookup("tok-a", now)
	if s.allowed("api.example.com", now) {
		t.Error("denied grant must not be applied")
	}
	listResp := controlRoundTrip(t, sock, proxyctl.Request{Type: proxyctl.ReqGrantList})
	if len(listResp.Grants) != 0 {
		t.Errorf("expected no pending grants after deny, got %+v", listResp.Grants)
	}
}

func TestSessionRegistryRequestGrant_CapsAndCoalescing(t *testing.T) {
	r := newSessionRegistry()
	now := time.Now()
	r.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{}, time.Hour, now)

	// Duplicate coalescing: same session+host updates in place, no growth.
	if _, err := r.requestGrant("tok-a", "api.example.com", 1000, "first", now); err != nil {
		t.Fatalf("requestGrant: %v", err)
	}
	pg2, err := r.requestGrant("tok-a", "api.example.com", 2000, "second", now)
	if err != nil {
		t.Fatalf("requestGrant coalesce: %v", err)
	}
	if len(r.listPending()) != 1 {
		t.Fatalf("expected coalescing to keep exactly 1 pending, got %d", len(r.listPending()))
	}
	if pg2.TTLMs != 2000 || pg2.Reason != "second" {
		t.Errorf("coalesced entry not updated: %+v", pg2)
	}

	// Per-session cap.
	for i := 0; i < proxyctl.MaxPendingPerSession; i++ {
		host := fmt.Sprintf("host%d.example.com", i)
		if _, err := r.requestGrant("tok-a", host, 1000, "", now); err != nil {
			// The coalesced entry above counts toward the cap too, so this may
			// legitimately start failing right at the boundary.
			break
		}
	}
	if _, err := r.requestGrant("tok-a", "one-too-many.example.com", 1000, "", now); !errors.Is(err, errPendingCapSession) {
		t.Errorf("expected errPendingCapSession once the per-session cap is hit, got %v", err)
	}
}

func TestSessionRegistryReap_PrunesStalePendingAndExpiredGrants(t *testing.T) {
	r := newSessionRegistry()
	now := time.Now()
	// A long session lease so only the (shorter) grant/pending expiries prune
	// in this test -- the session itself must stay live throughout.
	r.register("tok-a", "sess-a", "/repo/a", proxyctl.SessionPolicy{}, 100*time.Hour, now)

	pg, err := r.requestGrant("tok-a", "api.example.com", 1000, "", now)
	if err != nil {
		t.Fatalf("requestGrant: %v", err)
	}
	if _, err := r.approveGrant(pg.GrantID, now, func(string) error { return nil }); err != nil {
		t.Fatalf("approveGrant: %v", err)
	}

	// A second, never-approved pending request goes stale after pendingGrantTTL.
	if _, err := r.requestGrant("tok-a", "stale.example.com", 3600000, "", now); err != nil {
		t.Fatalf("requestGrant: %v", err)
	}

	later := now.Add(pendingGrantTTL + time.Minute)
	res := r.reap(later)
	if len(res.ExpiredGrants) != 1 || res.ExpiredGrants[0].GrantID != pg.GrantID {
		t.Errorf("expected the approved (short-TTL) grant to be reaped as expired: %+v", res.ExpiredGrants)
	}
	if len(r.listPending()) != 0 {
		t.Errorf("expected the stale pending request to be reaped, got %v", r.listPending())
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
