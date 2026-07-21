package shieldapp

// Body-transcript recording is OS-agnostic (see tunnel_body.go's doc
// comment); this test file carries no build tag so it runs on every host.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/keyring"
	"github.com/LuD1161/agentjail/internal/mitm"
)

// captureEmitter records events so a test can assert what reached agentjail.db.
type captureEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureEmitter) Emit(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureEmitter) find(eventType string) (audit.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.EventType == eventType {
			return e, true
		}
	}
	return audit.Event{}, false
}

// stubBodyKeys swaps the KEK seam and the body dir for one test.
func stubBodyKeys(t *testing.T, keys mitm.KeyWrapper, backend string, err error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	orig := openBodyKeys
	openBodyKeys = func() (mitm.KeyWrapper, string, error) { return keys, backend, err }
	t.Cleanup(func() { openBodyKeys = orig })
}

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// sendThroughTunnel drives one HTTPS request carrying canary through a MITM
// handler wired to rec's store, and returns the row's body paths.
func sendThroughTunnel(t *testing.T, bodies *mitm.BodyStore, canary string) *mitm.RequestLog {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, canary)
	}))
	defer upstream.Close()

	caCert, caKey, err := mitm.GenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	logs := make(chan *mitm.RequestLog, 4)
	h := mitm.NewMITMHandler(caCert, caKey, testLogger(io.Discard), func(rl *mitm.RequestLog) { logs <- rl })
	h.Bodies = bodies
	h.SessionID = bodies.SessionID()
	h.UpstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	go h.Handle(serverConn, "localhost", port)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	c := tls.Client(clientConn, &tls.Config{ServerName: "localhost", RootCAs: pool})
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest("POST", "https://localhost/x", strings.NewReader(canary))
	go req.Write(c)
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case rl := <-logs:
		return rl
	case <-t.Context().Done():
		t.Fatal("no request log emitted")
		return nil
	}
}

// With a working KeyWrapper the session's bodies land under bodies/<session>
// and no byte of the canary is readable at rest.
// See ADR 0092-persist-request-bodies (D1), ADR 0095-chunked-body-envelope.
func TestBodiesEncryptedWhenKeyringAvailable(t *testing.T) {
	keys, err := mitm.NewMemoryKeyWrapper()
	if err != nil {
		t.Fatalf("NewMemoryKeyWrapper: %v", err)
	}
	stubBodyKeys(t, keys, "test-keychain", nil)
	emitter := &captureEmitter{}

	rec := newBodyRecording(context.Background(), "aaaabbbbccccdddd", testLogger(io.Discard), emitter)
	if rec.store == nil {
		t.Fatal("store is nil: a working KeyWrapper must yield a body store")
	}
	if !rec.encrypted {
		t.Fatal("rec.encrypted = false: a working KeyWrapper must record bodies encrypted")
	}
	if _, ok := emitter.find(audit.TunnelBodiesUnencrypted); ok {
		t.Error("emitted tunnel.bodies_unencrypted while bodies ARE encrypted")
	}

	const canary = "SUPER-SECRET-CANARY-do-not-store-in-the-clear"
	rl := sendThroughTunnel(t, rec.store, canary)
	if rl.RequestBodyPath == "" {
		t.Fatal("RequestBodyPath is empty: the body was not captured at all")
	}
	if !strings.HasPrefix(rl.RequestBodyPath, "aaaabbbbccccdddd/") {
		t.Errorf("RequestBodyPath = %q, want it grouped under the session dir", rl.RequestBodyPath)
	}

	for _, rel := range []string{rl.RequestBodyPath, rl.ResponseBodyPath} {
		if rel == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(rec.store.Dir(), rel))
		if err != nil {
			t.Fatalf("read %s at rest: %v", rel, err)
		}
		if strings.Contains(string(raw), canary) {
			t.Errorf("%s holds the canary in PLAINTEXT at rest (%d bytes)", rel, len(raw))
		}
	}
	// The store must still be able to read back what it sealed.
	rc, err := rec.store.Open(rl.RequestBodyPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", rl.RequestBodyPath, err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != canary {
		t.Errorf("decrypted body = %q, want the canary back", got)
	}
}

// ErrNoKeychain must not stop recording: bodies are captured in the clear, and
// the degradation is loud on stderr AND durable in the audit log.
// See ADR 0092-persist-request-bodies (D5).
func TestNoKeychainRecordsInClearLoudlyAndAudits(t *testing.T) {
	keyErr := errors.New("keyring: no OS keychain available: linux Secret Service backend is not implemented")
	stubBodyKeys(t, nil, "", errors.Join(keyring.ErrNoKeychain, keyErr))
	emitter := &captureEmitter{}
	var logbuf strings.Builder

	var rec bodyRecording
	stderr := captureStderr(t, func() {
		rec = newBodyRecording(context.Background(), "eeeeffff00001111", testLogger(&logbuf), emitter)
	})

	if rec.store == nil {
		t.Fatal("store is nil: ErrNoKeychain must NOT stop recording")
	}
	if rec.encrypted {
		t.Fatal("rec.encrypted = true with no keychain: the posture is being overclaimed")
	}

	// 1. loud on stderr, not only in a log file.
	if !strings.Contains(stderr, "IN THE CLEAR") || !strings.Contains(stderr, "UNENCRYPTED") {
		t.Errorf("stderr notice is not loud about plaintext bodies; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, mitm.DefaultBodyDir()) {
		t.Errorf("stderr notice does not say WHERE the plaintext lands; got:\n%s", stderr)
	}

	// 2. audited: network.db cannot hold its own failure.
	ev, ok := emitter.find(audit.TunnelBodiesUnencrypted)
	if !ok {
		t.Fatalf("no %s audit event emitted; got %v", audit.TunnelBodiesUnencrypted, emitter.events)
	}
	if ev.SessionID != "eeeeffff00001111" {
		t.Errorf("audit SessionID = %q, want the session that is recording in the clear", ev.SessionID)
	}
	if ev.Detail["reason"] != audit.TunnelKeysAbsent {
		t.Errorf("audit reason = %q, want %s", ev.Detail["reason"], audit.TunnelKeysAbsent)
	}

	// The advice must not send a user with no keychain off to unlock one.
	if !strings.Contains(stderr, "NO OS keychain") {
		t.Errorf("stderr notice does not say the keychain is ABSENT; got:\n%s", stderr)
	}
	if strings.Contains(stderr, "LOCKED") || strings.Contains(stderr, "unlock the login keyring") {
		t.Errorf("stderr gives LOCKED advice for an ABSENT keychain; got:\n%s", stderr)
	}

	// 3. bodies really are captured, in the clear.
	const canary = "PLAINTEXT-CANARY-4711"
	rl := sendThroughTunnel(t, rec.store, canary)
	if rl.RequestBodyPath == "" {
		t.Fatal("RequestBodyPath is empty: no keychain must degrade encryption, not capture")
	}
	raw, err := os.ReadFile(filepath.Join(rec.store.Dir(), rl.RequestBodyPath))
	if err != nil {
		t.Fatalf("read body at rest: %v", err)
	}
	if !strings.Contains(string(raw), canary) {
		t.Errorf("body at rest does not hold the canary: expected a PLAINTEXT capture, got %d bytes", len(raw))
	}

	// The banner must own up to it.
	if !strings.Contains(rec.notice(), "UNENCRYPTED") {
		t.Errorf("launch notice = %q, want it to disclose unencrypted recording", rec.notice())
	}
}

// ErrKeychainLocked WRAPS ErrNoKeychain, so a classifier that tests
// ErrNoKeychain first tells every locked host "there is no keychain" — the
// exact bug AGE-254 exists to fix. This test fails if that order regresses.
func TestLockedKeychainAdvisesUnlockNotAbsence(t *testing.T) {
	keyErr := errors.New("default collection is locked and unlocking needs an interactive prompt")
	stubBodyKeys(t, nil, "", errors.Join(keyring.ErrKeychainLocked, keyErr))
	emitter := &captureEmitter{}
	var logbuf strings.Builder

	var rec bodyRecording
	stderr := captureStderr(t, func() {
		rec = newBodyRecording(context.Background(), "1111222233334444", testLogger(&logbuf), emitter)
	})

	// 1. the posture is unchanged: a locked keychain degrades encryption, not capture.
	if rec.store == nil {
		t.Fatal("store is nil: a LOCKED keychain must NOT stop recording")
	}
	if rec.encrypted {
		t.Fatal("rec.encrypted = true with a locked keychain: the posture is being overclaimed")
	}

	// 2. the notice names LOCKED and says how to unlock — not "no keychain".
	if !strings.Contains(stderr, "IN THE CLEAR") || !strings.Contains(stderr, "UNENCRYPTED") {
		t.Errorf("stderr notice is not loud about plaintext bodies; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "LOCKED") {
		t.Errorf("stderr notice does not say the keychain is LOCKED; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "unlock the login keyring") || !strings.Contains(stderr, "PAM auto-unlock") {
		t.Errorf("stderr notice does not say HOW to unlock; got:\n%s", stderr)
	}
	if strings.Contains(stderr, "NO OS keychain") {
		t.Errorf("stderr tells a LOCKED host it has no keychain (ErrNoKeychain checked first?); got:\n%s", stderr)
	}
	if !strings.Contains(stderr, mitm.DefaultBodyDir()) {
		t.Errorf("stderr notice does not say WHERE the plaintext lands; got:\n%s", stderr)
	}
	if !strings.Contains(rec.notice(), "UNENCRYPTED") || !strings.Contains(rec.notice(), "LOCKED") {
		t.Errorf("launch notice = %q, want it to disclose unencrypted recording AND the locked keychain", rec.notice())
	}

	// 3. the audit reason distinguishes locked from absent.
	ev, ok := emitter.find(audit.TunnelBodiesUnencrypted)
	if !ok {
		t.Fatalf("no %s audit event emitted; got %v", audit.TunnelBodiesUnencrypted, emitter.events)
	}
	if ev.Detail["reason"] != audit.TunnelKeysLocked {
		t.Errorf("audit reason = %q, want %s: a locked keychain is not an absent one",
			ev.Detail["reason"], audit.TunnelKeysLocked)
	}

	// 4. bodies really are captured, in the clear.
	const canary = "LOCKED-KEYCHAIN-CANARY-4712"
	rl := sendThroughTunnel(t, rec.store, canary)
	if rl.RequestBodyPath == "" {
		t.Fatal("RequestBodyPath is empty: a locked keychain must degrade encryption, not capture")
	}
	raw, err := os.ReadFile(filepath.Join(rec.store.Dir(), rl.RequestBodyPath))
	if err != nil {
		t.Fatalf("read body at rest: %v", err)
	}
	if !strings.Contains(string(raw), canary) {
		t.Errorf("body at rest does not hold the canary: expected a PLAINTEXT capture, got %d bytes", len(raw))
	}
}

// classifyKeyErr's ordering is the whole ticket, asserted directly so a
// regression names itself. See AGE-254.
func TestClassifyKeyErrOrdering(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want keyState
	}{
		{"locked wraps ErrNoKeychain, must still classify as locked", keyring.ErrKeychainLocked, keysLocked},
		{"locked wrapped again by a backend", errors.Join(keyring.ErrKeychainLocked, errors.New("dbus")), keysLocked},
		{"absent", keyring.ErrNoKeychain, keysAbsent},
		{"absent wrapped by a backend", errors.Join(keyring.ErrNoKeychain, errors.New("no session bus")), keysAbsent},
		{"unrelated error", errors.New("dbus: connection refused"), keysError},
		{"no error", nil, keysAvailable},
	} {
		if got := classifyKeyErr(tc.err); got != tc.want {
			t.Errorf("%s: classifyKeyErr = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The audit event is the only durable record of the degradation, so it must
// carry no key material and no body bytes. ADR 0032.
func TestUnencryptedAuditEventLeaksNothing(t *testing.T) {
	keys, err := mitm.NewMemoryKeyWrapper()
	if err != nil {
		t.Fatalf("NewMemoryKeyWrapper: %v", err)
	}
	// A wrapper that exists but errors: the detail must still be fixed strings.
	stubBodyKeys(t, keys, "test-keychain", errors.New("dbus: connection refused"))
	emitter := &captureEmitter{}
	captureStderr(t, func() {
		newBodyRecording(context.Background(), "99998888777766aa", testLogger(io.Discard), emitter)
	})

	ev, ok := emitter.find(audit.TunnelBodiesUnencrypted)
	if !ok {
		t.Fatalf("no %s audit event emitted", audit.TunnelBodiesUnencrypted)
	}
	if ev.Detail["reason"] != audit.TunnelKeysError {
		t.Errorf("audit reason = %q, want keyring_error for a non-ErrNoKeychain failure", ev.Detail["reason"])
	}
	// Every value must come from the fixed vocabulary: no err text, no bytes.
	allowed := map[string]bool{
		"none": true, audit.TunnelKeysAbsent: true, audit.TunnelKeysError: true,
		audit.TunnelKeysLocked: true, "recording continues in the clear": true,
	}
	for k, v := range ev.Detail {
		if !allowed[v] {
			t.Errorf("audit Detail[%q] = %q is not a fixed string: it may carry key material or body bytes", k, v)
		}
	}
	if ev.Entity != mitm.BodyDirName {
		t.Errorf("audit Entity = %q, want the body dir NAME only", ev.Entity)
	}
}

// A BodyStore construction failure must cost the session its transcript, never
// its network. See ADR 0092-persist-request-bodies (D1).
func TestBodyStoreFailureLeavesInterceptionOn(t *testing.T) {
	keys, err := mitm.NewMemoryKeyWrapper()
	if err != nil {
		t.Fatalf("NewMemoryKeyWrapper: %v", err)
	}
	stubBodyKeys(t, keys, "test-keychain", nil)
	emitter := &captureEmitter{}
	var logbuf strings.Builder

	// An empty session id is rejected by NewBodyStore: a construction failure
	// reachable without breaking the filesystem.
	rec := newBodyRecording(context.Background(), "", testLogger(&logbuf), emitter)

	if rec.store != nil {
		t.Fatal("store is non-nil after a construction failure")
	}
	if rec.encrypted {
		t.Fatal("rec.encrypted = true with no store at all")
	}
	if !strings.Contains(logbuf.String(), "UNAVAILABLE") {
		t.Errorf("no warning about unavailable recording; got:\n%s", logbuf.String())
	}
	if !strings.Contains(rec.notice(), "NOT recorded") {
		t.Errorf("launch notice = %q, want it to say bodies are not recorded", rec.notice())
	}
	// The banner must not tell the user their network is gone: it is not.
	if strings.Contains(rec.notice(), "UNENCRYPTED") {
		t.Errorf("launch notice = %q claims unencrypted recording when nothing is recorded", rec.notice())
	}
}
