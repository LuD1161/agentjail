package tunnel

// handler_midstream_test.go — S-D2 tests: on a managed database port the relay
// re-inspects each client→upstream message, so a benign first message (SELECT)
// cannot smuggle a later deny verb (DROP) past policy. A fully-benign managed
// connection relays to completion; the plain (non-managed) relay is unaffected.

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// denyDropMatcher builds a matcher whose single template denies postgres DROP.
func denyDropMatcher(t *testing.T) *netpolicy.Matcher {
	t.Helper()
	dir := t.TempDir()
	yaml := `id: deny-postgres-drop
info:
  name: deny postgres drop
  severity: high
match:
  protocol: [postgres]
  verb: [drop]
action: deny
reason: "drop denied"
`
	if err := os.WriteFile(filepath.Join(dir, "deny-drop.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing template: %v", err)
	}
	m, err := netpolicy.NewMatcher(dir)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

// tcpPair returns a connected pair of loopback TCP conns (a, b).
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		s, _ := ln.Accept()
		ch <- s
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s := <-ch
	if s == nil {
		t.Fatal("accept failed")
	}
	return c, s
}

func readWithTimeout(t *testing.T, c net.Conn, n int) ([]byte, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	got, err := c.Read(buf)
	return buf[:got], err
}

// A managed (5432) connection whose FIRST message is benign (SELECT) but a LATER
// message is a deny verb (DROP TABLE) must be torn down mid-stream: the DROP must
// never reach the upstream.
func TestRelayManaged_MidStreamDenyTearsDown(t *testing.T) {
	rec := &recordingHandler{}
	g := &Gateway{logger: slog.New(rec), matcher: denyDropMatcher(t)}

	agentEnd, gwClient := tcpPair(t)
	gwUpstream, upstreamEnd := tcpPair(t)
	defer agentEnd.Close()
	defer upstreamEnd.Close()

	done := make(chan struct{})
	go func() {
		g.relayManaged(gwClient, gwUpstream, "db", 5432, slog.New(rec))
		close(done)
	}()

	// First message: benign SELECT — must be forwarded to upstream.
	sel := buildPGSimpleQuery("SELECT 1")
	if _, err := agentEnd.Write(sel); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	got, err := readWithTimeout(t, upstreamEnd, len(sel))
	if err != nil || len(got) != len(sel) {
		t.Fatalf("benign SELECT not forwarded: got %d bytes, err %v", len(got), err)
	}

	// Second message: DROP — must trigger a mid-stream deny and NOT be forwarded.
	drop := buildPGSimpleQuery("DROP TABLE users")
	if _, err := agentEnd.Write(drop); err != nil {
		t.Fatalf("write DROP: %v", err)
	}
	// Upstream should observe close (EOF/reset), never the DROP bytes.
	if got, err := readWithTimeout(t, upstreamEnd, len(drop)); err == nil && len(got) > 0 {
		t.Fatalf("DROP was forwarded upstream (%d bytes) — mid-stream deny not enforced (S-D2)", len(got))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relayManaged did not return after mid-stream deny")
	}

	if !rec.seen("managed-port deny mid-stream; tearing down connection") {
		t.Error("mid-stream deny was not logged (S-D2)")
	}
}

// A fully-benign managed connection (two SELECTs) must relay both messages to
// completion and never fire a deny.
func TestRelayManaged_BenignRelaysToCompletion(t *testing.T) {
	rec := &recordingHandler{}
	g := &Gateway{logger: slog.New(rec), matcher: denyDropMatcher(t)}

	agentEnd, gwClient := tcpPair(t)
	gwUpstream, upstreamEnd := tcpPair(t)
	defer upstreamEnd.Close()

	done := make(chan struct{})
	go func() {
		g.relayManaged(gwClient, gwUpstream, "db", 5432, slog.New(rec))
		close(done)
	}()

	msgs := [][]byte{buildPGSimpleQuery("SELECT 1"), buildPGSimpleQuery("SELECT 2")}
	for _, m := range msgs {
		if _, err := agentEnd.Write(m); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readWithTimeout(t, upstreamEnd, len(m))
		if err != nil || len(got) != len(m) {
			t.Fatalf("benign message not forwarded: got %d, err %v", len(got), err)
		}
	}

	// Close the agent side; relayManaged should drain and return. A real
	// upstream closes its side when it sees the client's half-close (CloseWrite);
	// the dumb loopback upstream here does not, so close it too to end the
	// upstream→client copy.
	agentEnd.Close()
	upstreamEnd.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relayManaged did not return after client close")
	}

	if rec.seen("managed-port deny mid-stream; tearing down connection") {
		t.Error("benign managed connection fired a mid-stream deny (S-D2 over-fired)")
	}
}

// The plain relay (used for non-managed ports like 443) forwards arbitrary later
// bytes unchanged — no inspection, availability preserved.
func TestPlainRelay_NonManagedUnaffected(t *testing.T) {
	agentEnd, gwClient := tcpPair(t)
	gwUpstream, upstreamEnd := tcpPair(t)
	defer upstreamEnd.Close()

	done := make(chan struct{})
	go func() {
		relay(gwClient, gwUpstream, slog.Default())
		close(done)
	}()

	// Bytes that WOULD be a deny verb if this were an inspected managed relay.
	payload := buildPGSimpleQuery("DROP TABLE users")
	if _, err := agentEnd.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readWithTimeout(t, upstreamEnd, len(payload))
	if err != nil || len(got) != len(payload) {
		t.Fatalf("plain relay dropped/altered bytes: got %d, err %v", len(got), err)
	}

	agentEnd.Close()
	upstreamEnd.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return after client close")
	}
}
