package tunnel

// handler_faildclosed_test.go — S-D1 tests: on a managed database port an
// unrecognized protocol must fail CLOSED (deny, no relay), while a recognized
// benign op is relayed and non-managed ports stay allow-by-default (availability).

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// scriptedConn is a net.Conn whose read stream and destination address are
// fixed by the test, so handleConn can be driven directly without a real stack.
type scriptedConn struct {
	readData []byte
	readPos  int
	local    *net.TCPAddr
	remote   *net.TCPAddr
	maxRead  int

	mu     sync.Mutex
	closed bool
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if c.readPos >= len(c.readData) {
		return 0, io.EOF
	}
	if c.maxRead > 0 && len(b) > c.maxRead {
		b = b[:c.maxRead]
	}
	n := copy(b, c.readData[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *scriptedConn) RemoteAddr() net.Addr             { return c.remote }
func (c *scriptedConn) LocalAddr() net.Addr              { return c.local }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// buildPGSimpleQuery builds a valid PostgreSQL SimpleQuery ('Q') message so the
// recognizer produces a real postgres op (verb derived from the SQL).
func buildPGSimpleQuery(sql string) []byte {
	payload := append([]byte(sql), 0) // null-terminated
	msg := make([]byte, 5+len(payload))
	msg[0] = 'Q'
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// runHandleConn runs handleConn in a goroutine (it may block on the upstream
// dial after logging its decision) and polls the recorded logs for want.
func runHandleConn(t *testing.T, port int, peek []byte, want string) (rec *recordingHandler, conn *scriptedConn) {
	t.Helper()
	rec = &recordingHandler{}
	g := &Gateway{
		logger:   slog.New(rec),
		registry: dnsvip.NewRegistry(),
	}
	conn = &scriptedConn{
		readData: peek,
		// Loopback destination: if handleConn reaches the upstream dial it
		// fails fast (connection refused) instead of hanging.
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000},
	}
	go g.handleConn(conn)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.seen(want) {
			return rec, conn
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handleConn never logged %q", want)
	return rec, conn
}

// (a) Garbage bytes to managed port 5432 must be DENIED (fail-closed), not relayed.
func TestHandleConn_GarbageOnManagedPortDenied(t *testing.T) {
	rec, _ := runHandleConn(t, 5432, []byte("this is not a postgres wire message at all"),
		"unknown protocol on managed port; denying (fail-closed)")

	if rec.seen("connection allowed, relaying") {
		t.Error("garbage on managed port 5432 was relayed — fail-closed not enforced (S-D1)")
	}
}

// (b) A valid recognized postgres op with a benign verb (select) must be ALLOWED.
func TestHandleConn_RecognizedPostgresAllowed(t *testing.T) {
	rec, _ := runHandleConn(t, 5432, buildPGSimpleQuery("SELECT 1"),
		"connection allowed, relaying")

	if rec.seen("unknown protocol on managed port; denying (fail-closed)") {
		t.Error("recognized benign postgres op was denied — fail-closed over-fired (S-D1)")
	}
}

// (c) Unrecognized bytes on non-managed port 443 (plain TLS/HTTPS) must be
// ALLOWED to preserve host availability.
func TestHandleConn_UnrecognizedOn443Allowed(t *testing.T) {
	rec, _ := runHandleConn(t, 443, []byte{0x16, 0x03, 0x01, 0x00, 0x2f},
		"connection allowed, relaying")

	if rec.seen("unknown protocol on managed port; denying (fail-closed)") {
		t.Error("unrecognized TLS on port 443 was denied — availability constraint violated (S-D1)")
	}
}

func TestHandleConn_SplitHTTPHeaderUsesNamedPolicyAndRecordsDecision(t *testing.T) {
	dir := t.TempDir()
	template := []byte(`
id: deny-http-control
info:
  name: Block cleartext HTTP control
match:
  protocol: [http]
  host: [www.cloudflare.com]
  port: [80]
action: deny
reason: cleartext HTTP denied
`)
	if err := os.WriteFile(filepath.Join(dir, "http.yaml"), template, 0o600); err != nil {
		t.Fatal(err)
	}
	matcher, err := netpolicy.NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded := make(chan *mitm.RequestLog, 1)
	g := &Gateway{
		logger:   slog.New(&recordingHandler{}),
		registry: dnsvip.NewRegistry(),
		matcher:  matcher,
	}
	g.SetMITM(mitm.NewMITMHandler(nil, nil, slog.Default(), func(log *mitm.RequestLog) {
		recorded <- log
	}))
	conn := &scriptedConn{
		readData: []byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com:80\r\n\r\n"),
		maxRead:  7,
		local:    &net.TCPAddr{IP: net.IPv4(104, 20, 23, 154), Port: 80},
		remote:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000},
	}
	g.handleConn(conn)

	select {
	case log := <-recorded:
		if log.Host != "www.cloudflare.com" || log.PolicyTemplate != "deny-http-control" || log.StatusCode != 403 {
			t.Fatalf("recorded decision = %#v", log)
		}
	case <-time.After(time.Second):
		t.Fatal("raw HTTP denial was not recorded")
	}
}

func TestHandleConn_IncompleteHTTPHeaderDeniedWithPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "allow.yaml"), []byte(`
id: allow-http
info:
  name: Allow HTTP
match:
  protocol: [http]
action: allow
reason: allowed
`), 0o600); err != nil {
		t.Fatal(err)
	}
	matcher, err := netpolicy.NewMatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingHandler{}
	g := &Gateway{logger: slog.New(rec), registry: dnsvip.NewRegistry(), matcher: matcher}
	conn := &scriptedConn{
		readData: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
		local:    &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
		remote:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000},
	}
	g.handleConn(conn)
	if !rec.seen("incomplete HTTP header; denying (fail-closed)") {
		t.Fatal("incomplete HTTP header was not denied")
	}
	if rec.seen("connection allowed, relaying") {
		t.Fatal("incomplete HTTP header was relayed")
	}
}
