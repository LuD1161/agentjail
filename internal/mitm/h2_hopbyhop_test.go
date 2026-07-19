package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// h2Tunnel is the h2 analog of the h1 `tunnel` helper in bodycapture_test.go:
// a real h2 client connected to the MITM, forwarding to a real h2 upstream,
// with request logs and an optional BodyStore wired through the same way.
type h2Tunnel struct {
	cc       *http2.ClientConn
	clientTL *tls.Conn
	logs     chan *RequestLog
	done     chan struct{}
}

func newH2Tunnel(t *testing.T, upstream *httptest.Server, bodies *BodyStore) *h2Tunnel {
	t.Helper()
	caCert, caKey, err := GenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	logs := make(chan *RequestLog, 8)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewMITMHandler(caCert, caKey, logger, func(rl *RequestLog) { logs <- rl })
	h.UpstreamTLSConfig = upstreamTLSConfig(upstream)
	h.Bodies = bodies
	if bodies != nil {
		h.SessionID = bodies.SessionID()
	}

	host, port := upstreamHostPort(t, upstream)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Handle(serverConn, host, port)
	}()

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	cc, err := (&http2.Transport{}).NewClientConn(clientTLS)
	if err != nil {
		t.Fatalf("http2 NewClientConn: %v", err)
	}
	t.Cleanup(func() { cc.Close(); clientTLS.Close() })
	return &h2Tunnel{cc: cc, clientTL: clientTLS, logs: logs, done: done}
}

func (tn *h2Tunnel) waitLog(t *testing.T) *RequestLog {
	t.Helper()
	select {
	case rl := <-tn.logs:
		return rl
	case <-time.After(20 * time.Second):
		t.Fatal("no request log emitted")
		return nil
	}
}

// TestStripHopByHop is a direct unit test of the mechanism: every forbidden
// name is removed, including one named only via a Connection field value
// (RFC 7230 §6.1), and an unrelated header survives untouched.
func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "close, X-Custom")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("TE", "trailers")
	h.Set("Upgrade", "h2c")
	h.Set("Trailer", "X-Trailer-Name")
	h.Set("X-Custom", "named-only-by-connection-value")
	h.Set("Content-Type", "application/json")

	stripHopByHop(h)

	for _, forbidden := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
		"TE", "Upgrade", "Trailer", "X-Custom",
	} {
		if got := h.Get(forbidden); got != "" {
			t.Errorf("stripHopByHop left %q = %q, want removed", forbidden, got)
		}
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("stripHopByHop removed Content-Type (got %q), want preserved", got)
	}
}

// TestBuildUpstreamRequestStripsHopByHop constructs the *http.Request the
// same way http2.Server hands one to the handler and asserts
// buildUpstreamRequest never lets a hop-by-hop header reach outReq.Header.
// Bypasses the wire so it also covers names a conformant h2 client library
// would already filter (Connection, Proxy-Connection, Keep-Alive, Upgrade) --
// this is the last line of defense if that assumption ever stops holding.
func TestBuildUpstreamRequestStripsHopByHop(t *testing.T) {
	r, err := http.NewRequest("GET", "https://example.test/path", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Proxy-Connection", "keep-alive")
	r.Header.Set("Keep-Alive", "timeout=5")
	r.Header.Set("Transfer-Encoding", "chunked")
	r.Header.Set("TE", "trailers")
	r.Header.Set("Upgrade", "h2c")
	r.Header.Set("Trailer", "X-Something")
	r.Header.Set("X-Real-Header", "keep-me")

	rh := &h2RecordingHandler{host: "example.test", dialAddr: "example.test:443"}
	outReq, err := rh.buildUpstreamRequest(r)
	if err != nil {
		t.Fatalf("buildUpstreamRequest: %v", err)
	}
	for _, forbidden := range hopByHopHeaders {
		if got := outReq.Header.Get(forbidden); got != "" {
			t.Errorf("upstream request carries %q = %q, want stripped", forbidden, got)
		}
	}
	if got := outReq.Header.Get("X-Real-Header"); got != "keep-me" {
		t.Errorf("X-Real-Header = %q, want preserved", got)
	}
}

// TestH2ResponseHopByHopHeadersNotForwardedToClient proves the response leg:
// an upstream that (mis)sends hop-by-hop headers must not have them reach the
// h2 client, since Go's http2 server does not filter response headers by name
// the way it rejects them on the request side.
func TestH2ResponseHopByHopHeadersNotForwardedToClient(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Proxy-Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("TE", "trailers")
		w.Header().Set("Upgrade", "h2c")
		w.Header().Set("X-Real-Header", "keep-me")
		w.WriteHeader(http.StatusOK)
	}))

	tn := newH2Tunnel(t, upstream, nil)
	req, _ := http.NewRequest("GET", "https://x/", nil)
	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	for _, forbidden := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Upgrade"} {
		if got := resp.Header.Get(forbidden); got != "" {
			t.Errorf("client saw %q = %q, want stripped before forwarding", forbidden, got)
		}
	}
	if got := resp.Header.Get("X-Real-Header"); got != "keep-me" {
		t.Errorf("X-Real-Header = %q, want preserved", got)
	}
}
