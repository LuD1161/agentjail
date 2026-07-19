package mitm

import (
	"crypto/tls"
	"crypto/x509"
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

	"golang.org/x/net/http2"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// h2Upstream starts a real HTTP/2 test upstream (h2 over TLS, ALPN
// negotiated) so the round trip through the MITM exercises genuine h2 on
// both legs, not just the client-facing one.
func h2Upstream(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newTestHandler(t *testing.T, upstream *httptest.Server, onReq func(*RequestLog)) (*MITMHandler, *x509.Certificate) {
	t.Helper()
	caDir := t.TempDir()
	caCert, caKey, err := GenerateCA(caDir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewMITMHandler(caCert, caKey, logger, onReq)
	h.UpstreamTLSConfig = upstreamTLSConfig(upstream)
	return h, caCert
}

// upstreamHostPort strips the scheme off an httptest.Server URL and returns
// (host, port), matching what Handle receives from a real CONNECT.
func upstreamHostPort(t *testing.T, srv *httptest.Server) (string, string) {
	t.Helper()
	addr := strings.TrimPrefix(srv.URL, "https://")
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split upstream addr %q: %v", addr, err)
	}
	return "localhost", port
}

// TestHandleServesH2 is the round-1 gate: a real h2 client handshakes h2 with
// the MITM, sends a request, and gets the upstream's response back over h2,
// with a correctly populated RequestLog. AGE-223.
func TestHandleServesH2(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream saw ProtoMajor=%d, want 2 (h2 upstream leg)", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("h2 upstream OK"))
	}))

	var mu sync.Mutex
	var logs []*RequestLog
	h, caCert := newTestHandler(t, upstream, func(rl *RequestLog) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, rl)
	})
	h.SessionID = "sess-h2-abc123"
	h.OwnerPID = 4242

	host, port := upstreamHostPort(t, upstream)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

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
	if got := clientTLS.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("NegotiatedProtocol = %q, want h2", got)
	}

	cc, err := (&http2.Transport{}).NewClientConn(clientTLS)
	if err != nil {
		t.Fatalf("http2 NewClientConn: %v", err)
	}
	defer cc.Close()

	req, _ := http.NewRequest("GET", "https://"+host+":"+port+"/h2-test", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Errorf("response ProtoMajor = %d, want 2", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h2 upstream OK" {
		t.Errorf("body = %q, want %q", body, "h2 upstream OK")
	}

	cc.Close()
	clientTLS.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 1 {
		t.Fatalf("got %d RequestLogs, want 1", len(logs))
	}
	rl := logs[0]
	if rl.Method != "GET" {
		t.Errorf("Method = %q, want GET", rl.Method)
	}
	if rl.URL != "https://"+host+"/h2-test" {
		t.Errorf("URL = %q, want https://%s/h2-test", rl.URL, host)
	}
	if rl.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", rl.StatusCode)
	}
	if rl.SessionID != "sess-h2-abc123" {
		t.Errorf("SessionID = %q, want sess-h2-abc123", rl.SessionID)
	}
	if rl.OwnerPID != 4242 {
		t.Errorf("OwnerPID = %d, want 4242", rl.OwnerPID)
	}
}

// TestHandleServesH2WithoutDowngradeNotice is the case AGE-223 changed: an h2
// offer that the MITM honors must NOT be reported as a downgrade. Before this
// change, offering h2 was itself the trigger; now it is the normal case.
func TestHandleServesH2WithoutDowngradeNotice(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	em := &countingEmitter{}
	h, caCert := newTestHandler(t, upstream, func(*RequestLog) {})
	h.Audit = em

	host, port := upstreamHostPort(t, upstream)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

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
	req, _ := http.NewRequest("GET", "https://"+host+":"+port+"/", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	resp.Body.Close()
	cc.Close()
	clientTLS.Close()
	<-done

	if got := em.count(); got != 0 {
		t.Errorf("emitted %d TunnelALPNDowngraded events for a served h2 offer, want 0", got)
	}
}

// TestHandleH2PolicyDeny proves an h2 request goes through the same deny path
// as h1: same 403, same body, same X-Agentjail-Deny header, same RequestLog
// fields.
func TestHandleH2PolicyDeny(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached for a denied request")
	}))

	packDir := t.TempDir()
	tmplContent := `id: deny-all-h2-test
info:
  name: Deny All H2 Test
  severity: critical
  author: test
match:
  protocol:
    - http
action: deny
reason: "blocked by test policy"
`
	if err := os.WriteFile(filepath.Join(packDir, "deny.yaml"), []byte(tmplContent), 0644); err != nil {
		t.Fatal(err)
	}
	matcher, err := netpolicy.NewMatcher(packDir)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	var mu sync.Mutex
	var lastLog *RequestLog
	h, caCert := newTestHandler(t, upstream, func(rl *RequestLog) {
		mu.Lock()
		defer mu.Unlock()
		lastLog = rl
	})
	h.Matcher = matcher

	host, port := upstreamHostPort(t, upstream)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

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
	defer cc.Close()

	req, _ := http.NewRequest("GET", "https://"+host+":"+port+"/deny-me", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Agentjail-Deny"); got != "deny-all-h2-test" {
		t.Errorf("X-Agentjail-Deny = %q, want deny-all-h2-test", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "blocked by agentjail network policy") {
		t.Errorf("deny body = %q, want policy message", body)
	}

	cc.Close()
	clientTLS.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if lastLog == nil {
		t.Fatal("expected a RequestLog to be emitted for the denied h2 request")
	}
	if lastLog.PolicyAction != "deny" {
		t.Errorf("PolicyAction = %q, want deny", lastLog.PolicyAction)
	}
	if lastLog.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", lastLog.StatusCode)
	}
}
