package netproxyapp

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// ---- TestHostMatch_* — host matching logic ----

func TestHostMatch_ExactMatch(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "api.GITHUB.COM", true}, // case-insensitive after normalize
		{"api.github.com", "www.github.com", false},
		{"api.github.com", "github.com", false},
		{"api.github.com", "evil.api.github.com", false},
	}
	for _, tc := range tests {
		got := matchHost(normalizeHost(tc.pattern), normalizeHost(tc.host))
		if got != tc.want {
			t.Errorf("matchHost(%q, %q) = %v; want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestHostMatch_Wildcard(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "foo.bar.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "foo.notexample.com", false},
		{"*.github.com", "github.com", false},
		{"*.github.com", "api.github.com", true},
	}
	for _, tc := range tests {
		got := matchHost(normalizeHost(tc.pattern), normalizeHost(tc.host))
		if got != tc.want {
			t.Errorf("matchHost(%q, %q) = %v; want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestHostMatch_PortStripped(t *testing.T) {
	al := &allowlist{}
	al.load([]string{"api.github.com"})
	if !al.allowed("api.github.com") {
		t.Error("expected api.github.com allowed without port")
	}
	if al.allowed("attacker.example.com") {
		t.Error("expected attacker.example.com denied")
	}
}

func TestHostMatch_IDNEquivalence(t *testing.T) {
	al := &allowlist{}
	al.load([]string{"API.GitHub.COM"})
	if !al.allowed("api.github.com") {
		t.Error("case-insensitive IDN matching failed")
	}
}

func TestHostMatch_TrailingDot(t *testing.T) {
	got := normalizeHost("api.github.com.")
	if got != "api.github.com" {
		t.Errorf("normalizeHost with trailing dot = %q; want %q", got, "api.github.com")
	}
}

// ---- helpers ----

// discardLogger returns a slog.Logger that drops all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testToken is the session token every data-plane test registers.
const testToken = proxyctl.Token("test-session-token")

// newProxyForHosts builds a proxy whose single registered session (testToken)
// allows exactly the given hosts. This is how the data plane is exercised now
// that there is no global allowlist -- every CONNECT must carry a token.
func newProxyForHosts(hosts []string) *proxy {
	reg := newSessionRegistry()
	reg.register(testToken, "test-session", "/tmp/test-cwd", proxyctl.SessionPolicy{AllowedHosts: hosts}, time.Hour, time.Now())
	return &proxy{registry: reg, emitter: audit.NopEmitter{}, logger: discardLogger()}
}

// connectReq formats a CONNECT request line + headers carrying the session
// token as the Proxy-Authorization Basic username (empty tok => no auth header).
func connectReq(target string, tok proxyctl.Token) string {
	if tok == "" {
		return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth)
}

// serveProxy runs the proxy's accept loop over a fresh listener and returns the
// dialable address.
func serveProxy(t *testing.T, p *proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startEchoServer starts a plain TCP echo server and returns its listener.
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestConfiguredConnectorRouteDialsOnlyInstalledDestination(t *testing.T) {
	upstream := startEchoServer(t)
	host, portText, err := net.SplitHostPort(upstream.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	registry := newSessionRegistry()
	registry.register(testToken, "session-a", "/tmp/test-cwd", proxyctl.SessionPolicy{}, time.Hour, time.Now())
	if err := registry.installConnector(proxyctl.ConnectorRoute{SessionID: "session-a", ConnectorID: "chrome-cdp", Host: host, Port: uint16(port)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	proxyAddr := serveProxy(t, &proxy{registry: registry, emitter: audit.NopEmitter{}, logger: discardLogger()})
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	fmt.Fprint(client, connectReq("chrome-cdp.connector.agentjail:443", testToken))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	if _, err := client.Write([]byte("fixed destination")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("fixed destination"))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "fixed destination" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestConnectorRouteRejectsUnknownIDAndCrossSession(t *testing.T) {
	registry := newSessionRegistry()
	registry.register(testToken, "session-a", "/tmp/test-cwd", proxyctl.SessionPolicy{AllowedHosts: []string{"example.com"}}, time.Hour, time.Now())
	registry.register("second-token", "session-b", "/tmp/test-cwd", proxyctl.SessionPolicy{}, time.Hour, time.Now())
	if err := registry.installConnector(proxyctl.ConnectorRoute{
		SessionID: "session-a", ConnectorID: "chrome-cdp", Host: "127.0.0.1", Port: 9225,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	proxyAddr := serveProxy(t, &proxy{registry: registry, emitter: audit.NopEmitter{}, logger: discardLogger()})
	for _, test := range []struct {
		token proxyctl.Token
		want  int
	}{
		{token: "second-token", want: http.StatusForbidden},
		{token: "wrong-token", want: http.StatusProxyAuthRequired},
	} {
		client, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(client, connectReq("chrome-cdp.connector.agentjail:443", test.token))
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != test.want {
			t.Fatalf("connector route status = %d, want %d", resp.StatusCode, test.want)
		}
	}
}

// ---- CONNECT data-plane tests (per-session token) ----

// TestCONNECTRequest_AllowedHost verifies a CONNECT for an allowed host tunnels
// successfully when the request carries the session's token.
func TestCONNECTRequest_AllowedHost(t *testing.T) {
	upstream := startEchoServer(t)
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstream.Addr().String())

	p := newProxyForHosts([]string{upstreamHost})
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	target := net.JoinHostPort(upstreamHost, upstreamPort)
	fmt.Fprint(client, connectReq(target, testToken))

	reader := bufio.NewReader(client)
	responseLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(responseLine, "200") {
		t.Fatalf("expected 200 response, got: %q", responseLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	msg := "hello-tunnel\n"
	_, _ = fmt.Fprint(client, msg)
	echoed := make([]byte, len(msg))
	n, err := io.ReadFull(reader, echoed)
	if err != nil || n != len(msg) {
		t.Fatalf("echo read: n=%d err=%v", n, err)
	}
	if string(echoed) != msg {
		t.Errorf("echo mismatch: got %q, want %q", string(echoed), msg)
	}
}

// TestCONNECTRequest_DeniedHost verifies a CONNECT (with a valid token) to a
// host outside that session's allowlist returns 403.
func TestCONNECTRequest_DeniedHost(t *testing.T) {
	p := newProxyForHosts([]string{"api.github.com"})
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, connectReq("attacker.example.com:443", testToken))

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if deny := resp.Header.Get("X-Agentjail-Deny"); !strings.Contains(deny, "attacker.example.com") {
		t.Errorf("X-Agentjail-Deny header missing host: %q", deny)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "network.allowed_hosts") {
		t.Errorf("deny body missing 'network.allowed_hosts': %q", string(body))
	}
}

// TestCONNECTRequest_MissingToken proves there is NO global fallback: a CONNECT
// to an otherwise-allowed host with no Proxy-Authorization is denied (407).
func TestCONNECTRequest_MissingToken(t *testing.T) {
	p := newProxyForHosts([]string{"api.github.com"})
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, connectReq("api.github.com:443", "")) // no token

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("missing token: expected 407, got %d", resp.StatusCode)
	}
}

// TestCONNECTRequest_UnknownToken verifies an unregistered token is denied
// (407), never falling back to any allowlist.
func TestCONNECTRequest_UnknownToken(t *testing.T) {
	p := newProxyForHosts([]string{"api.github.com"})
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, connectReq("api.github.com:443", proxyctl.Token("not-a-real-token")))

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("unknown token: expected 407, got %d", resp.StatusCode)
	}
}

// TestCONNECTRequest_Malformed verifies a malformed request line returns 400
// (before any auth check).
func TestCONNECTRequest_Malformed(t *testing.T) {
	p := newProxyForHosts(nil)
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, "GARBAGE\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestCONNECTRequest_NonCONNECTMethod verifies plain HTTP GET to an ordinary
// (non-sentinel) host returns 405. The auth check now runs BEFORE the method
// dispatch (Codex r3 #2, so the grant sentinel can be token-bound), so this
// request must carry a valid token to reach the 405 path at all.
func TestCONNECTRequest_NonCONNECTMethod(t *testing.T) {
	p := newProxyForHosts(nil)
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	auth := base64.StdEncoding.EncodeToString([]byte(string(testToken) + ":"))
	fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestCONNECTRequest_NonCONNECTMethod_NoToken verifies that a non-sentinel GET
// with NO token gets 407, not 405 -- the auth gate runs first for every
// request, sentinel or not.
func TestCONNECTRequest_NonCONNECTMethod_NoToken(t *testing.T) {
	p := newProxyForHosts(nil)
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", resp.StatusCode)
	}
}

// TestProxyConnsCapAt256 verifies that when maxConcurrentConns is exceeded the
// proxy returns 503, rejecting at the accept loop before handleConn.
func TestProxyConnsCapAt256(t *testing.T) {
	p := &proxy{registry: newSessionRegistry(), logger: discardLogger()}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p.connCount.Store(maxConcurrentConns) // already at the cap

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			cur := p.connCount.Add(1)
			if cur > maxConcurrentConns {
				p.connCount.Add(-1)
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\nX-Agentjail-Deny: too-many-connections\r\nContent-Length: 28\r\n\r\ntoo many concurrent connections\n")
				conn.Close()
				continue
			}
			go func() {
				defer p.connCount.Add(-1)
				p.handleConn(conn)
			}()
		}
	}()
	t.Cleanup(func() { proxyLn.Close() })

	client, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, connectReq("attacker.example.com:443", testToken))

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

// ---- parse helpers ----

func TestParseRequestLine_Valid(t *testing.T) {
	method, target, proto, ok := parseRequestLine("CONNECT api.github.com:443 HTTP/1.1")
	if !ok {
		t.Fatal("expected ok")
	}
	if method != "CONNECT" || target != "api.github.com:443" || proto != "HTTP/1.1" {
		t.Errorf("got method=%q target=%q proto=%q", method, target, proto)
	}
}

func TestParseRequestLine_TooFewParts(t *testing.T) {
	if _, _, _, ok := parseRequestLine("CONNECT"); ok {
		t.Error("expected !ok for single token")
	}
}

func TestParseRequestLine_Empty(t *testing.T) {
	if _, _, _, ok := parseRequestLine(""); ok {
		t.Error("expected !ok for empty line")
	}
}

func TestParseBasicToken(t *testing.T) {
	tok := proxyctl.Token("abc123XYZ")
	enc := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	got, ok := parseBasicToken("Basic " + enc)
	if !ok || got != string(tok) {
		t.Errorf("parseBasicToken = %q ok=%v; want %q", got, ok, tok)
	}
	// Case-insensitive scheme.
	if got, ok := parseBasicToken("basic " + enc); !ok || got != string(tok) {
		t.Errorf("lowercase scheme failed: %q ok=%v", got, ok)
	}
	// Non-Basic and garbage are rejected.
	if _, ok := parseBasicToken("Bearer xyz"); ok {
		t.Error("Bearer should not parse as Basic")
	}
	if _, ok := parseBasicToken("Basic !!!notbase64"); ok {
		t.Error("invalid base64 should not parse")
	}
}

// ---- integration: full tunnel via httptest ----

// TestCONNECTRequest_HTTPSViaTestServer verifies the full tunnel using an
// httptest.Server (post-CONNECT the proxy just wires bytes).
func TestCONNECTRequest_HTTPSViaTestServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprintln(w, "agentjail-netproxy tunnel works")
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	p := newProxyForHosts([]string{host})
	proxyAddr := serveProxy(t, p)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	target := net.JoinHostPort(host, port)
	fmt.Fprint(client, connectReq(target, testToken))

	reader := bufio.NewReader(client)
	statusLine, _ := reader.ReadString('\n')
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 Connection established, got %q", statusLine)
	}
	for {
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	fmt.Fprintf(client, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upstream response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("expected 418, got %d", resp.StatusCode)
	}
}
