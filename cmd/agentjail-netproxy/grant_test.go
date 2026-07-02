package main

// grant_test.go exercises the runtime host grant flow end-to-end (AGE-93):
// the data-plane sentinel (main.go: isGrantSentinel/handleGrantSentinel)
// files a pending request, and the control-plane verbs (control.go:
// grant_list/grant_approve/grant_deny) let a human decide it. Both planes
// share one *sessionRegistry, mirroring how one netproxy process wires them
// in production (see proxy.run in main.go).

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// startGrantTestEnv wires a data-plane proxy and a control-plane server
// against the SAME session registry, each listening on its own temp
// socket/port, so a test can exercise the full sentinel-request ->
// control-socket-approve -> data-plane-CONNECT flow.
func startGrantTestEnv(t *testing.T, durableAudit bool) (proxyAddr, sock string, reg *sessionRegistry) {
	t.Helper()
	reg = newSessionRegistry()
	dir := shortSocketDir(t)
	sock = filepath.Join(dir, "netproxy-ctl.sock")
	cs, err := newControlServer(sock, reg, audit.NopEmitter{}, durableAudit, "test", testLogger())
	if err != nil {
		t.Fatalf("newControlServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go cs.serve(ctx)
	t.Cleanup(func() { cancel(); cs.close() })

	p := &proxy{registry: reg, emitter: audit.NopEmitter{}, logger: discardLogger()}
	proxyAddr = serveProxy(t, p)
	return proxyAddr, sock, reg
}

// sentinelGET formats a GET to the grant sentinel carrying tok as the
// Proxy-Authorization Basic username (empty tok => no auth header).
func sentinelGET(target string, tok proxyctl.Token) string {
	if tok == "" {
		return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: grant.agentjail.local\r\n\r\n", target)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: grant.agentjail.local\r\nProxy-Authorization: Basic %s\r\n\r\n", target, auth)
}

func TestGrantSentinel_FilesPendingRequestVisibleOverControlSocket(t *testing.T) {
	proxyAddr, sock, reg := startGrantTestEnv(t, true)
	reg.register("tok-1", "sess-1", "/repo", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, time.Now())

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, sentinelGET("http://grant.agentjail.local/allow?host=api.example.com&ttl=30m&reason=testing", "tok-1"))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
	var body struct {
		GrantID string `json:"grant_id"`
		Host    string `json:"host"`
		TTLMs   int64  `json:"ttl_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 202 body: %v", err)
	}
	if body.Host != "api.example.com" || body.GrantID == "" || body.TTLMs != (30*time.Minute).Milliseconds() {
		t.Errorf("unexpected 202 body: %+v", body)
	}

	grants, err := proxyctl.GrantList(sock, time.Second)
	if err != nil {
		t.Fatalf("GrantList: %v", err)
	}
	if len(grants) != 1 || grants[0].GrantID != body.GrantID || grants[0].Reason != "testing" {
		t.Fatalf("expected the filed grant to show up via GrantList: %+v", grants)
	}
}

func TestGrantSentinel_UnknownTokenIs407(t *testing.T) {
	proxyAddr, _, _ := startGrantTestEnv(t, true)

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	fmt.Fprint(client, sentinelGET("http://grant.agentjail.local/allow?host=api.example.com", proxyctl.Token("not-a-real-token")))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for unknown token, got %d", resp.StatusCode)
	}
}

func TestGrantSentinel_InvalidHostIs400(t *testing.T) {
	proxyAddr, _, reg := startGrantTestEnv(t, true)
	reg.register("tok-1", "sess-1", "/repo", proxyctl.SessionPolicy{}, time.Hour, time.Now())

	cases := []string{
		"http://grant.agentjail.local/allow?host=", // empty
		"http://grant.agentjail.local/allow?host=*",
		"http://grant.agentjail.local/allow?host=https%3A%2F%2Fevil.com",
		"http://grant.agentjail.local/allow?host=example.com:443",
	}
	for _, target := range cases {
		client, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		fmt.Fprint(client, sentinelGET(target, "tok-1"))
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("read response for %q: %v", target, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("target %q: expected 400, got %d", target, resp.StatusCode)
		}
		resp.Body.Close()
		client.Close()
	}
}

func TestGrantSentinel_OverPendingCapIs429(t *testing.T) {
	proxyAddr, _, reg := startGrantTestEnv(t, true)
	reg.register("tok-1", "sess-1", "/repo", proxyctl.SessionPolicy{}, time.Hour, time.Now())

	// Fill the per-session cap with distinct hosts (coalescing only applies to
	// repeated hosts, so each of these is a new pending entry).
	for i := 0; i < proxyctl.MaxPendingPerSession; i++ {
		client, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		host := fmt.Sprintf("host%d.example.com", i)
		fmt.Fprint(client, sentinelGET("http://grant.agentjail.local/allow?host="+host, "tok-1"))
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("request %d: expected 202 while under cap, got %d", i, resp.StatusCode)
		}
		resp.Body.Close()
		client.Close()
	}

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	fmt.Fprint(client, sentinelGET("http://grant.agentjail.local/allow?host=one-too-many.example.com", "tok-1"))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 over the pending cap, got %d", resp.StatusCode)
	}
}

func TestGrantSentinel_ConnectToSentinelIsNormalDeniedConnect(t *testing.T) {
	proxyAddr, _, reg := startGrantTestEnv(t, true)
	reg.register("tok-1", "sess-1", "/repo", proxyctl.SessionPolicy{AllowedHosts: []string{"api.github.com"}}, time.Hour, time.Now())

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	auth := base64.StdEncoding.EncodeToString([]byte("tok-1:"))
	fmt.Fprintf(client, "CONNECT grant.agentjail.local:443 HTTP/1.1\r\nHost: grant.agentjail.local\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	// A CONNECT to the sentinel authority is NOT a grant request -- it is
	// just an ordinary CONNECT to an unlisted host, so it is denied (403),
	// never a 202.
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 (ordinary denied CONNECT), got %d", resp.StatusCode)
	}

	grants, err := reqGrantListDirect(reg)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("CONNECT to the sentinel must not file a pending grant, got %+v", grants)
	}
}

// reqGrantListDirect reads pending grants straight from the registry
// (bypassing the control socket) for assertions that don't need the wire path.
func reqGrantListDirect(reg *sessionRegistry) ([]proxyctl.GrantInfo, error) {
	return reg.listPending(), nil
}

func TestGrantFlow_RequestApproveConnectSucceeds_ThenExpires(t *testing.T) {
	proxyAddr, sock, reg := startGrantTestEnv(t, true)
	reg.register("tok-1", "sess-1", "/repo", proxyctl.SessionPolicy{AllowedHosts: nil}, time.Hour, time.Now())

	// A real local listener so an eventually-allowed CONNECT actually tunnels.
	upstream := startEchoServer(t)
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstream.Addr().String())
	target := net.JoinHostPort(upstreamHost, upstreamPort)

	// File the request through the sentinel.
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprint(client, sentinelGET("http://grant.agentjail.local/allow?host="+upstreamHost+"&ttl=100ms", "tok-1"))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var body struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 202 body: %v", err)
	}
	resp.Body.Close()
	client.Close()

	// Before approval, a CONNECT to the requested host must still be denied.
	assertConnect(t, proxyAddr, target, "tok-1", http.StatusForbidden)

	// Approve over the control socket.
	if err := proxyctl.GrantApprove(sock, body.GrantID, time.Second); err != nil {
		t.Fatalf("GrantApprove: %v", err)
	}

	// Now the CONNECT succeeds.
	assertConnect(t, proxyAddr, target, "tok-1", 0) // 0 => expect 200 established

	// After the TTL lapses the reaper prunes the grant; force it directly
	// (reapLoop is a background ticker not exercised in this unit test).
	res := reg.reap(time.Now().Add(200 * time.Millisecond))
	if len(res.ExpiredGrants) != 1 {
		t.Fatalf("expected the granted host to be reaped as expired, got %+v", res.ExpiredGrants)
	}
	assertConnect(t, proxyAddr, target, "tok-1", http.StatusForbidden)
}

// assertConnect dials proxyAddr and issues a CONNECT for target carrying tok.
// wantStatus == 0 means "expect the tunnel to establish" (200); otherwise it
// asserts the exact denial status code.
func assertConnect(t *testing.T, proxyAddr, target string, tok proxyctl.Token, wantStatus int) {
	t.Helper()
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	auth := base64.StdEncoding.EncodeToString([]byte(string(tok) + ":"))
	fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth)
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if wantStatus == 0 {
		if !strings.Contains(line, "200") {
			t.Fatalf("expected 200 Connection established, got %q", line)
		}
		return
	}
	if !strings.Contains(line, fmt.Sprintf("%d", wantStatus)) {
		t.Fatalf("expected status %d, got %q", wantStatus, line)
	}
}
