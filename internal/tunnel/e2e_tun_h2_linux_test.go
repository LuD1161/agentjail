//go:build linux

// Real-TUN, unprivileged-userns end-to-end proof that the transparent tunnel
// intercepts HTTP/2 and gRPC-over-h2, not just plain TCP/HTTP1 (see
// e2e_tun_linux_test.go for the TCP/DNS baseline this extends). Plan
// plans/010-linux-tunnel-h2-e2e.md, Round 3 (R3.2-R3.4).
//
// Round 1 (feat/net-h2-core, merged e3ab92a) made mitm.MITMHandler.Handle
// offer [h2, http/1.1] and branch to serveH2. handleConn already routes every
// :443 connection on the forward path through Handle (handler.go), so h2
// already flows through the real TUN -- these tests PROVE that, and probe the
// gRPC/ALPN edges that Round 2 (feat/net-h2-hardening, internal/mitm) is
// landing in parallel.
//
// MECHANICS: handleConn's MITM branch is keyed on the LITERAL destination
// port (dstPort == 443, handler.go), and MITMHandler.Handle dials the
// upstream at that same literal port -- so a real e2e proof needs a real
// listener on 127.0.0.1:443, which requires CAP_NET_BIND_SERVICE. On a host
// without it, these tests SKIP (preflightPort443) rather than fail: that is a
// host permission gap, not a code bug.
//
// The h2/gRPC client itself cannot be bash's /dev/tcp (no TLS+ALPN support);
// see h2client_helper_linux_test.go for the self-reexec Go TLS client that
// runs inside the netns via nsenter.
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/dnsvip"
	"github.com/LuD1161/agentjail/internal/mitm"
	"github.com/LuD1161/agentjail/internal/netns"
)

// preflightPort443 skips cleanly when this host cannot bind the literal HTTPS
// port unprivileged. See the package doc comment above for why 443 is not
// substitutable with an ephemeral port for these tests.
func preflightPort443(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Skipf("skipping: cannot bind 127.0.0.1:443 unprivileged "+
			"(needs CAP_NET_BIND_SERVICE / root / net.ipv4.ip_unprivileged_port_start<=443; "+
			"this is a host permission gap, not a tunnel/mitm bug): %v", err)
	}
	return ln
}

// h2E2EHarness bundles the real-TUN + MITM plumbing shared by the h2, gRPC,
// and ALPN-edge-case tests: a real kernel TUN in a fresh userns, a
// ForwardGateway with MITM wired in via SetMITM, and a real TLS/h2 upstream
// (httptest.Server) bound to 127.0.0.1:443 so the MITM's hardcoded :443 dial
// lands on it.
type h2E2EHarness struct {
	ns      *netns.Namespace
	vipStr  string
	caPath  string
	selfExe string

	mu       sync.Mutex
	requests []*mitm.RequestLog
}

func (h *h2E2EHarness) onRequest(rl *mitm.RequestLog) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, rl)
}

func (h *h2E2EHarness) recordedRequests() []*mitm.RequestLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*mitm.RequestLog, len(h.requests))
	copy(out, h.requests)
	return out
}

// setupH2E2E stands up the whole path: CA -> MITM handler -> ForwardGateway
// -> real kernel TUN in a fresh userns, and a real TLS upstream on
// 127.0.0.1:443 serving handler. Returns the harness and a cleanup func the
// caller must defer. Skips (never fails) on host constraints that are not
// tunnel/mitm bugs: no TUN support, no unprivileged userns, or no
// CAP_NET_BIND_SERVICE for the literal :443 bind.
func setupH2E2E(t *testing.T, handler http.Handler) (*h2E2EHarness, func()) {
	t.Helper()
	preflightTUN(t)
	requireTool(t, "nsenter")
	requireTool(t, "timeout")

	port443 := preflightPort443(t)

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	// --- Real TLS+h2 upstream, forced onto the literal :443 listener. ---
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	_ = srv.Listener.Close()
	srv.Listener = port443
	srv.StartTLS()

	// --- In-memory CA (S-C1: never touches disk as a private key) trusted by
	// the in-netns client via a CA-cert-only file. ---
	caCert, caKey, caPEM, err := mitm.GenerateCAInMemory()
	if err != nil {
		srv.Close()
		t.Fatalf("GenerateCAInMemory: %v", err)
	}
	caPath := writeCAFile(t, caPEM)

	h := &h2E2EHarness{selfExe: selfExe, caPath: caPath}

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mh := mitm.NewMITMHandler(caCert, caKey, logger, h.onRequest)
	// The upstream is our own self-signed httptest cert, not one a real root
	// trusts -- MITM's client-facing leg is what these tests exercise, not
	// upstream cert validation, so skip verification on that leg only.
	mh.UpstreamTLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only upstream leg, see comment

	registry := dnsvip.NewRegistry()
	vip, err := registry.Allocate("127.0.0.1")
	if err != nil {
		srv.Close()
		t.Fatalf("allocate VIP: %v", err)
	}
	h.vipStr = vip.String()

	gw, err := NewForwardGateway(Config{}, registry, logger)
	if err != nil {
		srv.Close()
		t.Fatalf("NewForwardGateway: %v", err)
	}
	gw.SetMITM(mh)

	ns, tun, err := netns.CreateWithTUN(netns.TUNIfName, netns.TUNAddrCIDR)
	if err != nil {
		srv.Close()
		_ = gw.Close()
		if errors.Is(err, netns.ErrUnsupported) {
			t.Skipf("skipping: unprivileged userns unsupported: %v", err)
		}
		msg := err.Error()
		if strings.Contains(msg, "operation not permitted") ||
			strings.Contains(msg, "no such device") ||
			strings.Contains(msg, "no such file") {
			t.Skipf("skipping: TUN/userns setup unsupported here: %v", err)
		}
		t.Fatalf("CreateWithTUN failed (real bug on a supposedly-supported host): %v", err)
	}
	h.ns = ns

	ctx, cancel := context.WithCancel(context.Background())
	if err := gw.AttachTUN(ctx, tun); err != nil {
		cancel()
		srv.Close()
		_ = gw.Close()
		_ = ns.Close()
		_ = tun.Close()
		t.Fatalf("AttachTUN: %v", err)
	}
	go func() { _ = gw.ListenAndServe(ctx) }()

	cleanup := func() {
		cancel()
		srv.Close()
		_ = gw.Close()
		_ = ns.Close()
		_ = tun.Close()
	}
	return h, cleanup
}

// writeCAFile writes the CA cert (PEM, public only) to a file inside t.TempDir
// so the self-reexec'd client (running inside the netns, sharing the host
// mount table -- CreateWithTUN's CLONE_NEWNS does not unmount anything) can
// read it and build its own trust pool.
func writeCAFile(t *testing.T, caPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/ca.pem"
	if err := os.WriteFile(path, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

// h2ClientOverNS re-execs this test binary inside h.ns to run a real TLS/ALPN
// client (h2client_helper_linux_test.go), since bash's /dev/tcp cannot do a
// TLS handshake. It hard-caps the run with runInNS's `timeout` wrapper.
func h2ClientOverNS(t *testing.T, h *h2E2EHarness, timeout time.Duration, alpn h2HelperALPN, port, reqKind, path string) h2HelperResult {
	t.Helper()
	addr := net.JoinHostPort(h.vipStr, port)
	stdout, stderr := runInNS(t, h.ns, timeout, h.selfExe,
		h2HelperArg, string(alpn), addr, "127.0.0.1", h.caPath, reqKind, path)
	t.Logf("h2 client stdout=%q stderr=%q", stdout, stderr)
	res, err := parseHelperResult(stdout)
	if err != nil {
		t.Fatalf("parse h2 client result: %v (stdout=%q stderr=%q)", err, stdout, stderr)
	}
	return res
}

// --- R3.2: TestE2ETUNInterceptionH2 ---
//
// AC: the tunnel decrypts the h2 request and a RequestLog is recorded with
// the right method/host/status; the upstream observes ProtoMajor==2.
func TestE2ETUNInterceptionH2(t *testing.T) {
	const (
		path       = "/e2e/h2plain"
		respBanner = "AGENTJAIL_H2_E2E_BANNER"
		wantMethod = http.MethodGet
		wantHost   = "127.0.0.1"
		wantStatus = http.StatusOK
	)

	type observed struct {
		protoMajor int
		host       string
	}
	obsCh := make(chan observed, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case obsCh <- observed{protoMajor: r.ProtoMajor, host: r.Host}:
		default:
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, respBanner)
	})

	h, cleanup := setupH2E2E(t, mux)
	defer cleanup()

	// Client offers [h2, http/1.1]; MITM serves h2 first (AGE-223), so this
	// exercises the real serveH2 path end-to-end over the real TUN.
	res := h2ClientOverNS(t, h, 15*time.Second, alpnBoth, "443", "plain", path)

	if !res.OK {
		t.Fatalf("h2 client failed: %s", res.Err)
	}
	if res.Proto != "HTTP/2.0" {
		t.Fatalf("client negotiated %q, want HTTP/2.0 (h2 downgrade over the real TUN)", res.Proto)
	}
	if res.Status != wantStatus {
		t.Fatalf("client got status %d, want %d", res.Status, wantStatus)
	}
	if res.Body != respBanner {
		t.Fatalf("client got body %q, want %q", res.Body, respBanner)
	}

	select {
	case o := <-obsCh:
		if o.protoMajor != 2 {
			t.Fatalf("upstream observed ProtoMajor=%d, want 2 (MITM must actually speak h2 upstream, not downgrade)", o.protoMajor)
		}
		t.Logf("PASS: upstream observed a real h2 (ProtoMajor=2) request")
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never observed a request despite client receiving a response")
	}

	reqs := h.recordedRequests()
	if len(reqs) != 1 {
		t.Fatalf("got %d recorded RequestLogs, want 1: %+v", len(reqs), reqs)
	}
	rl := reqs[0]
	if rl.Method != wantMethod {
		t.Errorf("RequestLog.Method = %q, want %q", rl.Method, wantMethod)
	}
	if rl.Host != wantHost {
		t.Errorf("RequestLog.Host = %q, want %q", rl.Host, wantHost)
	}
	if rl.Path != path {
		t.Errorf("RequestLog.Path = %q, want %q", rl.Path, path)
	}
	if rl.StatusCode != wantStatus {
		t.Errorf("RequestLog.StatusCode = %d, want %d", rl.StatusCode, wantStatus)
	}
	t.Logf("PASS: RequestLog recorded correctly for the h2 request: %+v", rl)
}

// --- R3.3: gRPC-over-TUN ---
//
// AC: a gRPC-framed (application/grpc, length-prefixed, grpc-status trailer)
// h2 request through the tunnel is intercepted + recorded, and trailers are
// preserved end-to-end. Deliberately does NOT link google.golang.org/grpc
// (task constraint / no new dependency without an ADR) -- the client and the
// test upstream both speak raw application/grpc framing.
func TestE2ETUNInterceptionGRPC(t *testing.T) {
	const (
		path           = "/e2e.Service/Echo"
		wantGRPCStatus = "0"
		wantGRPCMsg    = "OK"
	)
	respPayload := []byte("agentjail-e2e-grpc-response")

	type observed struct {
		protoMajor  int
		contentType string
		method      string
	}
	obsCh := make(chan observed, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case obsCh <- observed{protoMajor: r.ProtoMajor, contentType: r.Header.Get("Content-Type"), method: r.Method}:
		default:
		}
		if len(body) < 5 {
			http.Error(w, "short grpc frame", http.StatusBadRequest)
			return
		}

		// Announce trailer NAMES before WriteHeader (RFC 9113 S8.1 / Go's
		// http.ResponseWriter trailer contract) -- mirrors the same idiom
		// mitm's h2RecordingHandler uses when forwarding trailers back to the
		// original client.
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcFrame(respPayload))
		w.Header().Set("Grpc-Status", wantGRPCStatus)
		w.Header().Set("Grpc-Message", wantGRPCMsg)
	})

	h, cleanup := setupH2E2E(t, mux)
	defer cleanup()

	// Real gRPC clients do h2 prior-knowledge (no ALPN fallback); h2-only
	// pinned matches that.
	res := h2ClientOverNS(t, h, 15*time.Second, alpnH2Only, "443", "grpc", path)

	if !res.OK {
		t.Fatalf("gRPC client failed: %s", res.Err)
	}
	if res.Proto != "HTTP/2.0" {
		t.Fatalf("client negotiated %q, want HTTP/2.0", res.Proto)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("client got HTTP status %d, want 200 (grpc-status travels in the trailer, not the status line)", res.Status)
	}

	select {
	case o := <-obsCh:
		if o.protoMajor != 2 {
			t.Errorf("upstream observed ProtoMajor=%d, want 2", o.protoMajor)
		}
		if o.contentType != "application/grpc" {
			t.Errorf("upstream observed Content-Type=%q, want application/grpc", o.contentType)
		}
		if o.method != http.MethodPost {
			t.Errorf("upstream observed Method=%q, want POST", o.method)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never observed the gRPC request")
	}

	// The trailer assertions are the part that may depend on the parallel
	// feat/net-h2-hardening branch (R2.1 gRPC trailers, R2.2 hop-by-hop
	// stripping) -- see the test's final report for whether this passed now.
	if res.GRPCStatus != wantGRPCStatus {
		t.Errorf("client received grpc-status=%q, want %q (trailer did not reach the client through the MITM)", res.GRPCStatus, wantGRPCStatus)
	}
	if res.GRPCMsg != wantGRPCMsg {
		t.Errorf("client received grpc-message=%q, want %q", res.GRPCMsg, wantGRPCMsg)
	}

	reqs := h.recordedRequests()
	if len(reqs) != 1 {
		t.Fatalf("got %d recorded RequestLogs, want 1: %+v", len(reqs), reqs)
	}
	rl := reqs[0]
	if rl.Method != http.MethodPost {
		t.Errorf("RequestLog.Method = %q, want POST", rl.Method)
	}
	if rl.Path != path {
		t.Errorf("RequestLog.Path = %q, want %q", rl.Path, path)
	}
	if ct := rl.RequestHeaders["Content-Type"]; ct != "application/grpc" {
		t.Errorf("RequestLog.RequestHeaders[Content-Type] = %q, want application/grpc", ct)
	}
	t.Logf("PASS: gRPC RequestLog recorded: %+v", rl)
}

// --- R3.4: ALPN edge cases ---
//
// AC: client offers h2-only (pinned), http/1.1-only, or both -- each
// intercepts and records correctly (h2 clients get h2, h1 clients get h1).
// One shared harness (one :443 bind, one TUN) drives three real connections,
// one per subtest -- the mechanism under test is per-connection ALPN
// negotiation, not the harness setup.
func TestE2ETUNInterceptionALPN(t *testing.T) {
	const path = "/e2e/alpn"
	const banner = "AGENTJAIL_ALPN_BANNER"

	type observed struct{ protoMajor int }
	obsCh := make(chan observed, 3)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case obsCh <- observed{protoMajor: r.ProtoMajor}:
		default:
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, banner)
	})

	h, cleanup := setupH2E2E(t, mux)
	defer cleanup()

	cases := []struct {
		name          string
		alpn          h2HelperALPN
		wantProto     string
		wantUpstreamP int
	}{
		{name: "h2-only client pinned", alpn: alpnH2Only, wantProto: "HTTP/2.0", wantUpstreamP: 2},
		{name: "http1.1-only client", alpn: alpnH1Only, wantProto: "HTTP/1.1", wantUpstreamP: 1},
		{name: "both offered, server prefers h2", alpn: alpnBoth, wantProto: "HTTP/2.0", wantUpstreamP: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := h2ClientOverNS(t, h, 15*time.Second, tc.alpn, "443", "plain", path)
			if !res.OK {
				t.Fatalf("client failed: %s", res.Err)
			}
			if res.Proto != tc.wantProto {
				t.Fatalf("negotiated proto = %q, want %q", res.Proto, tc.wantProto)
			}
			if res.Status != http.StatusOK {
				t.Fatalf("status = %d, want 200", res.Status)
			}
			if res.Body != banner {
				t.Fatalf("body = %q, want %q", res.Body, banner)
			}

			select {
			case o := <-obsCh:
				if o.protoMajor != tc.wantUpstreamP {
					t.Fatalf("upstream ProtoMajor = %d, want %d", o.protoMajor, tc.wantUpstreamP)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("upstream never observed the request")
			}
			t.Logf("PASS: %s intercepted and recorded correctly (proto=%s)", tc.name, res.Proto)
		})
	}

	reqs := h.recordedRequests()
	if len(reqs) != len(cases) {
		t.Fatalf("got %d recorded RequestLogs, want %d (one per ALPN case): %+v", len(reqs), len(cases), reqs)
	}
	for _, rl := range reqs {
		if rl.StatusCode != http.StatusOK || rl.Path != path {
			t.Errorf("unexpected RequestLog for ALPN case: %+v", rl)
		}
	}
}
