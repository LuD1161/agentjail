package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/LuD1161/agentjail/internal/netpolicy"
)

// streamingBody is an io.ReadCloser backed by an io.Pipe that a caller can
// write to incrementally and never close, modeling a client-streaming/bidi
// RPC that holds its request stream open while it waits on a response.
type streamingBody struct {
	*io.PipeReader
	w *io.PipeWriter
}

func newStreamingBody() *streamingBody {
	pr, pw := io.Pipe()
	return &streamingBody{PipeReader: pr, w: pw}
}

// TestH2StreamingRequestDoesNotDeadlock is AGE-223's central regression test:
// a client-streaming-shaped h2 request (one frame sent, request stream held
// open, response awaited before any half-close) must reach upstream and get
// a response back without the handler blocking on r.Body. Restoring the
// unconditional io.ReadAll(limited) that used to precede forwarding makes
// this test hang until it times out -- mutation-probed by hand, see AGE-223.
func TestH2StreamingRequestDoesNotDeadlock(t *testing.T) {
	reqMsg := []byte("first client-streaming frame")
	respMsg := []byte("response sent before body finished")

	upstreamSawFirstFrame := make(chan struct{}, 1)
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := readGRPCFrame(t, r.Body)
		if !bytes.Equal(got, reqMsg) {
			t.Errorf("upstream saw message %q, want %q", got, reqMsg)
		}
		select {
		case upstreamSawFirstFrame <- struct{}{}:
		default:
		}
		// Respond immediately, without waiting for the client to finish
		// sending: this is exactly what a real bidi/client-streaming server
		// does, and what proves the MITM forwarded the request instead of
		// blocking on a full body read.
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.Write(grpcFrame(respMsg))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))

	tn := newH2Tunnel(t, upstream, nil)

	body := newStreamingBody()
	t.Cleanup(func() { body.w.Close() })

	req, _ := http.NewRequest("POST", "https://x/grpc.test.Service/ClientStream", body)
	req.ContentLength = -1 // unknown/unbounded: this is what marks it streaming
	req.Header.Set("Content-Type", "application/grpc")

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := tn.cc.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Send exactly one frame, then block: never close the pipe, never send
	// a second frame. A handler that pre-drains the body with io.ReadAll
	// would never see this write return the favor -- it would be blocked
	// waiting for EOF that never comes, so RoundTrip would never get a
	// response and this send would race the deadline below instead.
	writeDone := make(chan error, 1)
	go func() { _, err := body.w.Write(grpcFrame(reqMsg)); writeDone <- err }()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write first frame: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writing the first frame did not complete: MITM never started reading the request stream")
	}

	select {
	case err := <-errCh:
		t.Fatalf("h2 RoundTrip: %v", err)
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		gotResp := readGRPCFrame(t, resp.Body)
		if !bytes.Equal(gotResp, respMsg) {
			t.Errorf("client saw message %q, want %q", gotResp, respMsg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("h2 RoundTrip did not return within 5s: request body pre-drain deadlocked the streaming request (AGE-223)")
	}

	select {
	case <-upstreamSawFirstFrame:
	default:
		t.Error("upstream never saw the client's first frame: request was not forwarded")
	}
}

// TestH2StreamingRequestHeaderPolicyDenyStillFires proves body-content
// scanning is the only thing skipped for a streaming request: a deny rule
// keyed on protocol/method/path alone must still fire immediately, without
// waiting on (or deadlocking on) a request body that never completes.
func TestH2StreamingRequestHeaderPolicyDenyStillFires(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached for a denied request")
	}))

	packDir := t.TempDir()
	tmplContent := `id: deny-all-h2-streaming-test
info:
  name: Deny All H2 Streaming Test
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

	logs := make(chan *RequestLog, 1)
	h, caCert := newTestHandler(t, upstream, func(rl *RequestLog) { logs <- rl })
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

	body := newStreamingBody()
	t.Cleanup(func() { body.w.Close() })

	req, _ := http.NewRequest("POST", "https://"+host+":"+port+"/deny-me-streaming", body)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/grpc")

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	select {
	case err := <-errCh:
		t.Fatalf("h2 RoundTrip: %v", err)
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
		if got := resp.Header.Get("X-Agentjail-Deny"); got != "deny-all-h2-streaming-test" {
			t.Errorf("X-Agentjail-Deny = %q, want deny-all-h2-streaming-test", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deny did not fire within 5s: header policy must not wait on a streaming body")
	}

	select {
	case rl := <-logs:
		if rl.PolicyAction != "deny" {
			t.Errorf("PolicyAction = %q, want deny", rl.PolicyAction)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no request log emitted for the denied streaming request")
	}
}
