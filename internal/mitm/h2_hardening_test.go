package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- R2.4: streaming / flush -------------------------------------------------

// TestH2StreamsIncrementallyNotBuffered is the h2 analog of
// TestCaptureDoesNotBufferSSEStream: a slow upstream proves bytes reach the
// client as they are produced, not all at once at EOF.
func TestH2StreamsIncrementallyNotBuffered(t *testing.T) {
	const events = 5
	const gap = 150 * time.Millisecond

	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 0; i < events; i++ {
			io.WriteString(w, "data: tick\n\n")
			flusher.Flush()
			time.Sleep(gap)
		}
	}))

	tn := newH2Tunnel(t, upstream, newBodyStore(t))
	req, _ := http.NewRequest("GET", "https://x/stream", nil)
	start := time.Now()
	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 512)
	var arrivals []time.Duration
	for i := 0; i < events; i++ {
		n, err := resp.Body.Read(buf)
		if n == 0 && err != nil {
			t.Fatalf("read event %d: %v", i, err)
		}
		arrivals = append(arrivals, time.Since(start))
	}

	total := time.Duration(events-1) * gap
	if arrivals[0] > total/2 {
		t.Errorf("first event took %v: response was buffered instead of streamed", arrivals[0])
	}
	if spread := arrivals[events-1] - arrivals[0]; spread < total/2 {
		t.Errorf("all %d events arrived within %v: stream was not incremental", events, spread)
	}
}

// --- R2.1: gRPC unary --------------------------------------------------------

// grpcFrame length-prefixes a message the way application/grpc requires:
// a 1-byte compression flag (0 = none) then a 4-byte big-endian length.
func grpcFrame(msg []byte) []byte {
	f := make([]byte, 5+len(msg))
	f[0] = 0
	binary.BigEndian.PutUint32(f[1:5], uint32(len(msg)))
	copy(f[5:], msg)
	return f
}

func readGRPCFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		t.Fatalf("read grpc frame header: %v", err)
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		t.Fatalf("read grpc frame body: %v", err)
	}
	return msg
}

// TestH2GRPCUnaryRoundTrips is R2.1: a raw application/grpc-framed h2 request
// (no google.golang.org/grpc dependency -- see the task's note on that) round
// trips through the MITM, is recorded like any other h2 request, and its
// grpc-status/grpc-message response trailers survive.
func TestH2GRPCUnaryRoundTrips(t *testing.T) {
	reqMsg := []byte("hello from grpc client")
	respMsg := []byte("hello from grpc server")

	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/grpc" {
			t.Errorf("upstream saw Content-Type = %q, want application/grpc", got)
		}
		got := readGRPCFrame(t, r.Body)
		if !bytes.Equal(got, reqMsg) {
			t.Errorf("upstream saw message %q, want %q", got, reqMsg)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
		w.WriteHeader(http.StatusOK)
		w.Write(grpcFrame(respMsg))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
	}))

	tn := newH2Tunnel(t, upstream, nil)

	req, _ := http.NewRequest("POST", "https://x/grpc.test.Service/Unary", bytes.NewReader(grpcFrame(reqMsg)))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Grpc-Encoding", "identity")

	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (grpc unary uses HTTP 200 with grpc-status in trailers)", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/grpc" {
		t.Errorf("Content-Type = %q, want application/grpc", got)
	}
	gotResp := readGRPCFrame(t, resp.Body)
	if !bytes.Equal(gotResp, respMsg) {
		t.Errorf("client saw message %q, want %q", gotResp, respMsg)
	}
	io.Copy(io.Discard, resp.Body) // drain to EOF so trailers populate

	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want %q", got, "0")
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "OK" {
		t.Errorf("Grpc-Message trailer = %q, want %q", got, "OK")
	}

	lastLog := tn.waitLog(t)
	if lastLog.StatusCode != http.StatusOK {
		t.Errorf("RequestLog.StatusCode = %d, want 200", lastLog.StatusCode)
	}
	if lastLog.RequestHeaders["Content-Type"] != "application/grpc" {
		t.Errorf("RequestLog did not record the grpc content-type header")
	}
}

// --- R2.3: body soak ---------------------------------------------------------

// TestH2GzipResponseStoredDecoded is the h2 analog of
// TestGzipResponseStoredDecoded: a gzip'd h2 response body is captured and
// decoded via the same bodyformat/bodystore path h1 uses.
func TestH2GzipResponseStoredDecoded(t *testing.T) {
	plain := bytes.Repeat([]byte("hello h2 gzip world. "), 4096)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()

	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	}))

	bodies := newBodyStore(t)
	tn := newH2Tunnel(t, upstream, bodies)
	req, _ := http.NewRequest("GET", "https://x/gz", nil)
	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rl := tn.waitLog(t)
	if rl.EncodingRaw != EncodingRawNone {
		t.Errorf("EncodingRaw = %q, want none: a valid gzip stream must decode", rl.EncodingRaw)
	}
	if got := readBody(t, bodies, rl.ResponseBodyPath); !bytes.Equal(got, plain) {
		t.Errorf("stored body is %d bytes, want the %d decoded bytes", len(got), len(plain))
	}
}

// TestH2RedactsSensitiveHeaders proves redaction applies over h2: the shared
// RequestLog produced by the h2 path is redacted at the store boundary the
// same way an h1-sourced row is (store_test.go: TestRequestStoreRoundTrip).
// See ADR 0032.
func TestH2RedactsSensitiveHeaders(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tn := newH2Tunnel(t, upstream, nil)
	req, _ := http.NewRequest("GET", "https://x/secret", nil)
	req.Header.Set("Authorization", "Bearer h2-secret-token")
	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rl := tn.waitLog(t)
	if rl.RequestHeaders["Authorization"] != "Bearer h2-secret-token" {
		t.Fatalf("captured RequestLog does not hold the raw header (redaction happens at the store, not here): got %q",
			rl.RequestHeaders["Authorization"])
	}

	dbPath := t.TempDir() + "/network.db"
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()
	if err := store.Log(rl); err != nil {
		t.Fatalf("Log: %v", err)
	}
	results, err := store.Query(context.Background(), RequestFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if got := results[0].RequestHeaders["Authorization"]; got != "[REDACTED]" {
		t.Errorf("persisted Authorization = %q, want [REDACTED]: h2 request leaked a credential to disk", got)
	}
}

// TestH2RequestSizeCountsBodyPastScanWindow is the h2 analog of
// TestRequestSizeCountsBodyPastScanWindow: a request body larger than
// maxBodyScan is still forwarded whole and RequestSize reflects the true
// streamed size, not the scan window. See AGE-243.
func TestH2RequestSizeCountsBodyPastScanWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bodyLen int
	}{
		{name: "under the scan window", bodyLen: 4 << 10},
		{name: "one byte over", bodyLen: maxBodyScan + 1},
		{name: "three times over", bodyLen: 3 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamGot int64
			upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamGot, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))

			tn := newH2Tunnel(t, upstream, nil)
			payload := bytes.Repeat([]byte("A"), tc.bodyLen)
			req, _ := http.NewRequest("POST", "https://x/upload", bytes.NewReader(payload))
			req.ContentLength = int64(tc.bodyLen)

			resp, err := tn.cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("h2 RoundTrip: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			rl := tn.waitLog(t)
			if upstreamGot != int64(tc.bodyLen) {
				t.Fatalf("upstream received %d bytes, want %d: forwarding is broken, "+
					"so the size assertion below would be meaningless", upstreamGot, tc.bodyLen)
			}
			if rl.RequestSize != int64(tc.bodyLen) {
				t.Errorf("RequestSize = %d, want %d (off by %d)",
					rl.RequestSize, tc.bodyLen, int64(tc.bodyLen)-rl.RequestSize)
			}
		})
	}
}

// --- R2.6: transport lifecycle ----------------------------------------------

// TestH2TransportReusesUpstreamConnection proves the per-tunnel Transport
// pools the upstream h2 connection across streams instead of dialing fresh
// for every request: 20 requests over one MITM tunnel must open exactly one
// upstream connection.
func TestH2TransportReusesUpstreamConnection(t *testing.T) {
	var newConns int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	upstream.EnableHTTP2 = true
	upstream.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	upstream.StartTLS()
	defer upstream.Close()

	tn := newH2Tunnel(t, upstream, nil)
	// Drain logs in the background: the channel is buffered to 8, and this
	// test's whole point is issuing more requests than that in one tunnel.
	go func() {
		for range tn.logs {
		}
	}()

	const n = 20
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://x/req-%d", i), nil)
		resp, err := tn.cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("h2 RoundTrip %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := atomic.LoadInt32(&newConns); got != 1 {
		t.Errorf("upstream saw %d new connections for %d requests over one h2 tunnel, want 1: "+
			"the shared Transport is not pooling the upstream h2 connection", got, n)
	}
}

// TestH2TransportClosesIdleConnectionsOnExit mutation-probes the
// `defer transport.CloseIdleConnections()` in serveH2: removing it would leave
// the pooled upstream h2 ClientConn's readLoop goroutine running after Handle
// returns, since the per-tunnel Transport is otherwise unreferenced but its
// pooled conn is not force-closed by anything else.
func TestH2TransportClosesIdleConnectionsOnExit(t *testing.T) {
	upstream := h2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tn := newH2Tunnel(t, upstream, nil)
	req, _ := http.NewRequest("GET", "https://x/", nil)
	resp, err := tn.cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// End the tunnel: closing the client conn makes ServeConn return, which
	// runs serveH2's deferred CloseIdleConnections.
	tn.cc.Close()
	tn.clientTL.Close()
	select {
	case <-tn.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after the client connection closed")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if !strings.Contains(goroutineStacks(), "http2.(*ClientConn).readLoop") {
			return
		}
		if time.Now().After(deadline) {
			t.Error("http2 client readLoop goroutine still running after the tunnel closed: " +
				"CloseIdleConnections is not tearing down the pooled upstream connection")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func goroutineStacks() string {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}
