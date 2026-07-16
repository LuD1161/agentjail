package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// tunnel stands up a MITM handler in front of upstream and returns a TLS client
// conn plus the last emitted log.
type tunnel struct {
	client *tls.Conn
	logs   chan *RequestLog
	done   chan struct{}
}

func newTunnel(t *testing.T, upstream *httptest.Server, bodies *BodyStore) *tunnel {
	t.Helper()
	caCert, caKey, err := GenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	logs := make(chan *RequestLog, 8)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewMITMHandler(caCert, caKey, logger, func(rl *RequestLog) { logs <- rl })
	handler.UpstreamTLSConfig = upstreamTLSConfig(upstream)
	handler.Bodies = bodies

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.Handle(serverConn, "localhost", port)
	}()

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientTLS := tls.Client(clientConn, &tls.Config{ServerName: "localhost", RootCAs: pool})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	return &tunnel{client: clientTLS, logs: logs, done: done}
}

func newBodyStore(t *testing.T) *BodyStore {
	t.Helper()
	b, err := NewBodyStore(filepath.Join(t.TempDir(), "bodies"))
	if err != nil {
		t.Fatalf("NewBodyStore: %v", err)
	}
	return b
}

func (tn *tunnel) waitLog(t *testing.T) *RequestLog {
	t.Helper()
	select {
	case rl := <-tn.logs:
		return rl
	case <-time.After(20 * time.Second):
		t.Fatal("no request log emitted")
		return nil
	}
}

func readBody(t *testing.T, b *BodyStore, rel string) []byte {
	t.Helper()
	rc, err := b.Open(rel)
	if err != nil {
		t.Fatalf("Open(%q): %v", rel, err)
	}
	if rc == nil {
		t.Fatalf("body %q absent", rel)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

// The capture tees: an SSE stream must reach the client event by event, not in
// one lump when the response ends. See ADR 0092-persist-request-bodies (D1).
func TestCaptureDoesNotBufferSSEStream(t *testing.T) {
	const events = 5
	const gap = 150 * time.Millisecond

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < events; i++ {
			io.WriteString(w, "data: tick\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(gap)
		}
	}))
	defer upstream.Close()

	tn := newTunnel(t, upstream, newBodyStore(t))
	req, _ := http.NewRequest("GET", "https://localhost/stream", nil)
	start := time.Now()
	go req.Write(tn.client)

	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	var arrivals []time.Duration
	for i := 0; i < events; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatalf("read event %d: %v", i, err)
		}
		br.ReadString('\n') // blank separator line
		arrivals = append(arrivals, time.Since(start))
	}

	// A buffering proxy holds every event until the stream ends, so the first
	// byte arrives no earlier than the last.
	total := time.Duration(events-1) * gap
	if arrivals[0] > total/2 {
		t.Errorf("first event took %v: capture buffered the stream instead of teeing it", arrivals[0])
	}
	if spread := arrivals[events-1] - arrivals[0]; spread < total/2 {
		t.Errorf("all %d events arrived within %v: stream was not incremental", events, spread)
	}
}

// Peak memory must not track body size -- the whole point of a file sink.
// See ADR 0092-persist-request-bodies (D1).
func TestCapturePeakMemoryDoesNotScaleWithBodySize(t *testing.T) {
	const bodyLen = 128 << 20 // far larger than any plausible buffer

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "134217728")
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for sent := 0; sent < bodyLen; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	bodies := newBodyStore(t)
	tn := newTunnel(t, upstream, bodies)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	req, _ := http.NewRequest("GET", "https://localhost/big", nil)
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("drain body: %v", err)
	}
	resp.Body.Close()
	if n != bodyLen {
		t.Fatalf("client got %d bytes, want %d", n, bodyLen)
	}

	rl := tn.waitLog(t)
	runtime.ReadMemStats(&after)

	if rl.ResponseSize != bodyLen {
		t.Errorf("ResponseSize = %d, want %d", rl.ResponseSize, bodyLen)
	}
	fi, err := os.Stat(filepath.Join(bodies.Dir(), rl.ResponseBodyPath))
	if err != nil {
		t.Fatalf("stat captured body: %v", err)
	}
	if fi.Size() != bodyLen {
		t.Errorf("captured file is %d bytes, want %d", fi.Size(), bodyLen)
	}

	// HeapAlloc is a live-set reading, so a file sink leaves it flat while a
	// bytes.Buffer sink holds the whole body.
	const budget = 8 << 20
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > budget {
		t.Errorf("heap grew %d bytes capturing a %d byte body (budget %d): the sink is buffering",
			grew, bodyLen, budget)
	}
}

// A gzip response is stored decoded; the raw fallback is not used.
// See ADR 0092-persist-request-bodies (D1).
func TestGzipResponseStoredDecoded(t *testing.T) {
	plain := bytes.Repeat([]byte("hello gzip world. "), 4096)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(plain)
	zw.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	}))
	defer upstream.Close()

	bodies := newBodyStore(t)
	tn := newTunnel(t, upstream, bodies)
	req, _ := http.NewRequest("GET", "https://localhost/gz", nil)
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
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

// A gzip stream that will not decode must store the RAW bytes and say so --
// never silently. This is the Jul-5 bug. See ADR 0092-persist-request-bodies (D1).
func TestCorruptGzipStoresRawWithMarker(t *testing.T) {
	corrupt := append([]byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}, bytes.Repeat([]byte("not gzip"), 512)...)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(corrupt)
	}))
	defer upstream.Close()

	bodies := newBodyStore(t)
	tn := newTunnel(t, upstream, bodies)
	req, _ := http.NewRequest("GET", "https://localhost/bad", nil)
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rl := tn.waitLog(t)
	if rl.EncodingRaw != EncodingRawResponse {
		t.Errorf("EncodingRaw = %q, want %q: raw bytes stored without a marker is the Jul-5 bug",
			rl.EncodingRaw, EncodingRawResponse)
	}
	if got := readBody(t, bodies, rl.ResponseBodyPath); !bytes.Equal(got, corrupt) {
		t.Errorf("stored %d bytes, want the %d raw encoded bytes verbatim", len(got), len(corrupt))
	}
}

// An unsupported encoding is stored raw and marked, never dropped.
// See ADR 0092-persist-request-bodies (D1).
func TestUnsupportedEncodingStoredRaw(t *testing.T) {
	payload := bytes.Repeat([]byte("brotli-ish"), 64)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Write(payload)
	}))
	defer upstream.Close()

	bodies := newBodyStore(t)
	tn := newTunnel(t, upstream, bodies)
	req, _ := http.NewRequest("GET", "https://localhost/br", nil)
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rl := tn.waitLog(t)
	if rl.EncodingRaw != EncodingRawResponse {
		t.Errorf("EncodingRaw = %q, want %q", rl.EncodingRaw, EncodingRawResponse)
	}
	if got := readBody(t, bodies, rl.ResponseBodyPath); !bytes.Equal(got, payload) {
		t.Errorf("stored %d bytes, want %d raw", len(got), len(payload))
	}
}

// A request body past the 1 MiB policy scan window is still stored whole:
// maxBodyScan governs what the DSL inspects, not what is stored.
// See ADR 0092-persist-request-bodies (D1).
func TestRequestBodyStoredWholePastScanWindow(t *testing.T) {
	const bodyLen = 3 << 20
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	bodies := newBodyStore(t)
	tn := newTunnel(t, upstream, bodies)

	payload := bytes.Repeat([]byte("Z"), bodyLen)
	req, _ := http.NewRequest("POST", "https://localhost/upload", bytes.NewReader(payload))
	req.ContentLength = bodyLen
	go req.Write(tn.client)
	resp, err := http.ReadResponse(bufio.NewReader(tn.client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rl := tn.waitLog(t)
	if rl.RequestSize != bodyLen {
		t.Errorf("RequestSize = %d, want %d", rl.RequestSize, bodyLen)
	}
	if got := readBody(t, bodies, rl.RequestBodyPath); len(got) != bodyLen {
		t.Errorf("stored request body is %d bytes, want %d: the scan window truncated the capture",
			len(got), bodyLen)
	}
}

// Body files are 0600 in a 0700 directory.
// See ADR 0092-persist-request-bodies (D1).
func TestBodyFilePermissions(t *testing.T) {
	b := newBodyStore(t)
	if fi, err := os.Stat(b.Dir()); err != nil {
		t.Fatalf("stat dir: %v", err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("body dir mode = %o, want 700", fi.Mode().Perm())
	}

	c, err := b.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c.Write([]byte("secret"))
	rel, _, err := b.Finish(c, "")
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	fi, err := os.Stat(filepath.Join(b.Dir(), rel))
	if err != nil {
		t.Fatalf("stat body: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("body file mode = %o, want 600", fi.Mode().Perm())
	}
}

// A missing body file is absent, not an error.
// See ADR 0092-persist-request-bodies (D1).
func TestMissingBodyFileIsAbsent(t *testing.T) {
	b := newBodyStore(t)
	rc, err := b.Open("deadbeefdeadbeefdeadbeefdeadbeef.body")
	if err != nil {
		t.Errorf("Open of a deleted body returned an error: %v", err)
	}
	if rc != nil {
		t.Error("Open of a deleted body returned a reader")
		rc.Close()
	}
}

// A body path must never escape the store directory.
func TestBodyPathTraversalRejected(t *testing.T) {
	b := newBodyStore(t)
	for _, rel := range []string{"../network.db", "sub/x.body", "/etc/passwd"} {
		if _, err := b.Open(rel); err == nil {
			t.Errorf("Open(%q) was accepted, want rejected", rel)
		}
	}
}

// An empty body leaves no file and no path.
func TestEmptyBodyLeavesNoFile(t *testing.T) {
	b := newBodyStore(t)
	c, err := b.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rel, raw, err := b.Finish(c, "")
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if rel != "" || raw {
		t.Errorf("Finish of an empty capture = (%q, %v), want (\"\", false)", rel, raw)
	}
	entries, _ := os.ReadDir(b.Dir())
	if len(entries) != 0 {
		t.Errorf("%d files left behind for an empty body", len(entries))
	}
}

// A gzip bomb costs the raw bytes, not the disk.
// See ADR 0092-persist-request-bodies (D1).
func TestGzipBombStoredRaw(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(make([]byte, maxExpansionFloor+(1<<20)))
	zw.Close()

	b := newBodyStore(t)
	c, err := b.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c.Write(gz.Bytes())
	rel, raw, err := b.Finish(c, "gzip")
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !raw {
		t.Error("a body expanding past the bomb limit was decoded, want raw fallback")
	}
	if got := readBody(t, b, rel); !bytes.Equal(got, gz.Bytes()) {
		t.Errorf("stored %d bytes, want the %d raw compressed bytes", len(got), gz.Len())
	}
}
