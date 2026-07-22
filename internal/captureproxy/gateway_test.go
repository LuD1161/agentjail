package captureproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/mitm"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// fakeRecorder captures logged entries in memory for assertions.
type fakeRecorder struct {
	mu      sync.Mutex
	entries []*mitm.RequestLog
}

func (f *fakeRecorder) Log(rl *mitm.RequestLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, rl)
	return nil
}

func (f *fakeRecorder) all() []*mitm.RequestLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*mitm.RequestLog, len(f.entries))
	copy(out, f.entries)
	return out
}

// newTestGateway starts a Gateway forwarding to an httptest server and
// returns the gateway, its base URL (with nonce), and the fake recorder.
func newTestGateway(t *testing.T, upstream *httptest.Server) (*Gateway, string, *fakeRecorder) {
	t.Helper()
	target := mustParseURL(t, upstream.URL)
	rec := &fakeRecorder{}
	g := New(target, rec, Options{
		SessionID: "test-session",
		OwnerPID:  1234,
		Transport: upstream.Client().Transport,
	})
	base, err := g.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, base, rec
}

func TestGatewayRejectsRequestWithoutNoncePrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be reached for an unauthenticated request")
	}))
	defer upstream.Close()

	_, base, _ := newTestGateway(t, upstream)
	loopbackRoot := base[:strings.Index(base, "/aj~")]

	resp, err := http.Get(loopbackRoot + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGatewayForwardsWithCorrectNonce(t *testing.T) {
	var gotPath, gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	_, base, rec := newTestGateway(t, upstream)

	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("upstream saw path %q, want %q (nonce must be stripped)", gotPath, "/v1/messages")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("upstream saw method %q, want POST", gotMethod)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("client got body %q", body)
	}

	entries := rec.all()
	if len(entries) != 1 {
		t.Fatalf("expected 1 recorded entry, got %d", len(entries))
	}
	rl := entries[0]
	if rl.Method != http.MethodPost {
		t.Errorf("recorded Method = %q, want POST", rl.Method)
	}
	if rl.Path != "/v1/messages" {
		t.Errorf("recorded Path = %q, want /v1/messages (no nonce)", rl.Path)
	}
	if rl.StatusCode != http.StatusOK {
		t.Errorf("recorded StatusCode = %d, want 200", rl.StatusCode)
	}
	if strings.Contains(rl.URL, "/aj~") {
		t.Errorf("recorded URL leaks the nonce prefix: %q", rl.URL)
	}
	if strings.Contains(rl.Path, "/aj~") {
		t.Errorf("recorded Path leaks the nonce prefix: %q", rl.Path)
	}
}

func TestGatewayStreamsSSEResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter does not support flushing")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	_, base, rec := newTestGateway(t, upstream)

	resp, err := http.Get(base + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	want := "data: chunk-0\n\ndata: chunk-1\n\ndata: chunk-2\n\n"
	if string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}

	entries := rec.all()
	if len(entries) != 1 {
		t.Fatalf("expected 1 recorded entry, got %d", len(entries))
	}
	if entries[0].StatusCode != http.StatusOK {
		t.Errorf("recorded StatusCode = %d, want 200", entries[0].StatusCode)
	}
	if entries[0].Method != http.MethodGet {
		t.Errorf("recorded Method = %q, want GET", entries[0].Method)
	}
	if entries[0].Path != "/v1/messages" {
		t.Errorf("recorded Path = %q, want /v1/messages", entries[0].Path)
	}
}

func TestGatewayPreservesInheritedPathPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := mustParseURL(t, upstream.URL+"/prefix")
	rec := &fakeRecorder{}
	g := New(target, rec, Options{Transport: upstream.Client().Transport})
	base, err := g.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Close()

	resp, err := http.Get(base + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if gotPath != "/prefix/v1/messages" {
		t.Errorf("upstream saw path %q, want /prefix/v1/messages", gotPath)
	}
}

// TestGatewayRedactsCredentialHeadersOnPersist exercises the real
// mitm.RequestStore as the Recorder (not the fake) so redaction is proven at
// the actual persistence boundary the production Gateway writes to (ADR
// 0032), mirroring internal/mitm's own store round-trip test.
func TestGatewayRedactsCredentialHeadersOnPersist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	dbPath := filepath.Join(t.TempDir(), "network.db")
	store, err := mitm.NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	target := mustParseURL(t, upstream.URL)
	g := New(target, store, Options{Transport: upstream.Client().Transport})
	base, err := g.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer g.Close()

	req, err := http.NewRequest(http.MethodGet, base+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-secret-value")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	results, err := store.Query(context.Background(), mitm.RequestFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 stored row, got %d", len(results))
	}
	got := results[0].RequestHeaders["Authorization"]
	if got != "[REDACTED]" {
		t.Errorf("Authorization header = %q, want [REDACTED]", got)
	}
	if got == "Bearer sk-secret-value" {
		t.Fatal("credential leaked verbatim to network.db")
	}
}

func TestGatewayCloseStopsServing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target := mustParseURL(t, upstream.URL)
	g := New(target, &fakeRecorder{}, Options{Transport: upstream.Client().Transport})
	base, err := g.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := http.Get(base + "/v1/messages"); err == nil {
		t.Error("expected request to a closed gateway to fail")
	}
}
