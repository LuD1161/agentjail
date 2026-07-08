package mitm

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestStoreRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-network.db")
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	entry := &RequestLog{
		Ts:           now,
		Host:         "api.github.com",
		Method:       "GET",
		Path:         "/repos/LuD1161/agentjail",
		URL:          "https://api.github.com/repos/LuD1161/agentjail",
		StatusCode:   200,
		RequestSize:  128,
		ResponseSize: 4096,
		ElapsedMs:    42,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer token123",
			"User-Agent":    "agentjail/0.1",
		},
		ResponseHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		SessionID: "sess-abc-123",
		ToolName:  "Bash",
	}

	if err := store.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Query back with no filter.
	ctx := context.Background()
	results, err := store.Query(ctx, RequestFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Host != "api.github.com" {
		t.Errorf("host: got %q, want %q", r.Host, "api.github.com")
	}
	if r.Method != "GET" {
		t.Errorf("method: got %q, want %q", r.Method, "GET")
	}
	if r.Path != "/repos/LuD1161/agentjail" {
		t.Errorf("path: got %q, want %q", r.Path, "/repos/LuD1161/agentjail")
	}
	if r.URL != "https://api.github.com/repos/LuD1161/agentjail" {
		t.Errorf("url: got %q, want %q", r.URL, "https://api.github.com/repos/LuD1161/agentjail")
	}
	if r.StatusCode != 200 {
		t.Errorf("status_code: got %d, want 200", r.StatusCode)
	}
	if r.RequestSize != 128 {
		t.Errorf("request_size: got %d, want 128", r.RequestSize)
	}
	if r.ResponseSize != 4096 {
		t.Errorf("response_size: got %d, want 4096", r.ResponseSize)
	}
	if r.ElapsedMs != 42 {
		t.Errorf("elapsed_ms: got %d, want 42", r.ElapsedMs)
	}
	if r.SessionID != "sess-abc-123" {
		t.Errorf("session_id: got %q, want %q", r.SessionID, "sess-abc-123")
	}
	if r.ToolName != "Bash" {
		t.Errorf("tool_name: got %q, want %q", r.ToolName, "Bash")
	}
	// S-C2 / ADR 0032: the Authorization credential must be redacted on disk,
	// never round-trip verbatim. Non-sensitive headers are preserved.
	if r.RequestHeaders["Authorization"] != "[REDACTED]" {
		t.Errorf("request header Authorization: got %q, want %q", r.RequestHeaders["Authorization"], "[REDACTED]")
	}
	if r.RequestHeaders["Authorization"] == "Bearer token123" {
		t.Errorf("request header Authorization leaked credential verbatim")
	}
	if r.RequestHeaders["User-Agent"] != "agentjail/0.1" {
		t.Errorf("request header User-Agent: got %q, want %q", r.RequestHeaders["User-Agent"], "agentjail/0.1")
	}
	if r.ResponseHeaders["Content-Type"] != "application/json" {
		t.Errorf("response header Content-Type: got %q", r.ResponseHeaders["Content-Type"])
	}
}

func TestRequestStoreQueryFilters(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-network.db")
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	entries := []*RequestLog{
		{Ts: now, Host: "api.github.com", Method: "GET", Path: "/repos", URL: "https://api.github.com/repos", StatusCode: 200},
		{Ts: now, Host: "api.github.com", Method: "POST", Path: "/repos", URL: "https://api.github.com/repos", StatusCode: 201},
		{Ts: now, Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages", URL: "https://api.anthropic.com/v1/messages", StatusCode: 200},
		{Ts: now, Host: "registry.npmjs.org", Method: "GET", Path: "/@mcp/sdk", URL: "https://registry.npmjs.org/@mcp/sdk", StatusCode: 200},
	}
	for _, e := range entries {
		if err := store.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	ctx := context.Background()

	// Filter by host.
	results, err := store.Query(ctx, RequestFilter{Host: "api.github.com", Limit: 10})
	if err != nil {
		t.Fatalf("Query host filter: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("host filter: expected 2, got %d", len(results))
	}

	// Filter by method.
	results, err = store.Query(ctx, RequestFilter{Method: "POST", Limit: 10})
	if err != nil {
		t.Fatalf("Query method filter: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("method filter: expected 2, got %d", len(results))
	}

	// Filter by host + method.
	results, err = store.Query(ctx, RequestFilter{Host: "api.github.com", Method: "POST", Limit: 10})
	if err != nil {
		t.Fatalf("Query host+method filter: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("host+method filter: expected 1, got %d", len(results))
	}

	// Limit.
	results, err = store.Query(ctx, RequestFilter{Limit: 2})
	if err != nil {
		t.Fatalf("Query limit: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("limit filter: expected 2, got %d", len(results))
	}
}

func TestRequestStoreStats(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-network.db")
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	entries := []*RequestLog{
		{Ts: now, Host: "api.github.com", Method: "GET", Path: "/a", URL: "https://api.github.com/a", RequestSize: 100, ResponseSize: 1000},
		{Ts: now, Host: "api.github.com", Method: "GET", Path: "/b", URL: "https://api.github.com/b", RequestSize: 200, ResponseSize: 2000},
		{Ts: now, Host: "api.anthropic.com", Method: "POST", Path: "/v1", URL: "https://api.anthropic.com/v1", RequestSize: 50, ResponseSize: 500},
	}
	for _, e := range entries {
		if err := store.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	ctx := context.Background()
	stats, err := store.Stats(ctx, 0)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("expected 2 host stats, got %d", len(stats))
	}
	// Ordered by request_count DESC, so github first.
	if stats[0].Host != "api.github.com" {
		t.Errorf("first host: got %q, want api.github.com", stats[0].Host)
	}
	if stats[0].RequestCount != 2 {
		t.Errorf("github request count: got %d, want 2", stats[0].RequestCount)
	}
	if stats[0].BytesOut != 300 {
		t.Errorf("github bytes out: got %d, want 300", stats[0].BytesOut)
	}
	if stats[0].BytesIn != 3000 {
		t.Errorf("github bytes in: got %d, want 3000", stats[0].BytesIn)
	}
}

func TestRequestStoreCount(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-network.db")
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Errorf("initial count: got %d, want 0", n)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 3; i++ {
		if err := store.Log(&RequestLog{Ts: now, Host: "example.com", Method: "GET", Path: "/", URL: "https://example.com/"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	n, err = store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 3 {
		t.Errorf("count after 3 inserts: got %d, want 3", n)
	}
}

func TestRequestStoreNilHeaders(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test-network.db")
	store, err := NewRequestStore(dbPath)
	if err != nil {
		t.Fatalf("NewRequestStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	entry := &RequestLog{
		Ts:     now,
		Host:   "example.com",
		Method: "GET",
		Path:   "/",
		URL:    "https://example.com/",
	}
	if err := store.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	ctx := context.Background()
	results, err := store.Query(ctx, RequestFilter{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].RequestHeaders != nil {
		t.Errorf("expected nil request headers, got %v", results[0].RequestHeaders)
	}
	if results[0].ResponseHeaders != nil {
		t.Errorf("expected nil response headers, got %v", results[0].ResponseHeaders)
	}
}
