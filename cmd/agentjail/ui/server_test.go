// server_test.go — unit tests for the agentjail local web UI.
//
// NOT in v0.1.0-alpha release. Dev tool only.
package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	localstore "github.com/LuD1161/agentjail/internal/store"
)

// ---------------------------------------------------------------------------
// TestSSEFormat — broadcaster sends event; subscriber receives correctly framed
// data: ...\n\n SSE payload.
// ---------------------------------------------------------------------------

func TestSSEFormat(t *testing.T) {
	store := NewStore()
	srv := NewServer("127.0.0.1:0", "/dev/null", "", false, store, "")

	// Minimal inline mux for the test.
	mux := http.NewServeMux()
	mux.HandleFunc("/events", srv.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect SSE client.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect SSE: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q; want text/event-stream", ct)
	}

	// Give the subscriber goroutine a moment to register.
	time.Sleep(50 * time.Millisecond)

	// Inject a raw eval line directly.
	raw := []byte(`{"time":"2026-05-24T03:00:00Z","level":"INFO","msg":"eval","tool":"Bash","session_id":"s1","action":"allow","rule_id":"default","elapsed_us":120}`)
	line, ok := store.Ingest(raw)
	if !ok {
		t.Fatal("Ingest returned false for valid eval line")
	}

	// Broadcast manually (mimic processLine).
	b, _ := json.Marshal(line)
	msg := string(b)
	srv.subsMu.Lock()
	for ch := range srv.subs {
		select {
		case ch <- msg:
		default:
		}
	}
	srv.subsMu.Unlock()

	// Read one SSE frame from the response body.
	done := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			text := scanner.Text()
			if strings.HasPrefix(text, "data: ") {
				done <- text
				return
			}
		}
		done <- ""
	}()

	select {
	case frame := <-done:
		if !strings.HasPrefix(frame, "data: ") {
			t.Errorf("SSE frame = %q; want prefix 'data: '", frame)
		}
		// Verify the payload is valid JSON.
		payload := strings.TrimPrefix(frame, "data: ")
		var out EvalLine
		if err := json.Unmarshal([]byte(payload), &out); err != nil {
			t.Errorf("SSE payload not valid JSON: %v", err)
		}
		if out.Tool != "Bash" {
			t.Errorf("SSE payload tool = %q; want Bash", out.Tool)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SSE frame")
	}
}

// ---------------------------------------------------------------------------
// TestParseEvalLine — Store.Ingest correctly parses an eval line.
// ---------------------------------------------------------------------------

func TestParseEvalLine(t *testing.T) {
	store := NewStore()

	raw := []byte(`{"time":"2026-05-24T03:00:00Z","level":"INFO","msg":"eval","tool":"Write","session_id":"abc123","action":"deny","rule_id":"file_policy/sensitive_credential","reason":"touches .ssh","elapsed_us":88}`)
	line, ok := store.Ingest(raw)
	if !ok {
		t.Fatal("expected Ingest to return true for eval line")
	}
	if line.Action != "deny" {
		t.Errorf("Action = %q; want deny", line.Action)
	}
	if line.RuleID != "file_policy/sensitive_credential" {
		t.Errorf("RuleID = %q; want file_policy/sensitive_credential", line.RuleID)
	}

	// Non-eval lines should return false.
	nonEval := []byte(`{"level":"INFO","msg":"daemon started"}`)
	_, ok2 := store.Ingest(nonEval)
	if ok2 {
		t.Error("expected Ingest to return false for non-eval line")
	}
}

// ---------------------------------------------------------------------------
// TestPolicyEnableEndpoint — POST /api/policy/enable writes the .rego file.
// ---------------------------------------------------------------------------

func TestPolicyEnableEndpoint(t *testing.T) {
	// Set HOME to a temp dir so getRulesDir doesn't touch the real system.
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Provide stub library functions.
	testRuleName := "test_rule"
	testRuleContent := []byte(`package agentjail.test_rule`)

	coreNames := func() []string { return []string{"command_policy"} }
	libNames := func() []string { return []string{testRuleName} }
	libContent := func(name string) []byte {
		if name == testRuleName {
			return testRuleContent
		}
		return nil
	}

	store := NewStore()
	srv := NewServer("127.0.0.1:0", "/dev/null", "", true, store, "")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/policy/enable", func(w http.ResponseWriter, r *http.Request) {
		srv.handlePolicyEnable(w, r, libNames, libContent)
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		srv.handleRules(w, r, coreNames, libNames)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// POST enable.
	resp, err := http.Post(ts.URL+"/api/policy/enable?name="+testRuleName, "", nil)
	if err != nil {
		t.Fatalf("POST enable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d; body: %s", resp.StatusCode, body)
	}

	// Verify the .rego file was written.
	target := filepath.Join(tmp, ".agentjail", "rules", testRuleName+".rego")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Errorf("expected .rego file at %s; not found", target)
	}
}

// ---------------------------------------------------------------------------
// TestPolicyEnableUnknownRule — error path returns 400 + JSON error.
// ---------------------------------------------------------------------------

func TestPolicyEnableUnknownRule(t *testing.T) {
	store := NewStore()
	srv := NewServer("127.0.0.1:0", "/dev/null", "", true, store, "")

	libNames := func() []string { return []string{"known_rule"} }
	libContent := func(name string) []byte { return nil }

	mux := http.NewServeMux()
	mux.HandleFunc("/api/policy/enable", func(w http.ResponseWriter, r *http.Request) {
		srv.handlePolicyEnable(w, r, libNames, libContent)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/policy/enable?name=nonexistent_rule", "", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := out["error"]; !ok {
		t.Errorf("response missing 'error' key: %v", out)
	}
}

func TestPolicyEditingDisabledByDefault(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "/dev/null", "", false, NewStore(), "")
	libNames := func() []string { return []string{"known_rule"} }
	libContent := func(string) []byte { return []byte("package agentjail") }

	req := httptest.NewRequest(http.MethodPost, "/api/policy/enable?name=known_rule", nil)
	rec := httptest.NewRecorder()
	srv.handlePolicyEnable(rec, req, libNames, libContent)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "--edit-policy") {
		t.Fatalf("response = %q, want edit-mode guidance", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestStoreRingBuffer — events capped at maxEvents; oldest drop off.
// ---------------------------------------------------------------------------

func TestStoreRingBuffer(t *testing.T) {
	store := NewStore()

	// Ingest maxEvents+10 events.
	for i := 0; i < maxEvents+10; i++ {
		raw := []byte(fmt.Sprintf(`{"time":"2026-05-24T03:00:00Z","level":"INFO","msg":"eval","tool":"Bash","session_id":"s1","action":"allow","elapsed_us":%d}`, i))
		store.Ingest(raw)
	}

	snap := store.Snapshot()
	if len(snap.RecentEvents) != maxEvents {
		t.Errorf("ring buffer length = %d; want %d", len(snap.RecentEvents), maxEvents)
	}
}

// ---------------------------------------------------------------------------
// TestConcurrentIngest — no data race with concurrent ingestion.
// ---------------------------------------------------------------------------

func TestConcurrentIngest(t *testing.T) {
	store := NewStore()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				raw := []byte(fmt.Sprintf(`{"time":"2026-05-24T03:00:00Z","level":"INFO","msg":"eval","tool":"Bash","session_id":"s%d","action":"allow","elapsed_us":%d}`, n, j))
				store.Ingest(raw)
			}
		}(i)
	}
	wg.Wait()
	snap := store.Snapshot()
	if len(snap.Sessions) == 0 {
		t.Error("expected sessions after concurrent ingest")
	}
}

// ---------------------------------------------------------------------------
// TestIsLoopback — address validation helper.
// ---------------------------------------------------------------------------

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9101", true},
		{"::1:9101", false}, // malformed; SplitHostPort fails
		{"[::1]:9101", true},
		{"0.0.0.0:9101", false},
		{"192.168.1.1:9101", false},
	}
	for _, tc := range tests {
		got := IsLoopback(tc.addr)
		if got != tc.want {
			t.Errorf("IsLoopback(%q) = %v; want %v", tc.addr, got, tc.want)
		}
	}
}

func TestSQLiteStateEndpoint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agentjail.db")
	st, err := localstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ctx := rContext()
	if err := st.RecordDecision(ctx, localstore.DecisionRecord{
		Ts:        time.Now().UTC(),
		SessionID: "sess-1",
		Agent:     "claude",
		ToolName:  "Bash",
		Action:    "deny",
		RuleID:    "aws_policy/delete_denied",
		Summary:   "aws s3 rb --force prod",
	}); err != nil {
		t.Fatalf("record decision: %v", err)
	}

	srv := NewServer("127.0.0.1:0", "/dev/null", dbPath, false, NewStore(), "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", srv.handleState)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatalf("GET state: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var snap StateSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if snap.TotalDeny != 1 {
		t.Fatalf("TotalDeny = %d, want 1", snap.TotalDeny)
	}
	if len(snap.Sessions) != 1 || snap.Sessions[0].ID != "sess-1" {
		t.Fatalf("sessions = %+v, want sess-1", snap.Sessions)
	}
	if snap.Source.Kind != "sqlite" || snap.Source.Fallback {
		t.Fatalf("source = %+v, want sqlite without fallback", snap.Source)
	}
}

func TestSQLiteSessionEndpoint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agentjail.db")
	st, err := localstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ctx := rContext()
	if err := st.RecordDecision(ctx, localstore.DecisionRecord{
		Ts:        time.Now().UTC(),
		SessionID: "sess-2",
		Agent:     "codex",
		ToolName:  "Bash",
		Action:    "ask",
		RuleID:    "aws_policy/create_ask",
		Summary:   "aws ec2 run-instances",
		ToolInput: map[string]interface{}{"command": "aws ec2 run-instances", "api_key": "secret"},
	}); err != nil {
		t.Fatalf("record decision: %v", err)
	}

	srv := NewServer("127.0.0.1:0", "/dev/null", dbPath, false, NewStore(), "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", srv.handleSession)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/session?id=sess-2&download=1")
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Events []EvalLine `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if len(out.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(out.Events))
	}
	if !strings.Contains(out.Events[0].ToolInputRedacted, "[redacted]") {
		t.Fatalf("tool input was not redacted: %s", out.Events[0].ToolInputRedacted)
	}
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, "agentjail-session-sess-2.json") {
		t.Fatalf("Content-Disposition = %q", disposition)
	}
}

func TestAuditEndpoint(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agentjail.db")
	st, err := localstore.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.RecordAuditEvent(context.Background(), localstore.AuditRecord{
		Ts:     time.Now().UTC(),
		Action: "policy.disable",
		RuleID: "command_policy/no-sudo",
		User:   "alice",
	}); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	srv := NewServer("127.0.0.1:0", "/dev/null", dbPath, false, NewStore(), "")
	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	srv.handleAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(out.Events) != 1 || out.Events[0].RuleID != "command_policy/no-sudo" {
		t.Fatalf("audit events = %+v", out.Events)
	}
}

func TestStateFallsBackToLogWithWarning(t *testing.T) {
	store := NewStore()
	store.Ingest([]byte(`{"time":"2026-05-24T03:00:00Z","level":"INFO","msg":"eval","tool":"Bash","session_id":"s1","action":"allow"}`))
	srv := NewServer("127.0.0.1:0", "/tmp/daemon.log", filepath.Join(t.TempDir(), "missing.db"), false, store, "")

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	srv.handleState(rec, req)
	var snap StateSnapshot
	if err := json.NewDecoder(rec.Body).Decode(&snap); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if snap.Source.Kind != "log" || !snap.Source.Fallback || snap.Source.Warning == "" {
		t.Fatalf("fallback source = %+v", snap.Source)
	}
}

func TestSafeFilename(t *testing.T) {
	if got := safeFilename("../session id"); got != "___session_id" {
		t.Fatalf("safeFilename = %q", got)
	}
}

func rContext() context.Context {
	return context.Background()
}
