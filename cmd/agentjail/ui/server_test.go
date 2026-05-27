// server_test.go — unit tests for the agentjail local web UI.
//
// NOT in v0.1.0-alpha release. Dev tool only.
package ui

import (
	"bufio"
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
)

// ---------------------------------------------------------------------------
// TestSSEFormat — broadcaster sends event; subscriber receives correctly framed
// data: ...\n\n SSE payload.
// ---------------------------------------------------------------------------

func TestSSEFormat(t *testing.T) {
	store := NewStore()
	srv := NewServer("127.0.0.1:0", "/dev/null", store)

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
	srv := NewServer("127.0.0.1:0", "/dev/null", store)

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
	srv := NewServer("127.0.0.1:0", "/dev/null", store)

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
