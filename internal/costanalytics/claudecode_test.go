package costanalytics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClaudeParserStateResumesWithoutConversationContent(t *testing.T) {
	fallback := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	state := NewClaudeParserState("session-resume", "/fallback", fallback)
	if _, ok := ApplyClaudeRecord(&state, []byte(`{"type":"user","cwd":"/real/project","timestamp":"2026-07-31T23:59:00Z","message":{"content":"not retained"}}`)); ok {
		t.Fatal("user record produced usage")
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "not retained") {
		t.Fatalf("parser state retained conversation content: %s", encoded)
	}
	var resumed ClaudeParserState
	if err := json.Unmarshal(encoded, &resumed); err != nil {
		t.Fatal(err)
	}
	usage, ok := ApplyClaudeRecord(&resumed, []byte(`{"type":"assistant","timestamp":"2026-08-01T00:01:00Z","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":4,"cache_creation_input_tokens":3,"cache_creation":{"ephemeral_5m_input_tokens":1,"ephemeral_1h_input_tokens":2}}}}`))
	if !ok {
		t.Fatal("assistant usage was not decoded")
	}
	if usage.SessionID != "session-resume" || usage.Project != "/real/project" || usage.Model != "claude-opus-4-8" {
		t.Fatalf("usage identity = %+v", usage)
	}
	if usage.Usage.Input != 10 || usage.Usage.Output != 4 || usage.Usage.CacheWrite != 3 || usage.Usage.CacheWrite5m != 1 || usage.Usage.CacheWrite1h != 2 {
		t.Fatalf("usage tokens = %+v", usage.Usage)
	}
	if want := time.Date(2026, 7, 31, 23, 59, 0, 0, time.UTC); !resumed.StartedAt.Equal(want) {
		t.Fatalf("StartedAt = %v, want %v", resumed.StartedAt, want)
	}
}

func TestClaudeCodeReaderUsesTranscriptCWDAndAggregatesUsage(t *testing.T) {
	projects := t.TempDir()
	sessionDir := filepath.Join(projects, "-encoded-project")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sessionDir, "session-1.jsonl")
	content := "{not-json}\n" +
		`{"type":"user","cwd":"/real/project","timestamp":"2026-07-31T10:00:00Z"}` + "\n" +
		`{"type":"assistant","cwd":"/real/project","timestamp":"2026-07-31T10:01:00Z","message":{"model":"claude-test","usage":{"input_tokens":10,"output_tokens":4,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	reader := &ClaudeCodeReader{projectsDir: projects}
	sessions, err := reader.ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	got := sessions[0]
	if got.Project != "/real/project" || got.SessionID != "session-1" || got.Model != "claude-test" {
		t.Fatalf("identity = %+v", got)
	}
	if got.InputTokens != 10 || got.OutputTokens != 4 || got.CacheRead != 3 || got.CacheWrite != 2 {
		t.Fatalf("usage = %+v", got)
	}
	wantStart := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	if !got.StartedAt.Equal(wantStart) {
		t.Fatalf("StartedAt = %s, want %s", got.StartedAt, wantStart)
	}
}

func TestClaudeCodeReaderContinuesAfterOversizedContentRecord(t *testing.T) {
	projects := t.TempDir()
	sessionDir := filepath.Join(projects, "-encoded-project")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sessionDir, "session-large.jsonl")
	content := `{"type":"user","cwd":"/real/project","message":{"content":"` +
		strings.Repeat("x", maxTranscriptLineBytes) + `"}}` + "\n" +
		`{"type":"assistant","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":4}}}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := (&ClaudeCodeReader{projectsDir: projects}).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].InputTokens != 10 || sessions[0].OutputTokens != 4 {
		t.Fatalf("sessions = %+v, want usage after oversized content record", sessions)
	}
}

func TestClaudeCodeReaderPricesCacheWritesByTTL(t *testing.T) {
	projects := t.TempDir()
	sessionDir := filepath.Join(projects, "-encoded-project")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sessionDir, "session-cache.jsonl")
	content := `{"type":"assistant","message":{"model":"claude-opus-4-8","usage":{"input_tokens":1000000,"output_tokens":1000000,"cache_read_input_tokens":1000000,"cache_creation_input_tokens":2000000,"cache_creation":{"ephemeral_5m_input_tokens":1000000,"ephemeral_1h_input_tokens":1000000}}}}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := (&ClaudeCodeReader{projectsDir: projects}).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	got := sessions[0]
	if got.CacheWrite != 2_000_000 || got.CacheWrite5m != 1_000_000 || got.CacheWrite1h != 1_000_000 || got.CostUSD != 46.75 {
		t.Fatalf("TTL-aware session = %+v", got)
	}
	if got.PricingMode != PricingModeRequestAware {
		t.Fatalf("PricingMode = %q, want request-aware", got.PricingMode)
	}
}

func TestClaudeCodeReaderMarksUnclassifiedCacheWritesEstimated(t *testing.T) {
	projects := t.TempDir()
	sessionDir := filepath.Join(projects, "-encoded-project")
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sessionDir, "session-cache-old.jsonl")
	content := `{"type":"assistant","message":{"model":"claude-opus-4-8","usage":{"cache_creation_input_tokens":1000000}}}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := (&ClaudeCodeReader{projectsDir: projects}).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].PricingMode != PricingModeTTLEstimate || sessions[0].CostUSD != 6.25 {
		t.Fatalf("unclassified cache session = %+v", sessions)
	}
}
