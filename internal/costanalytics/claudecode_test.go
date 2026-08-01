package costanalytics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
