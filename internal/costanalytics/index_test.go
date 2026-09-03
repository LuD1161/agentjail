package costanalytics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

func TestIndexerIncrementalCompleteRecords(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	claudeDir := filepath.Join(root, "claude", "project")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(claudeDir, "session.jsonl")
	first := `{"type":"assistant","cwd":"/work/project","timestamp":"2026-09-01T12:00:00Z","message":{"model":"claude-opus-4-6","usage":{"input_tokens":10,"output_tokens":2}}}` + "\n"
	if err := os.WriteFile(transcript, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(filepath.Join(root, "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	indexer := NewIndexer(db, IndexPaths{ClaudeProjects: filepath.Join(root, "claude")})
	indexer.now = func() time.Time { return time.Date(2026, 9, 2, 1, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	if err := indexer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, ctx, db, 2, 1, 1)

	partial := `{"type":"assistant","cwd":"/work/project","timestamp":"2026-09-02T12:00:00Z","message":{"model":"claude-opus-4-6","usage":{"input_tokens":5,"output_tokens":1}}}`
	appendFile(t, transcript, partial)
	if err := indexer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, ctx, db, 2, 1, 1)

	appendFile(t, transcript, "\n")
	if err := indexer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, ctx, db, 2, 2, 1)
	sessions, _, err := ReadIndexedSessions(ctx, db, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].InputTokens != 15 || sessions[0].OutputTokens != 3 {
		t.Fatalf("sessions = %#v", sessions)
	}

	if err := indexer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, ctx, db, 2, 2, 1)
}

func TestIndexerResetsTruncatedGeneration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	codexDir := filepath.Join(root, "codex")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(codexDir, "session.jsonl")
	initial := codexFixture("session-one", 10, 2)
	if err := os.WriteFile(transcript, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(root, "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	indexer := NewIndexer(db, IndexPaths{CodexSessions: codexDir})
	if err := indexer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, context.Background(), db, 2, 1, 1)

	replacement := codexFixture("session-two", 3, 1)
	if err := os.WriteFile(transcript, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := indexer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertIndexStatus(t, context.Background(), db, 2, 1, 1)
	sessions, _, err := ReadIndexedSessions(context.Background(), db, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "session-two" || sessions[0].InputTokens != 3 {
		t.Fatalf("sessions after replacement = %#v", sessions)
	}
}

func TestIndexerPreservesCodexForkDeduplication(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	codexDir := filepath.Join(root, "codex")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := codexMeta("parent", "") + codexTurn() + codexUsage(10, 2) + codexUsage(20, 4)
	child := codexMeta("child", "parent") + codexTurn() + codexUsage(10, 2) + codexUsage(30, 6)
	if err := os.WriteFile(filepath.Join(codexDir, "parent.jsonl"), []byte(parent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "child.jsonl"), []byte(child), 0o600); err != nil {
		t.Fatal(err)
	}

	legacy, err := NewCodexReaderAt(codexDir).ReadSessions(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(root, "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := NewIndexer(db, IndexPaths{CodexSessions: codexDir}).Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	indexed, _, err := ReadIndexedSessions(context.Background(), db, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(indexed) != len(legacy) {
		t.Fatalf("indexed sessions = %#v; legacy = %#v", indexed, legacy)
	}
	byID := make(map[SessionID]SessionCost, len(indexed))
	for _, session := range indexed {
		byID[session.SessionID] = session
	}
	if byID["parent"].InputTokens != 20 || byID["child"].InputTokens != 20 {
		t.Fatalf("fork usage = %#v", byID)
	}
}

func codexFixture(session string, input, output int) string {
	return codexMeta(session, "") + codexTurn() + codexUsage(input, output)
}

func codexMeta(session, parent string) string {
	return `{"timestamp":"2026-09-01T12:00:00Z","type":"session_meta","payload":{"id":"` + session + `","forked_from_id":"` + parent + `","cwd":"/work/project"}}` + "\n"
}

func codexTurn() string {
	return `{"timestamp":"2026-09-01T12:00:01Z","type":"turn_context","payload":{"model":"gpt-5.6"}}` + "\n"
}

func codexUsage(input, output int) string {
	return `{"timestamp":"2026-09-01T12:00:02Z","type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":` + strconv.Itoa(input) + `,"output_tokens":` + strconv.Itoa(output) + `}}}}` + "\n"
}

func appendFile(t *testing.T, path, value string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(value); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertIndexStatus(t *testing.T, ctx context.Context, db store.Store, checkpoints, events, daily int64) {
	t.Helper()
	status, err := db.CostIndexStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.CheckpointCount != checkpoints || status.EventCount != events || status.DailyRowCount != daily {
		t.Fatalf("status = %#v, want checkpoints=%d events=%d daily=%d", status, checkpoints, events, daily)
	}
	if !status.Ready {
		t.Fatal("cost projection is not ready")
	}
}
