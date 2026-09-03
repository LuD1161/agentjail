package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costindex"
)

func testCostBatch(t *testing.T, path, generation, eventKey string, offset int64) costindex.IngestionBatch {
	t.Helper()
	state, err := costindex.NewParserStateJSON([]byte(`{"model":"gpt-test","offset":12}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	return costindex.IngestionBatch{
		Checkpoint: costindex.Checkpoint{
			Source: costindex.SourceCodex, Path: costindex.Path(path), Generation: costindex.Generation(generation),
			FileIdentity: "identity-" + generation, SizeBytes: 100, ModTimeNS: 42,
			OffsetBytes: offset, ParserVersion: 1, ParserState: state, UpdatedAt: now,
		},
		Events: []costindex.UsageEvent{{
			Source: costindex.SourceCodex, Path: costindex.Path(path), Generation: costindex.Generation(generation),
			EventKey: costindex.EventKey(eventKey), SessionID: "session-1", Timestamp: now,
			Agent: "codex", Model: "gpt-test", Project: "/repo",
			Usage:           costindex.TokenUsage{Input: 10, Output: 2, CacheRead: 3},
			RequestUsage:    costindex.TokenUsage{Input: 10, Output: 2, CacheRead: 3},
			HasRequestUsage: true,
		}},
	}
}

func TestCostBatchIsAtomicAndIdempotent(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	batch := testCostBatch(t, "/sessions/a.jsonl", "g1", "event-1", 50)
	if err := st.CommitCostBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := st.CommitCostBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	status, err := st.CostIndexStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.CheckpointCount != 1 || status.EventCount != 1 {
		t.Fatalf("status = %+v, want one checkpoint and one event", status)
	}

	regressed := testCostBatch(t, "/sessions/a.jsonl", "g1", "event-2", 49)
	if err := st.CommitCostBatch(ctx, regressed); !errors.Is(err, costindex.ErrCheckpointRegression) {
		t.Fatalf("regression error = %v", err)
	}
	wrongGeneration := testCostBatch(t, "/sessions/a.jsonl", "g2", "event-2", 60)
	if err := st.CommitCostBatch(ctx, wrongGeneration); !errors.Is(err, costindex.ErrGenerationMismatch) {
		t.Fatalf("generation error = %v", err)
	}
	status, _ = st.CostIndexStatus(ctx)
	if status.EventCount != 1 {
		t.Fatalf("failed batches persisted events: %+v", status)
	}
}

func TestResetCostGenerationOnlyDeletesExactSource(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for _, batch := range []costindex.IngestionBatch{
		testCostBatch(t, "/sessions/a.jsonl", "g1", "event-a", 50),
		testCostBatch(t, "/sessions/b.jsonl", "g1", "event-b", 50),
	} {
		if err := st.CommitCostBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ResetCostGeneration(ctx, costindex.GenerationRef{Source: costindex.SourceCodex, Path: "/sessions/a.jsonl", Generation: "g1"}); err != nil {
		t.Fatal(err)
	}
	status, _ := st.CostIndexStatus(ctx)
	if status.CheckpointCount != 1 || status.EventCount != 1 {
		t.Fatalf("status after exact reset = %+v", status)
	}
	checkpoints, err := st.ListCostCheckpoints(ctx, costindex.SourceCodex)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].Path != "/sessions/b.jsonl" {
		t.Fatalf("remaining checkpoints = %+v, err %v", checkpoints, err)
	}
}

func TestReplaceAllCostDailyUsagePreservesDimensionsAndStartWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "agentjail.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	started := time.Date(2026, 9, 1, 23, 30, 0, 0, time.UTC)
	row := costindex.DailyUsage{
		Source: costindex.SourceClaudeCode, Path: "/sessions/a.jsonl", Generation: "g1",
		Day: "2026-09-01", SessionID: "session-1", StartedAt: started,
		Agent: "claude-code", Model: "claude-test", Project: "/repo",
		Usage:       costindex.TokenUsage{Input: 100, Output: 20, CacheRead: 50, CacheWrite: 5, CacheWrite5m: 5},
		PricingMode: "request-aware", PricingRevision: "prices-v1", CostUSD: 1.25, EventCount: 2,
	}
	if err := st.ReplaceAllCostDailyUsage(ctx, []costindex.DailyUsage{row}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	rows, err := ro.ListCostDailyUsage(ctx, costindex.Window{Since: started.Add(-time.Minute), Before: started.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].StartedAt != started || rows[0].PricingRevision != "prices-v1" || rows[0].Usage.CacheWrite5m != 5 {
		t.Fatalf("daily rows = %+v", rows)
	}
	if err := func() error {
		writer, ok := ro.(costindex.Writer)
		if ok {
			return errors.New("read-only store unexpectedly exposes cost writer")
		}
		_ = writer
		return nil
	}(); err != nil {
		t.Fatal(err)
	}
}
