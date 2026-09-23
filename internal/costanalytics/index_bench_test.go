package costanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costindex"
	"github.com/LuD1161/agentjail/internal/store"
)

// Measures unchanged lifetime-history projection work, excluding ingestion.
// See ADR 0142-incremental-cost-index.
func BenchmarkCostProjectionRefresh(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("events=%d", count), func(b *testing.B) {
			ctx := context.Background()
			db, err := store.Open(filepath.Join(b.TempDir(), "agentjail.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := db.Close(); err != nil {
					b.Error(err)
				}
			})
			seedProjectionBenchmark(b, ctx, db, count)
			indexer := NewIndexer(db, IndexPaths{})
			if err := indexer.rebuildProjection(ctx); err != nil {
				b.Fatal(err)
			}
			before, err := db.CostIndexStatus(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if before.EventCount != int64(count) || before.DailyRowCount != int64(count/100) {
				b.Fatalf("unexpected seed status: %+v", before)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := indexer.rebuildProjection(ctx); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			after, err := db.CostIndexStatus(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if after.EventCount != before.EventCount || after.DailyRowCount != before.DailyRowCount {
				b.Fatalf("projection changed counts: before=%+v after=%+v", before, after)
			}
			b.ReportMetric(float64(count), "events/op")
		})
	}
}

func seedProjectionBenchmark(b *testing.B, ctx context.Context, db IndexStore, count int) {
	b.Helper()
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for session := 0; session < count/100; session++ {
		id := SessionID(fmt.Sprintf("synthetic-session-%d", session))
		project := Project(fmt.Sprintf("/synthetic/project-%d", session%5))
		started := start.Add(time.Duration(session) * 24 * time.Hour)
		source := costindex.SourceClaudeCode
		model := costindex.Model("claude-sonnet-4-5")
		parser := persistedParserState{Claude: &ClaudeParserState{SessionID: id, Project: project, StartedAt: started}}
		if session%2 != 0 {
			source = costindex.SourceCodex
			model = "gpt-5"
			parser = persistedParserState{Codex: &CodexParserState{SessionID: id, Project: project, StartedAt: started, CanSplit: true, MaxTotal: 125000, Usage: CodexTokenUsage{InputTokens: 100000, OutputTokens: 25000, TotalTokens: 125000}}}
		}
		encoded, err := json.Marshal(parser)
		if err != nil {
			b.Fatal(err)
		}
		state, err := costindex.NewParserStateJSON(encoded)
		if err != nil {
			b.Fatal(err)
		}
		cp := costindex.Checkpoint{Source: source, Path: costindex.Path(fmt.Sprintf("/synthetic/session-%d.jsonl", session)), Generation: "v1", FileIdentity: fmt.Sprintf("synthetic-%d", session), ParserVersion: costParserVersion, ParserState: state, UpdatedAt: started}
		batch := costindex.IngestionBatch{Checkpoint: cp}
		for event := 0; event < 100; event++ {
			usage := costindex.TokenUsage{Input: 1000, Output: 250, CacheRead: 100}
			batch.Events = append(batch.Events, costindex.UsageEvent{Source: source, Path: cp.Path, Generation: cp.Generation, EventKey: costindex.EventKey(fmt.Sprintf("event-%d", event)), SessionID: costindex.SessionID(id), Timestamp: started.Add(time.Duration(event) * time.Minute), Agent: costindex.Agent(source), Model: model, Project: costindex.Project(project), Usage: usage, RequestUsage: usage, HasRequestUsage: true})
		}
		if err := db.CommitCostBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
}
