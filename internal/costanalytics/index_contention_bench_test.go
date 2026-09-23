package costanalytics

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costindex"
	"github.com/LuD1161/agentjail/internal/store"
)

const projectionProbeInterval = 2 * time.Millisecond
const projectionProbeWindow = 2 * time.Second

// Measures one serial writer on the indexer's singleton store, including CPU scheduling.
// Phase metrics are wall times, not direct database pool/lock wait measurements.
func BenchmarkCostProjectionWriterContention(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		for _, rebuild := range []bool{false, true} {
			mode := "idle"
			if rebuild {
				mode = "rebuild"
			}
			b.Run(fmt.Sprintf("events=%d/%s", count, mode), func(b *testing.B) {
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
				phases := &projectionPhaseStore{IndexStore: db}
				indexer := NewIndexer(phases, IndexPaths{})
				if err := indexer.rebuildProjection(ctx); err != nil {
					b.Fatal(err)
				}
				before, err := db.CostIndexStatus(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if before.EventCount != int64(count) || before.DailyRowCount != int64(count/100) {
					b.Fatalf("unexpected seed: %+v", before)
				}
				phases.read = 0
				phases.replace = 0
				var samples []time.Duration
				var maxGap, windowTotal, rebuildTotal time.Duration
				rebuilds := 0
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result, elapsed, work, n, err := probeProjectionWindow(db, indexer, rebuild)
					if err != nil {
						b.Fatal(err)
					}
					samples = append(samples, result.latencies...)
					if result.maxGap > maxGap {
						maxGap = result.maxGap
					}
					windowTotal += elapsed
					rebuildTotal += work
					rebuilds += n
				}
				b.StopTimer()
				recorded, err := db.DecisionCount(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if recorded != int64(len(samples)) {
					b.Fatalf("writes=%d samples=%d", recorded, len(samples))
				}
				after, err := db.CostIndexStatus(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if after.EventCount != before.EventCount || after.DailyRowCount != before.DailyRowCount {
					b.Fatalf("projection counts changed: before=%+v after=%+v", before, after)
				}
				if len(samples) == 0 {
					b.Fatal("no writer samples")
				}
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				b.ReportMetric(float64(samples[(len(samples)*50+99)/100-1].Nanoseconds())/1000, "writer-p50-us")
				b.ReportMetric(float64(samples[(len(samples)*95+99)/100-1].Nanoseconds())/1000, "writer-p95-us")
				b.ReportMetric(float64(samples[len(samples)-1].Nanoseconds())/1000, "writer-max-us")
				b.ReportMetric(float64(len(samples)), "writer-samples")
				b.ReportMetric(float64(maxGap.Nanoseconds())/1e6, "probe-gap-max-ms")
				b.ReportMetric(float64(windowTotal.Nanoseconds())/1e6/float64(b.N), "window-ms/op")
				b.ReportMetric(float64(rebuilds)/float64(b.N), "rebuilds/op")
				if rebuilds > 0 {
					b.ReportMetric(float64(phases.read.Nanoseconds())/1e6/float64(rebuilds), "read-ms/rebuild")
					b.ReportMetric(float64(phases.replace.Nanoseconds())/1e6/float64(rebuilds), "replace-ms/rebuild")
					b.ReportMetric(float64((rebuildTotal-phases.read-phases.replace).Nanoseconds())/1e6/float64(rebuilds), "compute-ms/rebuild")
				}
			})
		}
	}
}

type projectionProbeResult struct {
	latencies []time.Duration
	maxGap    time.Duration
	err       error
}

func probeProjectionWindow(db store.Store, indexer *Indexer, rebuild bool) (projectionProbeResult, time.Duration, time.Duration, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stop := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan projectionProbeResult, 1)
	go func() {
		ticker := time.NewTicker(projectionProbeInterval)
		defer ticker.Stop()
		result := projectionProbeResult{}
		var previous time.Time
		defer func() { done <- result }()
		close(ready)
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				result.err = ctx.Err()
				return
			case <-ticker.C:
				start := time.Now()
				if !previous.IsZero() && start.Sub(previous) > result.maxGap {
					result.maxGap = start.Sub(previous)
				}
				previous = start
				err := db.RecordDecision(ctx, store.DecisionRecord{Ts: start, SessionID: "synthetic-writer", Agent: "benchmark", ToolName: "Read", Action: "allow", RuleID: "benchmark/synthetic", Summary: "synthetic writer probe"})
				if err != nil {
					result.err = err
					return
				}
				result.latencies = append(result.latencies, time.Since(start))
			}
		}
	}()
	<-ready
	start := time.Now()
	deadline := start.Add(projectionProbeWindow)
	var work time.Duration
	rebuilds := 0
	var workErr error
	if rebuild {
		for time.Now().Before(deadline) {
			operation := time.Now()
			workErr = indexer.rebuildProjection(ctx)
			work += time.Since(operation)
			if workErr != nil {
				break
			}
			rebuilds++
		}
	} else {
		timer := time.NewTimer(projectionProbeWindow)
		select {
		case <-timer.C:
		case <-ctx.Done():
			workErr = ctx.Err()
		}
		timer.Stop()
	}
	close(stop)
	result := <-done
	elapsed := time.Since(start)
	if workErr != nil {
		return result, elapsed, work, rebuilds, workErr
	}
	return result, elapsed, work, rebuilds, result.err
}

type projectionPhaseStore struct {
	IndexStore
	read    time.Duration
	replace time.Duration
}

func (s *projectionPhaseStore) ListCostUsageEvents(ctx context.Context, w costindex.Window) ([]costindex.UsageEvent, error) {
	start := time.Now()
	defer func() { s.read += time.Since(start) }()
	return s.IndexStore.ListCostUsageEvents(ctx, w)
}
func (s *projectionPhaseStore) ListCostCheckpoints(ctx context.Context, source costindex.Source) ([]costindex.Checkpoint, error) {
	start := time.Now()
	defer func() { s.read += time.Since(start) }()
	return s.IndexStore.ListCostCheckpoints(ctx, source)
}
func (s *projectionPhaseStore) ReplaceAllCostDailyUsage(ctx context.Context, rows []costindex.DailyUsage) error {
	start := time.Now()
	defer func() { s.replace += time.Since(start) }()
	return s.IndexStore.ReplaceAllCostDailyUsage(ctx, rows)
}
