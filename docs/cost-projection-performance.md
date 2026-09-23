# Cost projection refresh measurements

ADR 0142-incremental-cost-index makes source ingestion incremental. Projection
refresh still reads all lifetime usage facts, reconstructs sessions, and replaces
all report rows even when nothing changed. This benchmark isolates that phase;
it does not measure JSONL parsing, provider discovery, or the cost-report query.

## Reproduce

```sh
go test ./internal/costanalytics -run '^$' -bench '^BenchmarkCostProjectionRefresh$' -benchtime=3x -benchmem -cpu=1 -count=3
```

`BenchmarkCostProjectionRefresh` seeds the real singleton SQLite store through
typed `CommitCostBatch` calls. It uses synthetic metadata only: 100 events per
session, evenly split between Claude Code and Codex, five projects, one model
per session, request-aware Codex usage, and daily session starts. No transcript
or real account information is read. Seeding and the initial projection build
are outside timing. Before and after timing, assertions verify event and
projection-row counts. Each timed iteration rebuilds unchanged history.

The benchmark is serial, with GOMAXPROCS=1, and includes database reads, typed
conversion, pricing, aggregation, and transactional projection replacement.
The initial build warms the database/cache. OpenCode and fork-lineage traversal
are excluded; they may add additional costs in production.

## Results

Apple M2 Pro, darwin/arm64, Go 1.26.3, 2026-09-23; medians of three runs, three
iterations per run. No production optimization was applied. These measurements
replace the preliminary 1k/10k results.

| Lifetime events | Sessions / projection rows | Refresh time | Allocated bytes/op | Allocations/op |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 10 | 4.412 ms | 2,174,216 | 24,277 |
| 10,000 | 100 | 42.931 ms | 26,260,536 | 241,526 |
| 100,000 | 1,000 | 442.661 ms | 283,837,224 | 2,413,716 |

The run means ranged from 4.261–4.421 ms, 42.854–43.449 ms, and
441.236–444.608 ms respectively. A hundred times the lifetime history incurs
about a hundred times the runtime, even with unchanged output. Allocated bytes
are cumulative allocations per operation, not peak heap or retained memory.

## Writer contention probe

```sh
go test ./internal/costanalytics -run '^$' -bench '^BenchmarkCostProjectionWriterContention$' -benchtime=1x -count=3 -benchmem -cpu=1,12
```

The probe compares an idle indexer against continuously rebuilding unchanged
history for at least two seconds. One writer uses the same singleton store and
attempts a real `RecordDecision` every 2 ms. Assertions verify every completed
write and unchanged event/projection counts. This intentionally stresses rebuild
overlap; it does not reproduce the production refresh frequency.

The writer is a closed-loop probe: blocked operations and scheduler delays drop
ticker samples. Latency excludes time before the write starts, so sample counts
and maximum start gaps are essential context. It is not an open-loop arrival
p95. Phase times are wall time, including scheduling and pool waits; residual
computation is not a CPU profile. The last rebuild completes before the window
ends, so windows can exceed two seconds.

See [the measurement report](performance-measurements-20260923.md) for both
single-core and 12-core results, sample counts, phases, and raw measurements.

## Follow-up worth evaluating

`Indexer.rebuildProjection` calls `ListCostUsageEvents` with an unbounded window.
The store first obtains generated SQL rows and then allocates a second typed
usage-event slice. Projection builds additional per-session/event maps, and
`ReplaceAllCostDailyUsage` deletes and reinserts all report rows in a transaction.
This makes the unchanged-refresh case a useful first optimization target.

A narrowly scoped follow-up should investigate skipping projection replacement
when no normalized facts/checkpoints, pricing revision, or OpenCode input have
changed and a valid projection already exists. A durable revision contract must
cover replacement/truncation, first backfill, prior failures, price changes,
fork-parent arrival, and process restart; a process-local boolean is insufficient.
Measure the resulting unchanged and changed refreshes with this benchmark and
add invalidation tests before considering session-specific incremental updates.

Do not apply a 90-day event filter as a shortcut: lifetime lineage facts are
required to deduplicate forks, and reports select whole sessions by start time.
Any dirty-session architecture must preserve those ADR 0142 guarantees and make
pricing-wide invalidation explicit. The current measurements do not justify
changing that architecture without a separate design decision.
