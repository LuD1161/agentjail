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

Apple M2 Pro, darwin/arm64, 2026-09-23; medians of three runs, three iterations
per run. No production optimization was applied in this measurement commit.

| Lifetime events | Sessions / projection rows | Refresh time | Allocated bytes/op | Allocations/op |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 10 | 4.76 ms | 2,174,178 | 24,275 |
| 10,000 | 100 | 45.73 ms | 26,260,536 | 241,526 |

The 1,000-event time range was 4.62–5.01 ms; 10,000 events took
45.27–49.70 ms. Ten times the lifetime history incurred approximately 9.6 times
the runtime and 12.1 times the allocation volume despite unchanged output.
These small synthetic runs establish scaling, not a production p95, peak heap,
or an extrapolation to millions of events.

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
