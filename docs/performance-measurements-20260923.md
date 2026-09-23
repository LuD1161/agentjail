# Local performance measurements — 2026-09-23

The review improves large hook latency and multi-rule network matching. Small
end-to-end hook gains are modest; concurrent hooks show no clear improvement.
Unchanged cost projection rebuilds and large gzip capture finalization remain
measurable costs. This measurement follow-up changes benchmarks and docs only.

## Method

- Before: `f766ac89`; after: `45da48ee`. Clean worktrees exclude unrelated local
  untracked files. Identical matcher/connection benchmarks and real-hook latency
  harness were copied onto the before worktree; production code was unchanged.
- Apple M2 Pro, 12 physical/logical cores, 16 GiB RAM, darwin/arm64, Go 1.26.3.
  Shared workstation, initial load averages 5.13/5.03/5.48. No benchmarks or
  builds ran concurrently with another benchmark, but host load was not isolated.
- Three comparison rounds, ordered before/after, after/before, before/after.
  Component benchmarks: `-cpu=1 -benchtime=500ms -benchmem`. Real hooks use normal
  process defaults, 10 warmups and 100 samples per workload per round.
- Tables show medians of three run summaries. Hook p95 is the median of three
  per-run p95s, **not a pooled percentile**. Component times are means within
  each run. Three repeats support local comparisons, not statistical confidence
  intervals or production service-level claims.
- All data is synthetic. No production accounts, transcripts, or credentials
  are used. Raw benchmark lines and hook summaries are in
  [the measurement data](performance-measurements-20260923.txt).

## Real hook → daemon → policy → response

The harness launches the actual hook binary for each request against a real
daemon. All workloads required explicit decisions; fail-open notices fail the
harness. Nine enforcement fixtures and the warm p95 < 50 ms gate passed in all
six before/after runs.

| Workload | Before p95 | After p95 | Change | Before / after median |
| --- | ---: | ---: | ---: | ---: |
| Warm small | 6.36 ms | 5.93 ms | −6.8% | 5.73 / 5.54 ms |
| Uncached small | 8.02 ms | 6.89 ms | −14.1% | 6.44 / 6.18 ms |
| Warm 512 KiB | 29.25 ms | 21.57 ms | −26.3% | 28.08 / 20.27 ms |
| Four concurrent small | 10.96 ms | 11.48 ms | +4.7% | 8.64 / 8.80 ms |

Warm-small p95 ranges: 6.31–6.59 ms before, 5.75–5.93 ms after. Large-request
p95 ranges: 28.96–29.77 ms before, 21.20–22.07 ms after. Concurrent p95 ranges
overlap (10.94–12.87 versus 11.47–11.65 ms); claim no demonstrated improvement
there. Uncached-small p95 ranges are 6.94–8.75 versus 6.86–6.91 ms. The baseline
varies considerably, so its improvement magnitude needs more repeats before
treating it as stable.

## Component measurements

| Network matching | Before | After | Speed ratio | Before / after bytes allocated |
| --- | ---: | ---: | ---: | ---: |
| 128 B, 1 rule | 9.733 µs | 1.669 µs | 5.8x | 12,617 / 1,496 |
| 128 B, 8 rules | 78.164 µs | 3.164 µs | 24.7x | 100,944 / 2,728 |
| 1 MiB, 1 rule | 1.134 ms | 1.130 ms | ~1x | 2,126,052 / 2,114,935 |
| 1 MiB, 8 rules | 9.047 ms | 1.258 ms | 7.2x | 17,008,420 / 2,116,237 |

Precompiled patterns and serializing the payload once reduce repeated rule
work. One-rule large-payload matching remains dominated by payload handling.
These are matcher-only gains, not whole-request speed ratios.

| Daemon connection | Before response | After response | Before / after total | Before / after bytes allocated |
| --- | ---: | ---: | ---: | ---: |
| Small | 125.417 µs | 10.490 µs | 131.477 / 15.959 µs | 1,054,476 / 9,596 |
| 512 KiB | 11.653 ms | 5.827 ms | 11.681 / 7.126 ms | 2,690,214 / 3,692,502 |

This benchmark uses `net.Pipe`, a stub evaluator, and discarded logs. It excludes
OPA and process startup. Response timing ends when the response is decoded;
total timing also waits for post-response work. Small-request allocation drops
99.1%, but large-request allocation rises **37.3%** as the smaller initial
scanner buffer grows. Moving log-only work after the response reduces response
latency without eliminating that work. Neither tradeoff should be hidden by the
small-request result.

## Remaining costs

[Cost projection measurements](cost-projection-performance.md): rebuilding
unchanged 1k/10k/100k histories takes 4.41/42.93/442.66 ms and allocates
2.17/26.26/283.84 MB per operation. Runtime scales with lifetime history.

[Capture finalization measurements](capture-finalization-performance.md): gzip
finalization of 1/16/64 MiB synthetic JSONL takes 3.04/42.99/170.56 ms. Expansion
is 6.47–6.54x. Repeated-byte fixtures understate this cost by about threefold at
larger sizes. Finalization remains synchronous; these numbers exclude original
body writes and do not measure full HTTP request duration.

## Shared-store writer contention

A 2 ms writer probe compares idle indexing with continuous unchanged rebuilds.
Rows show medians of three per-run summaries. The nominal window is two seconds,
but the current rebuild finishes before stopping. This is an overlap stress
test, not production refresh frequency or a production latency percentile.

| CPUs available to Go | Events | Idle / rebuild writer p95 | Idle / rebuild samples | Rebuild maximum start gap |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1,000 | 0.128 / 3.601 ms | 1000 / 155 | 25.55 ms |
| 1 | 10,000 | 0.128 / 39.826 ms | 1000 / 133 | 43.57 ms |
| 1 | 100,000 | 0.135 / 396.302 ms | 1000 / 26 | 396.80 ms |
| 12 | 1,000 | 0.147 / 3.134 ms | 1000 / 997 | 4.48 ms |
| 12 | 10,000 | 0.139 / 33.550 ms | 1000 / 228 | 37.66 ms |
| 12 | 100,000 | 0.167 / 324.102 ms | 999 / 108 | 334.90 ms |

For 100,000 events with one CPU, median per-rebuild phase times were 398.7 ms reading, 30.4 ms residual computation, and 20.2 ms replacing projection rows. Rebuild-window duration ranged from 2222–2258 ms; writer sample counts ranged from 20–27.

For 100,000 events with 12 CPUs, median per-rebuild phase times were 340.6 ms reading, 20.6 ms residual computation, and 21.8 ms replacing projection rows. Rebuild-window duration ranged from 2297–2303 ms; writer sample counts ranged from 106–110.

Blocked writes and scheduler delays cause ticker samples to be dropped: this is
a closed-loop probe with fewer samples during rebuilds. The reported latency
starts when `RecordDecision` starts, so it omits time spent waiting to start.
The low sample counts limit tail precision, especially with one CPU. More CPU
availability reduces scheduler pressure but does not eliminate write delays.
Phase measurements include scheduling and pool wait; they do not isolate lock
wait or CPU time. Reading lifetime history dominates measured rebuild wall time,
so optimizing only projection replacement would leave most of that work intact.

## Reproduction

```sh
go test ./internal/netpolicy ./internal/daemonapp -run '^$' -bench '^(BenchmarkMatcherEvaluate|BenchmarkHookConnection)$' -benchmem -cpu=1 -benchtime=500ms
bash cmd/agentjail-hook/test/smoke.sh
go test ./internal/costanalytics -run '^$' -bench '^BenchmarkCostProjectionRefresh$' -benchtime=3x -count=3 -benchmem -cpu=1
go test ./internal/costanalytics -run '^$' -bench '^BenchmarkCostProjectionWriterContention$' -benchtime=1x -count=3 -benchmem -cpu=1,12
go test ./internal/mitm -run '^$' -bench '^BenchmarkBodyCaptureFinish$' -benchmem -benchtime=3x -count=3 -cpu=1
```

Run workloads serially. The baseline requires the identical benchmark and hook
harness files from the after revision. Run each comparison command in the stated
three-round order. Larger workload benchmarks apply to the after revision only.

## Next priorities

1. Evaluate durable invalidation that skips unchanged cost projection rebuilds,
   preserving pricing, source replacement, fork lineage, restart, and failure
   correctness. Measure both changed and unchanged histories before adopting it.
2. Profile gzip finalization under actual payload and storage distributions.
   An asynchronous lifecycle needs explicit bounded queuing, durability, cleanup,
   and shutdown design; these isolated measurements do not justify a goroutine
   around finalization.
3. Investigate large-hook scanner allocation if those requests are frequent.
   Preserve bounded input handling and the small-request allocation benefit.

Git metadata caching, SSE catch-up, UI rendering/memory, and browser interaction
latency were not timed in this run. No measured speed claims are made for those
changes.

## Validation

All six before/after smoke runs passed. All expanded workload benchmarks passed
count or decrypted-body integrity assertions. `go build ./...`, `go vet ./...`,
and race-enabled tests for `internal/costanalytics` and `internal/mitm` passed
in the clean measurement worktree. The original workspace's unrelated untracked
files were preserved. No release, push, or PR was performed.
