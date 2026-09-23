# ADR 0002 — Latency is an engineering metric, not a user-facing one

- **Status:** Accepted
- **Date:** 2026-05-23
- **Task:** display-side change; bench
- **Deciders:** agentjail-core
- **Related:** [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) §"How It Works"

## Context

`cmd/agentjail-daemon/main.go` records `elapsed_us` for every eval:

```go
start := time.Now()
resp, err := s.eval(ctx, req)
elapsed := time.Since(start)
// → slog.Info("eval", ..., "elapsed_us", elapsed.Microseconds())
```

This times **exactly** three operations inside the daemon:

1. Cache lookup (sub-microsecond)
2. On cache miss: OPA Rego evaluation against the compiled policy bundle
3. Cache set

It **does not** include:

- Hook process fork/exec (≈3–5 ms cold; ≈0.5 ms when binary is in page cache)
- Hook stdin parse, socket dial, request marshal (≈1 ms)
- Daemon socket read + JSON decode of the request (≈0.3 ms)
- Response marshal, socket write, hook decode, stdout write (≈0.5 ms)
- Claude Code's tool-call dispatch loop reading the hook's stdout

End-user-perceived latency (the time the agent waits between deciding to call
a tool and actually running it) is therefore roughly **`elapsed_us + ~10 ms`**
of plumbing, dominated by the eval cost on cold complex paths.

### Observed numbers (2026-05-23, macOS arm64)

- Smoke test (`cmd/agentjail-hook/test/smoke.sh`): median 8 ms, p95 11 ms (end-to-end wall time)
- Daemon `elapsed_us` for warm cache hit: <1 ms
- Daemon `elapsed_us` for cold complex Bash deny (no-bash-touch-sensitive-path, 8 regex predicates): 20–25 ms
- Daemon `elapsed_us` for typical file-policy match: 1–4 ms

### Why this matters

During demo display work we surfaced `elapsed_us` as a column showing
`21048µs`. Engineering-accurate. Useless to a non-engineer audience:

- "µs" reads as "slow" to most viewers despite meaning microseconds
- It's a partial measurement of the wrong thing (eval cost, not user wait)
- It distracts from the actual headline (a dangerous action was prevented)
- The wide variance between cold (20 ms) and warm (<1 ms) makes the column
  jitter visibly in a recording, drawing the eye to the wrong thing

## Decision

Treat `elapsed_us` as an **internal observability metric**, not a user-facing
UX metric.

1. **Daemon keeps logging it** as a JSON field — forensic value, feeds the
   bench, useful for debugging policy hotspots
2. **`agentjail logs` rich/demo display omits the column entirely**
3. **`agentjail logs --basic` keeps the column** — engineers piping/grepping
   want the raw number, and `--basic` is also what CI logs and audit pipelines
   consume
4. **External performance claims** (README, blog, demo voiceover, sales material)
   cite end-to-end p95 wall time (`~10 ms typical`, `<50 ms target`), measured
   via `cmd/agentjail-hook/test/smoke.sh` — never raw `elapsed_us`
5. **Engineering latency targets** in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) (`<5 ms
   in-process eval`) remain the goal. Enforcement is via the bench in CI,
   not by humans reading log lines

## Consequences

**Positive:**

- Demo recordings read as fast/instant rather than "21 ms"
- Engineers retain full forensic data via `--basic` + raw JSON log
- Removes the awkward partial-measurement explanation from user docs

**Negative:**

- New contributors may not realize the field exists if they only see the rich view
  → mitigated by an inline comment in `cmd/agentjail-daemon/main.go` near the slog call
- Risk of regressing latency without anyone noticing in dogfood
  → mitigated by the bench running in CI on every PR (when CI is re-enabled)
- A future "we made it 2× faster" claim needs to specify which metric (eval,
  warm, cold, end-to-end p95) — but that ambiguity already exists

## Guidance for future contributors

> If you ever add a user-facing latency display anywhere, **measure end-to-end
> wall time** (from hook stdin-read to hook stdout-write), not the daemon's
> partial `elapsed_us`. Otherwise the number is misleading and we have to
> explain "yes it says 21 ms but it's actually ~10 ms total" — which is worse
> than just not showing the number.

## End-to-end regression gate (2026-09-22)

The smoke suite enforces the existing **p95 < 50 ms** end-to-end target for
each of four policy paths: file allow, file deny, shell ask, and MCP deny. Each
runs five warmups followed by 50 measured samples, with separate repeated-input
and unique-input sets. Unique tool inputs avoid the daemon's decision-cache key;
this measures uncached evaluation with the already-running daemon, not startup.
Payloads are evaluated only; no file operation, shell command, or MCP call runs.

A single Python process uses `perf_counter_ns` around hook process creation,
stdin delivery, and response collection. Interpreter startup, JSON preparation,
and result validation are outside the timed interval. This replaces timestamps
from separate Python processes that accidentally counted interpreter overhead.
Nearest-rank p95, median, and maximum are printed for every set. Every sample
must return the expected decision; missing responses and timeouts fail instead
of appearing as fast fail-open successes. A budget miss fails the smoke job.

Developer hosts can explicitly set `AGENTJAIL_SMOKE_P95_MS` to a positive finite
budget or `AGENTJAIL_SMOKE_SAMPLES` to at least 20; the output records both. CI
rejects a changed 50 ms budget or fewer than 50 samples. No retries discard slow
runs. Use a quiet machine for comparisons; sustained host contention is visible
in these wall-time measurements. The smoke CI job already runs this gate.

Calibration on macOS arm64 with concurrent builds paused produced p95 values
of 5.89–6.74 ms across the eight sets (50 samples each). A separate run under
concurrent build load reached 50.35 ms and correctly failed; that result was
not discarded by an automatic retry. The existing 50 ms budget therefore has
substantial headroom on the measured quiet host; CI runner results remain the
source of truth for CI-specific noise.

This gate covers the hook/daemon policy pipeline, not OS sandbox startup, agent
dispatch, external MCP servers, or credential issuance. It does not enforce the
separate in-process evaluation target.

### Large-payload and concurrency diagnostics (2026-09-23)

The same harness additionally reports warm small, uncached small, warm 512 KiB,
and four-concurrent small requests, each with ten warmups and 100 measured
real hook processes. Warm small requests also enforce the configured p95 budget;
the other diagnostic workloads have no absolute budget. These workloads retain
the before/after measurement methodology. Allow and ask samples must have no
degradation notice, and every
diagnostic sample must return an explicit allow. A fast fail-open response
cannot pass either set of checks. Regression tests cover degraded responses,
missing decisions, missed budgets, and CI override rejection.

See [controlled measurements](../performance-measurements-20260923.md) for
before/after results and limits. Run `bash cmd/agentjail-hook/test/smoke.sh`
to run the gate and diagnostics together.

### Hook transport allocation and framing

Hook and daemon scanners start at 4 KiB and grow only when a frame needs it;
the 1 MiB maximum is unchanged. The daemon decodes its routing envelope once
before decoding the selected request type. `BenchmarkHookConnection` reports
full connection cost and allocations for small and large benign tool inputs.
It isolates transport/recording overhead with a trivial evaluator and is not an
OPA or end-to-end agent latency claim.

Log-only summary and tool-input redaction run after the daemon sends the policy
response. Approval-display redaction remains response-critical, and SQLite
still redacts independently at its storage boundary. The connection benchmark
also reports `response-ns/op` (request encode through response decode), separately
from total work including post-response logging.
