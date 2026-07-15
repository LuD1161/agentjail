# ADR 0075: bound the SIGHUP reload rate by coalescing

**Status:** Accepted

## Context

A full Rego recompile is the daemon's most expensive operation. SIGHUP triggers
one, and SIGHUP is the one reload trigger that **cannot** be authenticated:
Landlock is a filesystem LSM and does not mediate signals, so a same-UID process
reaches it regardless of the sandbox. The control socket's `daemon_reload` is
gated by the ctlauth token (ADR 0069); this path has no equivalent lever.

It is reachable in practice, not just in principle. Verified by evaluating the
real policy bundle:

| command | verdict |
|---|---|
| `pkill -f agentjail-daemon` | **deny** (`library/no-daemon-kill`) |
| `kill -HUP $(pgrep -f agentjail-daemon)` | **allow** |

`no-daemon-kill` matches `pkill`/`killall` **by process name**; a PID resolved
via `pgrep` and signalled with `kill` does not match. Its own "WHAT IT DOES NOT
COVER" section says exactly this. So an agent can drive reloads through an
allowed Bash command.

Two prior claims about this path deserve correcting, since both shaped how it
was scoped:

- **"Reload blocks eval."** It does not. `policyeval.evaluator.Reload` performs
  the compile (`NewHookOPAEngineWithData`) *outside* `engineMu` and takes the
  write lock only to swap the pointer. Eval blocks for a pointer swap, not a
  recompile.
- **"It is serialized, so it offers no amplification."** Serialization (via
  `reloadMu` and the single-goroutine signal loop, with `sigCh` buffered at 1 so
  excess signals are dropped rather than queued) bounds *concurrency*, not
  *rate*. A tight SIGHUP loop keeps the daemon recompiling back-to-back
  indefinitely.

The real amplification is subtler than CPU burn: every reload calls
`e.cache.Invalidate()`. Sustained reloads therefore make every subsequent eval a
cache miss, pushing latency toward the hook's ~30 ms budget — and a hook that
misses its budget stops consulting policy at all.

## Decision

Coalesce SIGHUP-triggered reloads: at most one recompile per
`minReloadInterval` (2 s), with a trigger arriving during the cooldown
**deferred, not dropped**. `internal/daemonapp/reloadcoalesce.go`.

Three choices worth naming:

**Bound the signal path, not `reloadPolicy`.** The ticket proposed rate-limiting
reload irrespective of trigger, on the grounds that bounding cost beats trusting
the caller. That reasoning predates its own premise: after ADR 0067–0069, the
socket path *has* a real boundary, so trusting an authenticated caller is now
justified. More decisively, `daemon_reload` answers with the compile verdict
(ADR 0066) — coalescing there would make the verdict a lie, describing a
recompile that has not happened yet. SIGHUP can neither be authenticated nor
report a verdict, so it is the path that must be bounded.

**Defer, don't drop.** The CLI reloads via SIGHUP in several places
(`mcp.go`, `custom_rules.go`). Silently skipping a reload would let
`agentjail mcp allow` report success while the change never takes effect — the
silent-drift class of ADR 0050/0073, reintroduced.

**Keep the handler.** Dropping SIGHUP entirely was the alternative, on the
grounds that the socket now carries an authenticated `daemon_reload` with a real
reply. Rejected: SIGHUP is still the CLI's actual mechanism in those paths, so
removing it breaks working commands for a lever that coalescing already bounds.

## Consequences

A SIGHUP storm collapses to one recompile per 2 s regardless of how many
signals arrive. A human editing `policy.yaml` and sending one SIGHUP is
unaffected — 2 s is far below human reload cadence.

The signal loop is now a `select` over the signal channel and a coalesce timer.
The shutdown path is unchanged.

**The residual is larger than what this closes, and worth stating plainly:**
`kill -9 $(pgrep -f agentjail-daemon)` is also allowed (same by-name gap), and
killing the daemon outright is strictly stronger than making it busy. The SIGHUP
storm was never the best available lever. What blunts *that* is ADR 0074 —
a killed daemon now resolves to `degraded`, not fail-open, so agentjail's
self-protection survives it. Bounding the reload rate is worth doing because it
is cheap and removes a gratuitous CPU/cache-invalidation lever, not because it
is the last word on daemon availability.

Closing the by-name gap properly (matching `kill` against a PID resolved from
`pgrep`, or supervising more aggressively) is a separate question against
`no-daemon-kill`, which is **not** a locked rule and can be disabled via
`policy.yaml` — see `resolver_test.rego`'s B3.

Related: ADR 0066 (`daemon_reload` off the agent socket), ADR 0069 (the token
that gates the socket path), ADR 0074 (the degraded default that blunts the
daemon-down case), ADR 0050 (the hook's budget and fail-open tiers).
