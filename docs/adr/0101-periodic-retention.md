# 0101 - Periodic retention

Status: Accepted

## Context

`store.Cleanup` is the only thing that enforces the retention window (default 30
days, `--retention`) and checkpoints the WAL (`PRAGMA wal_checkpoint(TRUNCATE)`,
[ADR 0071](./0071-retention-vacuum-and-wal-checkpoint.md)). It was called exactly
once, inline at daemon startup (`internal/daemonapp/main.go`). There was no
ticker and no other caller.

The daemon is designed to stay up — launchd `KeepAlive`, systemd `Restart=always`
([ADR 0070](./0070-supervisor-restarts-daemon-on-clean-exit.md)). So retention
ran once per process life and then never again: a daemon up for months kept every
decision ever recorded and the 30-day window was fiction. Restarts (e.g. the
auto-updater) masked it by accident, and that masking gets *weaker* as the daemon
gets more stable (AGE-225).

The soak harness measured the cost: the DB grows linearly (~445 bytes/decision,
22 MB at 50k) with nothing reclaiming it while the daemon lives. The WAL, by
contrast, stays bounded by SQLite's own autocheckpoint — so the missing periodic
checkpoint is not urgent, but the missing periodic *cleanup* is the real leak.

## Decision

Run retention on a ticker, not just at startup. A new `--retention-interval`
flag (default **6h**, `0` = startup-only) drives a `retentionLoop` goroutine that
re-invokes the same `retentionSweep` the startup pass uses (store `Cleanup` +
body sweep), so the two cannot diverge. The loop exits on context cancellation.

6h balances two facts from the soak: growth is steady but not fast (hours-scale
reclamation is fine), and `Cleanup`'s `VACUUM` is already conditional (ADR 0071),
so a periodic caller does not thrash the writer (measured ~6,600 decisions/sec,
p99 ~2ms, flat across the run). `0` preserves the old startup-only behavior for
anyone who wants it.

## Consequences

- A daemon that never restarts now enforces its retention window; `--retention`'s
  documented meaning matches its behavior.
- `retentionLoop` is unit-tested (fires repeatedly until cancel; `0` disables) and
  mutation-probed, so a future refactor that silently drops the ticker fails CI.
- The body sweep ([ADR 0092](./0092-persist-request-bodies.md) D2) inherits the
  same cadence for free — it was previously also startup-only.
- The interval is a floor, not a guarantee of freshness between ticks; a session
  that ends just after a tick lingers up to one interval past its window. That is
  an acceptable trade for not running `VACUUM` on the hot path continuously.
