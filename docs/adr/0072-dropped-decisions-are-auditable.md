# 0072 — Dropped decisions must leave a trace

Status: Accepted

## Context

Decisions are persisted asynchronously (ADR 0018): the hot path pushes onto a
bounded channel and a writer goroutine drains it, so a slow DB never wedges a
policy decision. Fail-open on logging is correct and stays — the decision was
already returned to the hook, and enforcement is unaffected.

What was wrong is that the loss was **invisible**. A full buffer or a failed
write dropped the record with only an `slog.Warn` to `daemon.log`. Nothing
durable recorded it, so after the fact the `decisions` table simply
under-reported with no way to tell an idle period from a lossy one. "Is this
table missing rows?" was not answerable from the data it holds.

The count matters more than the individual rows here. Knowing "412 decisions
were dropped in this window" is what distinguishes a quiet day from a broken
one; recovering each lost row is neither possible (the buffer is gone) nor
necessary for that.

## Decision

Count every dropped decision (buffer-full and write-error alike) in an atomic
counter, and emit a `decisions.dropped` audit event carrying the count.

- The hot path only does an atomic add — no IO, no added latency.
- The writer goroutine flushes on a 30s ticker and once more at shutdown.
  Aggregating bounds the blast radius: a saturated store is exactly when we
  must not emit one audit row per drop.
- Best-effort. If the emit fails the count is restored, so the next flush
  retries rather than losing the fact that data was lost.

## Consequences

- Under-recording is now answerable from the DB alone: no `decisions.dropped`
  events in a window means the gap is real idleness, not loss.
- Up to 30s of drops (and any drop after the final flush, e.g. SIGKILL) go
  unrecorded. Accepted: this is a diagnostic, not a ledger.
- `decisions.dropped` counts only what the daemon received. It cannot see
  decisions that never reached it — a daemon that is down, or a hook that
  never fired, is a different gap with no in-daemon detector today. The
  divergence signal for that (`shield.activated` climbing while `decisions`
  stays flat) is a known follow-up, not yet built.

Related: ADR 0018 (SQLite store), ADR 0050 (daemon unreachable), Plan 009
(unified audit log).
