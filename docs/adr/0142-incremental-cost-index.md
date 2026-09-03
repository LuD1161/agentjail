# ADR 0142-incremental-cost-index

Status: Accepted

Amends the derived-view reread decision in
[ADR 0123-supplemental-model-pricing](0123-supplemental-model-pricing.md).

## Context

`agentjail cost` reread every eligible Claude Code and Codex transcript before
printing a report. The requested period was applied to Codex sessions only
after every JSONL file had been parsed. On a development machine with 974
Codex transcripts occupying 5.8 GB, the default report remained silent for
45--60 seconds while one active transcript exceeded 1 GB. The command was not
deadlocked, but there was no observable distinction between useful work and a
hang.

Re-reading retained source data did make pricing changes simple: each request
used the current bundled catalog and supplemental rules. Replacing that scan
with persisted dollar totals alone would make reports fast at the cost of
freezing old prices and losing the request-level dimensions required by ADR
0123. Filtering files by modification time alone is also insufficient. Active
JSONL files grow, Codex reports cumulative counters, forked transcripts copy
ancestor history, and a process may stop in the middle of a record.

AgentJail's daemon is already supervised continuously by launchd or systemd.
Adding a separate cron job would duplicate lifecycle and installation logic,
and a sleeping laptop can miss a wall-clock invocation.

## Decision

Maintain a local, typed cost index in the existing AgentJail SQLite store. The
index persists only usage metadata: source and session identity, model and
project attribution, timestamps, token categories, request-pricing dimensions,
fork lineage, and recorded cost where a provider supplies it. It never persists
conversation or tool-result content.

Each JSONL source has a durable checkpoint containing its file generation,
last complete-record byte offset, and the typed parser state needed to resume
cumulative counters. Usage facts and the checkpoint that acknowledges them are
committed in one transaction with idempotent source keys. A trailing partial
record remains unacknowledged. Replacement or truncation starts a new source
generation and removes only facts derived from the replaced generation.

Retain normalized Codex lineage keys independently of the report window. A new
fork may copy history from an ancestor older than the maximum 90-day report, so
normal report retention cannot discard the evidence needed to avoid charging
that history twice.

Materialize report rows by UTC session-start day, source, session, project, and
model. Rows retain token totals, cost, pricing mode, and a pricing revision;
dollar totals can therefore be rebuilt from normalized facts when pricing
changes without rereading transcripts. Reports retain the existing CLI
contract: `--period` selects whole sessions by their start time, rather than
splitting a long-running session at an event boundary. OpenCode remains an
external typed SQLite source and is folded into the projection during refresh;
it does not require a transcript scan.

Run cost maintenance once after daemon readiness and then at each next local
calendar midnight through a small process-local daily scheduler. The scheduler
only supplies serial calendar execution and cancellation. The cost job owns its
durable checkpoints and catches up every missed day, so sleep or downtime does
not depend on a timer being delivered. Transcript parsing happens outside a
write transaction; each bounded batch is committed atomically through the
daemon's existing singleton store.

CLI and UI readers use the store's read-only capability. They never fall back
to a synchronous multi-gigabyte transcript scan. During first backfill or after
an indexing failure, reports return the indexed-through time and an explicit
building or stale diagnostic. Cost maintenance is informational and cannot
block policy evaluation; failures are visible but remain fail-open with respect
to enforcement.

## Consequences

- The first upgrade performs one resumable background backfill. Later source
  ingestion is proportional to appended transcript bytes; rebuilding the small
  typed projection never rereads provider transcripts.
- Cost queries read a small indexed time series and should complete in
  milliseconds instead of tens of seconds.
- A daemon must have run the new indexer before the new CLI can report indexed
  cost data; absence is explicit rather than triggering the legacy scan.
- The reusable scheduler can host later daily maintenance without becoming a
  cron-expression framework. Each job still owns its durability and catch-up
  semantics.
- The SQLite schema grows, but no new dependency or second AgentJail database
  connection is introduced.
- Parser-version or pricing-revision changes can rebuild derived rows from
  retained typed facts. Raw transcripts remain the ultimate recovery source.
