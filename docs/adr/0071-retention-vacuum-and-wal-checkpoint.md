# 0071 — Conditional VACUUM, and checkpoint the WAL at startup

Status: Accepted

## Context

The store runs in WAL mode. `store.Cleanup` (retention) runs once per daemon
start and unconditionally ran `VACUUM` afterwards to reclaim space.

Two problems, one cause — everything stayed in the WAL:

1. **VACUUM on every start.** VACUUM rewrites the entire database, and in WAL
   mode that rewrite is journalled. The overwhelmingly common purge is a no-op
   (a 30-day window on a young DB deletes nothing), so each daemon start pushed
   a full copy of the DB into `-wal` to reclaim nothing.
2. **The WAL was never reset.** Only SQLite's auto-checkpoint folded it back,
   and a long-lived daemon with a polling reader can starve that indefinitely.

A store that has not auto-checkpointed can therefore hold its entire history in
`-wal` alone — losing that one file loses everything not yet folded into the
main DB. Auto-checkpoint does usually run, so this is a latent risk rather than
a certainty; the point is that nothing in the daemon *guarantees* it.

A prior incident lost thousands of decisions when an **external** `sqlite3`
process checkpointed a DB the daemon held open. That is an argument against
foreign checkpoints, not against the owner checkpointing its own DB.

## Decision

1. `VACUUM` only when retention actually deleted rows. Nothing deleted,
   nothing to reclaim.
2. Checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`) at the end of `Cleanup`, on
   the owning connection, at startup before the async writer goroutine starts.

Best-effort: `TRUNCATE` yields to live readers and reports busy rather than
blocking. A missed checkpoint is logged, never fatal — it retries next start.

## Consequences

- The main DB holds the data; the WAL stops being the sole copy of history.
- Daemon start no longer pays a full-DB rewrite for a no-op purge.
- Durability is improved, not solved: there is still no *periodic* checkpoint
  for a daemon that runs for weeks without restart, and no backup. Startup is
  a floor, not the whole answer — both remain open follow-ups.
- The rule from the prior loss is unchanged and still load-bearing: never
  checkpoint or VACUUM this DB from an external process. Read-only consumers
  use `store.OpenReadOnly` (`mode=ro`).
- Pinned by `TestCleanupCheckpointsWAL`.

Related: ADR 0018 (SQLite store).
