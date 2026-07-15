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

Observed on a dev box: a **4 KiB** `agentjail.db` beside a **3.8 MiB** `-wal` —
i.e. *nothing* had ever been checkpointed. The entire history lived in one
uncommitted sidecar file, where losing `-wal` loses everything. This is a
plausible mechanic for AGE-212's unexplained "DB history starts Jul 2".

The 2026-06-27 loss of ~8000 decisions (AGE-91) came from an **external**
`sqlite3` process checkpointing a DB the daemon held open. That is an argument
against foreign checkpoints, not against the owner checkpointing its own DB.

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
- This does not close AGE-91: there is still no *periodic* checkpoint for a
  daemon that runs for weeks without restart, and no backup. Startup is a
  floor, not the whole answer.
- The AGE-91 rule is unchanged and still load-bearing: never checkpoint or
  VACUUM this DB from an external process. Read-only consumers use
  `store.OpenReadOnly` (`mode=ro`).
- Pinned by `TestCleanupCheckpointsWAL`.

Refs: AGE-212, AGE-91. Related: ADR 0018 (SQLite store).
