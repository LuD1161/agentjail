# 0033 — Unified Audit Log

Status: Accepted
Date: 2026-06-30
Amends: [ADR 0018](0018-sqlite-local-store.md)

## Context

agentjail had events scattered across 5+ systems: the `audit_events` table
(policy mutations only), the `decisions` table (tool-call evaluations), slog
JSON logs (lifecycle events, config reloads, daemon startup/shutdown), the
`audit.log` flat file (legacy append-only policy mutations), PostHog telemetry
(anonymous remote), and ad-hoc stdout prints. No unified way existed to answer
"what happened to tool X at 3pm" or "who changed policy during this session".

Only one production caller used `RecordAuditEvent`. Over 50 slog event sites
captured useful operational data (shield activation, secret grants/revokes,
session lifecycle, config changes) but all of it was lost on restart since slog
wrote to a rotating file with no structured retention. Reconstructing the full
history of any entity required correlating multiple sources manually.

## Decision

**A unified `audit_log` table replaces the scattered event sources.** The
`audit_events` table and flat-file `audit.log` are migrated idempotently into
the new table. Decisions are NOT duplicated — they stay in the `decisions`
table, and a unified query layer provides a combined chronological view when
needed.

### Schema

```sql
audit_log(
  id          INTEGER PRIMARY KEY,
  ts          TEXT    NOT NULL,   -- RFC 3339
  event_type  TEXT    NOT NULL,   -- e.g. "policy.changed", "session.started"
  entity      TEXT    NOT NULL,   -- what was affected (tool name, session id, rule id)
  detail      TEXT,               -- redacted JSON, 4096-byte cap
  actor       TEXT,               -- who/what caused it (user, daemon, shield)
  session_id  TEXT,               -- links to sessions table when applicable
  ref_id      TEXT                -- cross-reference (e.g. decision id, credential fingerprint)
)
```

Indexed on `(session_id, ts)`, `(event_type, ts)`, and `ts`.

### AuditEmitter interface

A new `AuditEmitter` interface lives in `internal/audit/`. Components import
the interface, not the store — this decouples audit production from the
storage backend. Event type constants are defined in `internal/audit/audit.go`.

### Three durability classes

1. **Fail-closed** — policy mutations. `policy.change_requested` is emitted
   BEFORE `config.Save()`; if the audit write fails, the save is aborted.
   `policy.changed` is emitted AFTER successful save. This guarantees every
   policy mutation has an audit trail.

2. **Transactional** — store auto-emit. Emitted in the same SQLite transaction
   as the primary data write via `New(tx)`. If the audit insert fails, the
   failure is logged but does NOT roll back the primary write. This covers
   tool/skill/session lifecycle events that are written alongside their data.

3. **Best-effort** — lifecycle events (daemon startup, shield activation,
   config reload). Post-commit, fire-and-forget. Never blocks the hot path.
   Acceptable to lose on crash.

### Store-boundary redaction

The `Detail` field is redacted at the store boundary using the same
key-pattern matcher as `RedactToolInput` (strips tokens, keys, passwords,
secrets). A hard 4096-byte cap prevents unbounded JSON from bloating the
database. Caller-side redaction is encouraged as defense-in-depth but not
relied upon.

### Shield compatibility

The shield opens the SQLite database before sandbox activation. Pre-opened
file descriptors survive Landlock/Seatbelt restrictions, so audit writes
continue to work after the kernel sandbox locks down filesystem access.

### Legacy migration

On first run after upgrade, if the `audit_events` table contains rows and the
`audit_log` table is empty, existing entries are migrated idempotently
(best-effort, never blocks startup). The flat-file `audit.log` is similarly
imported if present. Both legacy sources are retained read-only for rollback
safety.

## Consequences

+ Single source for full history reconstruction of any entity — tools,
  sessions, policies, credentials, shield state.
+ Auto-emit from store writes eliminates manual instrumentation for common
  lifecycle events.
+ Policy mutations are fail-closed: no silent, unaudited config changes.
+ 40+ emit sites across daemon, CLI, shield, and secrets provide comprehensive
  coverage.
+ The `AuditEmitter` interface allows future backends (daemon unix socket
  endpoint for true out-of-process decoupling, remote syslog, etc.) without
  changing callers.
+ Decisions stay in their own optimized table — no schema bloat or migration
  risk for the hot path.
- Adds write load to SQLite on every auditable event. Mitigated by WAL mode
  and the best-effort class for high-frequency lifecycle events.
- The 4096-byte detail cap may truncate large payloads. Callers should
  pre-summarize rather than rely on the cap.
- Future: a daemon unix socket audit endpoint would allow out-of-process
  decoupling, letting the shield and CLI emit audit events without opening
  the database directly.
