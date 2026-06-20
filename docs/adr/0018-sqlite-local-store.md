# 0018 — SQLite as the local store

Status: Accepted

## Context

agentjail's local state currently lives in three flat files under
`~/.agentjail/`:

- `daemon.log` — structured JSON lines (slog), one per tool-call evaluation.
  `agentjail logs` tails this file and renders it.
- `audit.log` — structured JSON lines, one per policy mutation
  (`agentjail policy disable`, `mcp allow/block`). Append-only, 0600.
- `policy.yaml` — the config overlay (not a log).

This works at low volume but has three problems the AWS pack + replay
feature surface:

1. **No per-session query.** `agentjail replay --session <id>` needs all
   decisions for one session in chronological order. With a flat JSON-lines
   file that is a full scan + filter; with SQLite it is an indexed lookup.
2. **No structured retention.** The daemon rotates `daemon.log` by size
   (10 MB × 5), but there is no max-age policy and no way to age out old
   sessions without rotating the whole file.
3. **The UI (Phase 3, deferred) needs a query backend.** Browsing decisions,
   sessions, and audit events from a TUI/web app is natural over SQLite and
   painful over a tail of JSON lines.

The design note §13.2 decides: move `daemon.log` and `audit.log` to SQLite
as the single local store for decisions, audit events, and session metadata.
Telemetry (anonymous, remote, PostHog) stays separate — it is a different
concern.

## Decision

**SQLite replaces file logging as the local store.** A new `internal/store`
package wraps `database/sql` + a pure-Go SQLite driver.

### Driver: `modernc.org/sqlite` (pure Go, no CGO)

`modernc.org/sqlite` is a transpiled-from-C SQLite with no CGO dependency.
The alternative, `mattn/go-sqlite3`, requires CGO (a C toolchain at build
time). agentjail builds pure-Go today (cross-compiles to macOS/Linux/Windows
from any host; no C compiler assumed on the install machine). Keeping the
pure-Go build is a hard constraint — the binary is distributed via
`curl | sh` and Homebrew, and a CGO dependency would break the no-toolchain
install story. `modernc.org/sqlite` is larger (~a few MB) but preserves the
pure-Go, single-static-binary distribution.

### Database file

- Path: `~/.agentjail/agentjail.db`.
- Mode: `0600` (owner read/write only). The directory `~/.agentjail/` is
  already `0700` and denied to the agent by `file_policy/agentjail_self`
  (locked), so the agent cannot read the DB.
- Journal mode: **WAL** (`PRAGMA journal_mode=WAL`) — a kill mid-write
  leaves the DB consistent; the WAL is replayed on next open. `synchronous=NORMAL`
  balances durability and latency.
- DSN pragmas: `busy_timeout=5000` (wait on lock instead of erroring),
  `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=NORMAL`.

### Schema

Three tables:

- `decisions(id, ts, session_id, agent, tool_name, summary, action, rule_id,
  reason, impact, elapsed_us, cwd, tool_input_redacted)` — one row per
  tool-call evaluation. `tool_input_redacted` is the redacted JSON of the
  full `tool_input` (ADR 0019). Indexed on `(session_id, ts)` and `ts`.
- `audit_events(id, ts, action, rule_id, user)` — one row per policy
  mutation (replaces `audit.log`).
- `sessions(session_id, start_ts, end_ts, agent, cwd, decision_count)` —
  one row per session, upserted as decisions arrive.

### Write path (daemon)

The daemon opens the store at startup and writes each decision **async /
buffered** (a goroutine draining a bounded channel). A DB write never wedges
a policy decision: if the channel is full or the write errors, the decision
is still returned to the hook and the failure is logged at Warn (fail-open
on logging, not on policy). The slog JSON line is retained as a
write-ahead debug trail during the transition; SQLite is the queryable
source of truth for `agentjail logs` and `agentjail replay`.

### Retention

On startup (and periodically), the store deletes decisions/audit_events
older than a configurable max age (default 30 days) and `VACUUM`s to reclaim
space. `sessions` rows whose last decision is older than the max age are
also removed.

### Migration

On first run, if `daemon.log` exists and the `decisions` table is empty,
the store imports the historical JSON-lines entries (best-effort: parse
each line, insert; log and skip unparseable lines; never block startup).
This preserves existing audit history across the upgrade.

### Read path (CLI)

`agentjail logs` and `agentjail replay` query SQLite instead of tailing
`daemon.log`. If the DB is absent (a pre-upgrade install that has not yet
run the daemon), `agentjail logs` falls back to the legacy `daemon.log`
tail so mixed-version installs keep working.

## Consequences

+ Per-session replay is an indexed lookup, not a full scan.
+ Structured retention (max-age + VACUUM) without whole-file rotation.
+ A query backend for the deferred UI (Phase 3).
+ WAL survives a kill mid-write; the DB is never left corrupt.
+ `agentjail logs` output is unchanged (same columns); only the source
  changes.
+ Pure-Go driver preserves the no-CGO, `curl | sh` distribution.
- Binary size grows by a few MB (the transpiled SQLite). Acceptable for a
  local tool.
- A new dependency (`modernc.org/sqlite` + its transitive set). Requires
  `make licenses` to regenerate `THIRD_PARTY_LICENSES` (CI fails the
  release if stale).
- The slog JSON line is retained for now (belt-and-suspenders during the
  transition); a future commit may remove it once SQLite is proven in the
  field.
- Fail-open on logging: a DB write failure does not block the decision. The
  decision is still enforced; only the audit record is lost. This is the
  right trade-off for a <5ms latency target (a synchronous DB write per
  decision would risk the budget).
