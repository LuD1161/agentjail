# 0100 - Network session active by owner PID

Status: Accepted

## Context

The Network UI sidebar marked a session "active" with a 120-second
network-recency heuristic (`now - last_seen < 120s` in `network.tsx`). An agent
that is still running but network-idle for over two minutes wrongly showed
inactive, contradicting the CLI (`agentjail sessions list --active`), which is
authoritative: it marks a session active by live PID from
`~/.agentjail/active-sessions.json`.

The obvious fix — join the network session onto the daemon session and reuse its
liveness — does not work: the two are different identities. The tunnel mints its
own id via `mitm.NewSessionID()` (`tunnel_shield_linux.go`), unrelated to the
daemon session id, so there is no key to join on.

## Decision

Record the owning shield process PID on every network request row and decide
"active" by that PID's liveness, independent of the id-space mismatch.

- `internal/mitm`: `RequestLog` gains `OwnerPID int`, persisted in a new
  `owner_pid INTEGER` column (hand-rolled store, idempotent `ALTER TABLE`;
  declared INTEGER so PIDs round-trip as numbers, not text). The `MITMHandler`
  gains an `OwnerPID` field, stamped onto every row like `SessionID`. The tunnel
  sets `h.OwnerPID = os.Getpid()` at session setup, so all rows of one session
  share one PID.
- The liveness check is centralized in `procutil.Alive(pid)` (signal 0), and the
  CLI's `isProcessAlive` now delegates to it so the two paths cannot drift.
- The UI aggregates rows per session (`aggregateSessions`) and sets
  `SessionInfo.Active = procutil.Alive(ownerPID)` server-side. `network.tsx`
  reads the payload's `active` flag; the 120s window is deleted.

## Consequences

- A session whose owning shield PID is alive is active even when `last_seen` is
  older than two minutes; a dead PID is inactive. The UI now agrees with the CLI.
- The tunnel is Linux-only, so `OwnerPID` is only populated on Linux. macOS has
  no tunnel session, so its network sessions carry PID 0 and read inactive —
  acceptable, since there is nothing to report active there.
- One source of truth for liveness (`procutil.Alive`), shared by the CLI and UI.
- Existing `network.db` files gain the column via the idempotent migration;
  rows written before this change have `owner_pid = 0` and read inactive.
