# 007 — SQLite-backed UI replay viewer

## Goal

Make `agentjail ui` the on-demand local viewer for the SQLite event store added in Phase 1. It should show sessions, recent decisions, and per-session replay without introducing a persistent background service.

## Current State

- `agentjail ui` starts only when invoked and binds to loopback by default.
- The UI currently tails `daemon.log` into an in-memory ring buffer.
- Phase 1 moved decisions and session metadata into `~/.agentjail/agentjail.db`.
- `agentjail replay --session <id>` already reads chronological decisions from SQLite.

## Slice 1

- Add `agentjail ui --db PATH`, defaulting to `~/.agentjail/agentjail.db`.
- Keep `--log PATH` as a legacy fallback for mixed-version installs.
- Make `GET /api/state` read sessions and recent decisions from SQLite when available.
- Add `GET /api/session?id=<session_id>` for chronological replay decisions.
- Include redacted `tool_input` in session detail responses, but not in the default state snapshot.
- Update the static UI to fetch session details when a session is selected.

## Slice 2

- Add action/tool/rule filters; session filtering remains available from the sidebar.
- Show the active SQLite/log source and a warning when legacy fallback is active or SQLite trails the log.
- Add `internal/store.ListAuditEvents`, `GET /api/audit`, and an audit-event browser.
- Export versioned, redacted session bundles from `GET /api/session?id=...&download=1`.
- Make policy status read-only by default; `agentjail ui --edit-policy` opts into mutation controls.

## Later Slices

- Consider opening SQLite read-only for UI/query paths without running migrations.
- Add server-side filters if datasets grow beyond the current bounded local snapshots.

## Verification

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `make smoke`
- Manual: `agentjail ui --db ~/.agentjail/agentjail.db` and open `http://127.0.0.1:9101`.
