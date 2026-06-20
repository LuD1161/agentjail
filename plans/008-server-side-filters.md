# 008 — Server-side filters for UI state/session endpoints

## Problem

`/api/state` currently loads up to 5000 decisions from SQLite and sends them to the browser, where the JS client filters by action/tool/rule locally. For datasets beyond a few thousand rows this is wasteful: the server sends data the client discards, and the browser blocks on re-rendering large arrays.

## Goal

Push filtering to the SQLite query layer so the server sends only matching rows. Keep the client-side filter UI unchanged — the dropdowns and text input become HTTP query params.

## Endpoints

### GET /api/state

Existing: returns sessions + recent events + counters + source status.

Change: add optional query params that filter the `recent_events` array:
- `?action=deny` — filter by action (comma-separated: `?action=deny,ask`)
- `?tool=Bash` — filter by exact tool name
- `?rule=aws` — filter by rule_id substring (LIKE '%aws%')
- `?limit=500` — cap rows (default 5000, max 10000)

Counters (`total_allow`/`deny`/`ask`) remain global — they reflect all sessions, not the filtered view. Sessions remain unfiltered.

Implementation: pass the filter params through to `store.Filter` in `sqliteSnapshot()`.

### GET /api/session?id=<session_id>

Existing: returns all decisions for one session (up to 5000).

Change: add the same filter params:
- `?action=deny&tool=Bash&rule=aws`

Implementation: pass params to `store.Filter` in `handleSession()`.

### GET /api/audit

Existing: returns last 500 audit events, newest first.

No change needed — audit volume is low.

## Store Layer

`store.Filter` already supports `Actions`, `Tool`, `SessionID`, `Limit`. The missing piece is:

- `Rule` substring filter — add a `Rule string` field to `Filter`, implemented as `WHERE rule_id LIKE ?` in `ListDecisions`.

## Frontend Changes

Minimal:
1. `loadState()` sends current filter values as query params instead of filtering locally.
2. `selectSession()` sends filter values to `/api/session?id=...&action=...&tool=...&rule=...`.
3. `filtersChanged()` triggers a debounced re-fetch from the server instead of local re-render.
4. Keep the existing client-side filter as a fast-path for the in-memory ring buffer when no server params are set (SSE live events).

## Pagination (deferred)

If the filtered result set exceeds `limit`, return a `has_more: true` flag and a `next_after_id` cursor. The frontend can fetch the next page with `?after_id=<cursor>`. This is not needed for the initial slice — the current 5000-row cap is sufficient for most local sessions.

## Verification

- Unit test: `store.Filter{Rule: "aws"}` returns only AWS-rule decisions.
- Integration test: `/api/state?action=deny` returns only deny rows.
- Chrome CDP test: filter dropdown sends server params and the timeline updates.
