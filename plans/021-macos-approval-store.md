# Plan 021: Build the approval state store

> **Executor instructions:** Normal acceptance requires plan 020 reviewed DONE.
> Parallel implementation may begin after its public `ReviewControlling` and
> model API has landed and the orchestrator confirms that API is stable; plan
> 021 cannot be reviewed DONE until plan 020's cancellation-safe transport is
> accepted. Read its public types/tests and the product design. Own only
> `State/`; do not edit transport, UI, app entry, or notifications.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact new State/test paths and handoff. Committed Models/Transport
> drift is required; uncommitted State work stops the task.

## Status

- **Priority:** P0
- **Effort:** M
- **Risk:** MED
- **Depends on:** plan 020
- **Category:** app / correctness
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Polling, reconnection, deduplication, and one-shot decisions are easy to get
wrong when embedded directly in SwiftUI. A deterministic state store makes
cached data non-authoritative, prevents double approval, and allows UI and
notifications to share one source of truth without racing each other.

## Current state

Plan 020 provides `ReviewControlling` and typed snapshots/errors. The product
design requires normal two-second polling, capped reconnect backoff, immediate
refresh on activation/action, stable-ID dedupe, and disabled actions whenever
the daemon is disconnected. macOS 13 rules out relying on newer Observation
framework APIs; use `ObservableObject`/Combine at the UI boundary and Swift
actors/tasks for work.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| State tests | `rtk swift test --package-path macos/AgentjailApproval --filter ApprovalStore` | pass without wall-clock sleeps |
| Full tests | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | pass, no concurrency warnings promoted to errors |

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/State/**`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/State/**`
- `plans/macos-app/handoffs/021.md`

**Out of scope:** models/transport changes, SwiftUI views, notifications,
UserDefaults, app lifecycle/login, Go, Package.swift, or real daemon behavior.

## Git workflow

One signed local commit: `feat(macos): add approval state store`. Follow the
shared commit lock; do not push.

## Steps

### Step 1: Model legal UI states

Create named states that make illegal combinations hard to represent:

- starting;
- connecting;
- ready with a snapshot (empty or pending);
- disconnected with last successful rows marked stale/non-actionable;
- unsupported protocol/version;
- action failure attached to a specific review.

Track per-review action state (`idle`, `approving`, `denying`, `failed`) so a
row cannot perform two simultaneous decisions. Avoid Boolean soups.

**Verify:** table tests cover every state/action transition and reject approve
when disconnected, stale, unsupported, unbound/unrepresentable, locally
expired, or already deciding.

### Step 2: Implement deterministic polling

Inject the client, clock/sleeper, and scheduler. Normal ready polling is every
two seconds. On transport/unavailable errors, back off 2, 4, 8, 16, then 30
seconds maximum. Unauthorized and protocol mismatch are stable states and must
not hot-loop. Manual retry and app activation trigger an immediate fetch.

Cancellation must stop the poll task and release the store; starting twice must
not create two loops. No wall-clock sleeps in tests.

**Verify:** fake-clock tests assert exact call schedule, cap, reset after
success, cancellation, and one loop only.

### Step 3: Apply snapshots safely

Dedupe by review ID, preserve server order, remove reviews absent from a fresh
authoritative snapshot, and expose pending count. A failed refresh keeps the
last rows only as stale display context and disables actions. An empty valid
snapshot is ready/empty, never disconnected.

Use the injected clock to disable a row at `expires_at <= now` even before the
next poll. This is UX defense-in-depth only; plan 029's daemon claim remains the
authority and rejects expiry using server time.

**Verify:** tests cover duplicate IDs, reorder, removal, truncation metadata,
empty success, and failure after success.

### Step 4: Implement one-shot decisions

On explicit approve/deny:

1. validate current row/actionability;
2. mark that row in-flight immediately on the main actor;
3. send one mutation through the client;
4. fetch a fresh snapshot on an unambiguous success;
5. on refusal/race, show bounded failure and refresh;
6. on ambiguous transport failure, do not retry mutation; refresh when safe.

Approve must require `canApprove`; deny requires `canDeny`. No method accepts
host/project/reason as authority—review ID only.

**Verify:** concurrent calls for the same ID produce one client mutation;
different IDs can progress independently; lost reply never retries.

### Step 5: Add foreground hooks as methods, not AppKit code

Expose `start`, `stop`, `refreshNow`, `applicationDidBecomeActive`, `approve`,
and `deny` entry points. Do not import AppKit or SwiftUI in the core state code;
plan 024 wires lifecycle notifications.

### Step 6: Verify and commit

Run state/full tests and build, write the handoff, and commit owned files under
the lock.

## Done criteria

- [ ] State enum prevents actionable stale/disconnected rows.
- [ ] Polling/backoff/cancellation are deterministic and fake-clock tested.
- [ ] Snapshots dedupe/sort/remove correctly.
- [ ] Same-review decisions are one-shot; mutations are never auto-retried.
- [ ] Unrepresentable and locally expired rows cannot approve.
- [ ] Empty, unavailable, unauthorized, and version mismatch are distinct.
- [ ] Core state imports no AppKit/SwiftUI/UserDefaults.
- [ ] Tests/build pass in a signed local commit.

## STOP conditions

- Plan 020 lacks an error distinction needed to prevent an unsafe retry.
- Correct tests require real sleeps or the production singleton.
- State implementation requires editing Package.swift or transport files.
- Product semantics changed to current-session or command approval.

## Maintenance notes

The store is the single source for panel and notification action state. Future
review kinds must add explicit legal transitions rather than defaulting to the
project-host path.
