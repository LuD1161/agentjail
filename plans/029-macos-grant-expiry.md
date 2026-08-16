# Plan 029: Enforce atomic pending-grant expiry

> **Executor instructions:** Begin only after plans 016 and 017 are reviewed
> DONE. Read their diffs/handoffs, `docs/GOTCHAS.md`, the accepted menu-review
> ADR, and the coordination protocol. Make server time part of every registry
> authorization transition; do not rely on the minute reaper.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact registry, daemon call-site/test, GOTCHAS, and handoff paths.
> Committed prerequisite changes are expected; uncommitted overlap is a STOP.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** HIGH
- **Depends on:** plans 016 and 017
- **Category:** security / correctness
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

`PendingGrantTTL` claims to bound how long a human may decide, but today only a
periodic reaper checks `Expires`. `ListPending`, `FindGrant`, `ClaimGrant`, and
request coalescing can observe or approve an already-expired entry before the
next reap. A notification arriving in that interval makes the race realistic.
Expiry must be linearized under the registry lock at the snapshot and claim,
with the reaper retained only for cleanup.

## Current state

- `Registry.Reap(now)` removes expired unclaimed entries.
- `RequestGrant(..., now)` renews a duplicate ID even if that entry already
  expired but has not been reaped.
- `ClaimGrant(grantID)` takes no clock and can claim expired state.
- `grantServer.approve` performs a racy `FindGrant` followed by `ClaimGrant`.
- Plan 017's review projection already excludes `Expires <= now`; this task
  applies the same rule to every mutation path.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Registry | `rtk go test ./internal/grantctl -run 'Test.*(Expir|Claim|RequestGrant|Review)' -count=1` | pass |
| Daemon | `rtk go test ./internal/daemonapp -run 'Test.*(Grant|Expir)' -count=1` | pass |
| Race | `rtk go test ./internal/grantctl ./internal/daemonapp -race` | pass |
| Vet | `rtk go vet ./internal/grantctl ./internal/daemonapp` | exit 0 |
| Build | `rtk env CGO_ENABLED=0 go build ./cmd/agentjail ./cmd/agentjail-daemon` | pass |

## Scope

**In scope:**

- `internal/grantctl/registry.go`
- `internal/grantctl/registry_test.go`
- smallest expiry/call-site edits in `internal/daemonapp/grantserver.go`
- focused daemon tests in `internal/daemonapp/grantserver_test.go`
- one concise entry in `docs/GOTCHAS.md`
- `plans/macos-app/handoffs/029.md`

**Out of scope:** review JSON fields, framing, CWD resolution, audit durability,
policy persistence, Swift, UI, README, reaper interval, or a new dependency.

## Git workflow

One signed local commit: `fix(grants): enforce pending expiry`. Use the shared
lock, stage only exact owned files, and do not push.

## Steps

### Step 1: Make expiry a typed registry outcome

Add `ErrGrantExpired`. Centralize removal/index cleanup in a lock-held helper so
claim, deny, request coalescing, and reaping cannot drift. Define expiry as
`!now.Before(pg.Expires)` (`Expires <= now`).

Pass `now time.Time` explicitly into public registry operations whose result
depends on liveness, including claim/deny/list/find as needed. Do not hide
authorization time behind `time.Now()` in the registry; deterministic callers
and tests must choose it.

**Verify:** exact-boundary table tests distinguish one nanosecond before expiry
from equality/after and assert the typed expired result.

### Step 2: Linearize claim and cleanup

Within the same `Registry.mu` critical section, `ClaimGrant(grantID, now)` must:

1. find the record;
2. reject already claimed;
3. if expired, delete both indexes and return `ErrGrantExpired` without a
   snapshot or closures;
4. otherwise mark claimed and return the existing transaction snapshot.

An approval that claims before expiry may finish its already-linearized
transaction after the clock boundary. A rollback may briefly restore it, but
the next time-aware read/claim/request removes it and it can never be claimed
again. Document/test that exact rule.

**Verify:** concurrent claim at the boundary has one deterministic winner and
never returns an expired snapshot; race tests stay green.

### Step 3: Make reads, deny, and coalescing consistent

- List/review/find exclude expired entries at the caller-provided time.
- Deny at/after expiry removes the stale record and returns `ErrGrantExpired`
  (or the accepted typed equivalent), never success on live state that no
  longer exists.
- `RequestGrant(..., now)` removes an expired duplicate before cap counting and
  mints a fresh ID; it must not renew the old stable ID.
- Pending caps count only unexpired, unclaimed records at `now`.
- `Reap(now)` reuses the same predicate/removal helper and remains cleanup.

**Verify:** tests cover expired entries consuming no cap, duplicate-after-expiry
getting a new ID, snapshot/list omission before the reaper tick, deny expiry,
and index integrity after every branch.

### Step 4: Remove the daemon check/claim race

Update daemon call sites to pass one captured server time to each registry
operation. In `approve`, remove the preliminary `FindGrant`; the atomic timed
claim is the single liveness/existence decision. Preserve fail-closed durable
audit, binding check, rollback, persistence, and audit ordering exactly.

Return a bounded, non-sensitive expired refusal distinct from an empty queue.
Do not add a new state-change `slog` without the matching audit event required
by project rules.

**Verify:** daemon tests approve immediately before expiry, refuse at equality,
and prove no policy overlay/audit-request event occurs for the refused claim.

### Step 5: Record the green-suite blind spot and commit

Add a concise GOTCHAS entry: periodic cleanup made the queue look TTL-bounded,
but authorization methods never checked the deadline; cleanup is not an
authorization predicate, and time must be checked under the same lock as claim.
Run all gates, write the handoff, and commit under the shared lock.

## Done criteria

- [ ] `Expires <= now` is one shared typed predicate across registry paths.
- [ ] Snapshot/list/claim/deny cannot act on expired state before the reaper.
- [ ] Duplicate requests after expiry receive a fresh ID and caps ignore stale entries.
- [ ] Claim time and claimed-state transition are atomic under one lock.
- [ ] Refused expiry writes no overlay and emits no policy-change-request audit.
- [ ] Focused/race/vet/build gates pass and GOTCHAS records the hidden gap.
- [ ] Signed local commit contains only owned paths.

## STOP conditions

- Correct expiry requires weakening claim/audit atomicity or using app/local time
  as authority.
- A prerequisite changed the registry transaction contract incompatibly.
- A new persistent queue, database, or dependency is proposed.
- Tests need wall-clock sleeps instead of injected fixed times.

## Maintenance notes

The periodic reaper controls memory retention, not permission. Future pending
authorization types must accept an explicit decision time at the same atomic
transition that consumes them.

