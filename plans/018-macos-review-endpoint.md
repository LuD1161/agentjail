# Plan 018: Serve authenticated menu-review snapshots

> **Executor instructions:** Begin only after plans 029 and 030 are reviewed
> DONE. Read their diffs, the accepted ADR, `AGENTS.md`, and ADR 0069. Add one
> read-only control verb behind the existing authenticate-before-dispatch gate.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the review-handler paths, serialized dispatch file, and handoff. Committed
> prerequisite drift is expected; any uncommitted overlap is not.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** MED
- **Depends on:** plans 029 and 030
- **Category:** security / backend
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Swift needs a coherent snapshot of current pending reviews, not audit history.
Serving it from the daemon preserves in-memory authority, token authentication,
verified project binding, and the singleton-store rule. Keeping the operation
read-only and off the hook path avoids latency or availability changes to
normal policy evaluation.

## Current state

`internal/daemonapp/grantserver.go:230-254` extracts peer UID, decodes a bounded
request, and validates `CtlToken` before the switch. `grant_list` is answered
from `registry.ListPending()` at lines 256-258. That pre-dispatch token check is
load-bearing and must remain above every case. Approve/deny and audit behavior
at lines 260-287 must remain unchanged.

Plan 017 adds the v1 `review_snapshot` request and typed registry projection.
Plan 016 makes `can_approve` meaningful on Darwin by verifying CWD or leaving
the request unbound. Plan 029 makes expiry atomic; plan 030 supplies the strict
bounded request/response frame used by every control verb.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Focused | `rtk go test ./internal/daemonapp ./internal/grantctl -run 'Test.*Review|Test.*Grant' -count=1` | pass |
| Race | `rtk go test ./internal/daemonapp ./internal/grantctl -race` | pass |
| Vet | `rtk go vet ./internal/daemonapp ./internal/grantctl` | exit 0 |
| Build | `rtk env CGO_ENABLED=0 go build ./cmd/agentjail ./cmd/agentjail-daemon` | exit 0 |

## Scope

**In scope:**

- `internal/daemonapp/grantserver_review.go` (new)
- `internal/daemonapp/grantserver_review_test.go` (new)
- the smallest dispatch-only edit in `internal/daemonapp/grantserver.go`
- only if structurally unavoidable, narrowly related tests in
  `internal/daemonapp/grantserver_test.go`
- `plans/macos-app/handoffs/018.md`

**Out of scope:** grant approval semantics, hook path, store/SQLite, Swift,
notifications, streaming, installer, README, or control-token format.

## Git workflow

One signed local commit: `feat(daemon): serve menu review snapshots`. Use the
shared commit lock; do not push.

## Steps

### Step 1: Add a narrow review handler

Implement a method that accepts only protocol v1, captures server `now` once,
calls the registry's typed projection with it, and returns that same
generated-at timestamp/version/count/truncation.
Keep projection/sorting in `grantctl`; the daemon should not rebuild domain
objects from untyped maps.

**Verify:** unit test exact response fields for bound and unbound reviews.

### Step 2: Wire it after authentication

Add exactly one switch case for `ReqReviewSnapshot` below the existing token
validation. No unauthenticated negotiation endpoint is needed. Unsupported or
missing client versions return `ok=false` with a bounded, non-sensitive error.

Do not log the token, review reason, host list, or project paths. This read-only
operation is not an audit event or user-visible state change.

**Verify:** an invalid/missing token receives unauthorized and the registry
projection spy/counter proves it was never called.

### Step 3: Exercise transport and races

Using a real temporary Unix socket and the existing server test pattern, cover:

- valid v1 snapshot;
- missing, invalid, and future protocol versions;
- malformed and oversize request;
- non-whitespace trailing data in one frame and a second frame that is never
  dispatched (reuse plan 030's regression rather than adding a new decoder);
- no pending requests versus daemon unavailable (client distinguishes them);
- deterministic capped snapshot with truncation metadata;
- concurrent snapshot while another caller approves/denies (race detector);
- unbound Darwin-shaped request is returned `can_approve=false`;
- old `grant_list`, approve, deny, and reload calls still work.

**Verify:** focused and race suites pass.

### Step 4: Verify no hook-hot-path change

Confirm the only production dispatch edit is in `handleCtlConn`, never
agent-facing `handleConn` or policy evaluation. Use `git diff` and cite the
exact location in the handoff.

**Verify:** `rtk git diff -- internal/daemonapp/grantserver.go` shows only the
new authenticated control case.

### Step 5: Build and commit

Run tests, race, vet, CGO-disabled builds, write the handoff, and commit under
the shared lock.

## Done criteria

- [ ] v1 snapshot is served only after UID and token checks.
- [ ] Unsupported/missing versions fail distinctly from an empty queue.
- [ ] Response is typed, bounded, deterministic, and uses verified project path.
- [ ] No sensitive fields are logged or audited.
- [ ] Hook/evaluation hot path is untouched.
- [ ] Existing control verbs still pass tests.
- [ ] Tests/race/vet/build pass in a signed local commit.

## STOP conditions

- Authentication would need to move below dispatch.
- Snapshot requires a second database connection or audit-log parsing.
- Plan 016 did not establish fail-closed verified project binding.
- The contract cannot be served within the existing message/deadline bounds.

## Maintenance notes

Polling clients can reconnect and obtain a full snapshot; do not add server
subscriptions until measured need justifies lifecycle/backpressure complexity.
Any future mutation verb needs its own audit/durability analysis.
