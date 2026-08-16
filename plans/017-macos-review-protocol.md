# Plan 017: Add the versioned menu-review wire contract

> **Executor instructions:** Read plan 015's ADR, `AGENTS.md`, ADRs 0035, 0067,
> 0069, and 0132, plus the coordination protocol. Implement only typed contract
> and registry projection code. Do not add a daemon dispatch case or Swift.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact `internal/grantctl` contract/registry/client paths and handoff.
> Any uncommitted contract work is a STOP condition.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** MED
- **Depends on:** plan 015
- **Category:** architecture / security
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

The existing `grant_list` shape is CLI-oriented, unversioned, map-ordered, and
contains the self-reported CWD rather than the authoritative bound project. A
native client needs an additive, versioned, display-safe projection that says
what action is possible and what effect approval has. Defining it in Go keeps
the daemon as source of truth and gives Swift a golden compatibility fixture.

## Current state

At `internal/grantctl/grantctl.go:39-70`, control verbs are named
`grant_request`, `grant_list`, `grant_approve`, and `grant_deny`. The response
at lines 100-106 carries only `Grants []GrantInfo`. `GrantInfo` at lines
108-123 exposes `CWD`, while the authoritative `BoundCWD` exists only on
`ClaimedGrant`. `Registry.ListPending()` iterates a Go map, so order is
unspecified. `MaxControlMsgBytes` is 64 KiB and must bound the new response.

Existing client style is `internal/grantctl/client.go:71-108`: one typed
function per operation, bounded Unix-socket round trip, `ok=false` surfaced as
an error.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Unit tests | `rtk go test ./internal/grantctl -race` | pass |
| Vet | `rtk go vet ./internal/grantctl` | exit 0 |
| Contract fixture | `rtk go test ./internal/grantctl -run TestReviewSnapshotGolden -count=1` | pass |
| Token scan | `rtk rg -n 'token|challenge|command|tool_input' internal/grantctl/testdata/review_snapshot_v1.json` | no matches |

## Scope

**In scope:**

- `internal/grantctl/grantctl.go`
- `internal/grantctl/client.go`
- `internal/grantctl/registry.go`
- matching `internal/grantctl/*_test.go`
- `internal/grantctl/testdata/review_snapshot_v1.json` (new)
- `plans/macos-app/handoffs/017.md`

**Out of scope:** daemon dispatch, approval behavior, ctlauth, audit, Swift,
SQLite/store, installer, docs outside the handoff, or a streaming protocol.

## Git workflow

One signed local commit: `feat(grants): define menu review protocol`. Follow
the shared lock and never stage the whole directory blindly.

## Steps

### Step 1: Define named v1 types

Add an additive `review_snapshot` request with explicit client protocol
version. Use named types/enums, not bare policy strings:

- `ReviewProtocolVersion = 1`;
- `ReviewKindProjectHost`;
- `ReviewScopeFutureProjectSessions`;
- `ReviewContextState` values `verified`, `unbound`, and `unrepresentable`;
- `ReviewInfo` with stable JSON fields: review ID, kind, complete host, complete
  verified project path, bounded agent-provided reason plus
  `reason_truncated`, context state, created/expiry Unix milliseconds,
  approval scope, `can_approve`, and `can_deny`;
- response metadata: protocol version, generated-at Unix milliseconds,
  total pending count, truncation flag, and reviews;
- byte bounds `MaxReviewHostBytes = 255`, `MaxReviewProjectPathBytes = 2048`,
  and `MaxReviewReasonBytes = 256`;
- `MaxReviewSnapshotItems = 3`, chosen so even six-byte JSON escaping of every
  bounded byte plus envelope overhead remains below `MaxControlMsgBytes`.

Extend the existing envelope additively so old grant clients keep decoding.
The request must send its version; version zero is not silently treated as v1.

Do not include `CtlToken` in any response type. Do not include raw command,
Codex challenge, tool input, policy contents, or an executable action string.

**Verify:** compile-time enum tests reject/avoid unknown zero values where
possible, and reflection guards ensure response/review types have no token- or
challenge-shaped field/tag.

### Step 2: Project authoritative registry state

Add a registry method that accepts an injected `now` and returns `ReviewInfo`
from pending records:

- `project_path` comes from `BoundCWD`, never `CWD`;
- an authority-bearing host/path is present in full or absent; never truncate
  one while leaving the review actionable;
- empty binding yields `unbound`; a host/path over its projection limit yields
  `unrepresentable`; both have `can_approve=false` and `can_deny=true`;
- only verified context with complete authority fields can approve;
- reason may be truncated at a valid UTF-8 boundary and must set
  `reason_truncated=true`; it carries no authority;
- `can_deny` is true for every pending, unclaimed record;
- approval scope is always `future_project_sessions` for v1;
- timestamps come from the registry's existing `Created`/`Expires` fields;
- sort newest-first by creation time, then review ID for deterministic ties;
- exclude `Expires <= now` from both rows and total; plan 029 makes the same
  server-time rule atomic at claim;
- return total before truncating to the newest three.

Do not expose claimed records. Preserve `ListPending()` behavior for the CLI.

**Verify:** tests cover bound, unbound, overlong host/path, truncated reason,
claimed, expired-before-reap, more than three, deterministic ties, and no
self-reported CWD leakage.

### Step 3: Add the typed Go client function

Add `ReviewSnapshot(sockPath, ctlToken, timeout)` following `GrantList`. It
sends the v1 request, rejects `ok=false`, rejects a response version other than
1, and returns the typed snapshot. Plan 030 owns strict shared framing; do not
duplicate transport framing in this contract task.

**Verify:** client tests cover missing/bad response version, refusal, malformed
JSON, and a valid snapshot. Oversize/trailing shared-frame regression belongs
to plan 030.

### Step 4: Lock the JSON contract

Create a deterministic golden fixture with three project-host reviews (one
verified/actionable, one unbound deny-only, one unrepresentable deny-only).
Test exact JSON field names and v1 decode/encode. Construct it from fake values.

Add a worst-case encoding test with three maximally escaped, max-length
hosts/paths/reasons and assert the complete newline-terminated response is
strictly smaller than 64 KiB. Also prove an over-limit authority field is
omitted and deny-only, never truncated-and-actionable. Never raise the control
message limit for UI convenience.

**Verify:** fixture test passes and token/challenge/raw-command scan is empty.

### Step 5: Verify and commit

Run race and vet, write the handoff, acquire the lock, stage only owned files,
and commit.

## Done criteria

- [ ] v1 request and response are additive, typed, and explicitly versioned.
- [ ] Only verified `BoundCWD` reaches `project_path`.
- [ ] Unbound/unrepresentable reviews cannot be approved but can be denied.
- [ ] Expired-before-reap reviews are absent from a snapshot generated at `now`.
- [ ] Snapshot is deterministic, capped, and below 64 KiB worst-case.
- [ ] Golden fixture contains no token/challenge/command/tool input.
- [ ] Existing grant clients/tests still pass.
- [ ] Race and vet pass; signed local commit is scoped.

## STOP conditions

- A safe projection requires exposing self-reported CWD as authoritative.
- The response cannot stay within 64 KiB at a useful bounded count.
- Existing clients would require a breaking wire change.
- A new dependency, database query, or streaming transport seems necessary.

## Maintenance notes

The Go golden fixture is the source for plan 020's Swift decoder and plan 026's
cross-language gate. New review kinds must define truthful effects and
actionability in Go before the app renders them.
