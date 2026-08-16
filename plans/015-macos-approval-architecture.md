# Plan 015: Record the macOS menu-review architecture

> **Executor instructions:** Read this plan completely, then read `AGENTS.md`,
> `plans/macos-app/DESIGN.md`, and `plans/macos-app/COORDINATION.md`. Run every
> verification gate. Work only in the listed scope. The orchestrator maintains
> the central board; write your result to the unique handoff file. Do not push.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the orchestrator-reserved ADR path and handoff. If another macOS
> menu-review ADR or a conflicting number exists, stop before writing.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** LOW
- **Depends on:** none
- **Category:** direction / architecture
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

The new app crosses a security boundary: an unsandboxed GUI will hold the same
control-plane authority as the human CLI. The product scope, token handling,
project binding, Codex separation, app sandbox posture, and notification
semantics must be decided before parallel implementation begins. One accepted
ADR gives every executor a single source of truth and prevents the UI from
silently promising authority the daemon does not have.

## Current state

- `docs/adr/0047-daemon-grant-server.md` identifies a macOS menu-bar
  Approve/Deny UI as a follow-up and keeps the daemon as grant authority.
- `docs/adr/0067-control-plane-token-auth.md` and
  `docs/adr/0069-daemon-control-token.md` establish `control.token`, not socket
  path or same UID, as the control-plane boundary.
- `docs/adr/0118-codex-approval-broker.md` and
  `docs/adr/0119-command-approval-transport.md` bind Codex approval to its
  native prompt and one-use process-attested challenge.
- `docs/adr/0132-cli-command-surface.md` says project-host approval persists for
  future sessions and does not widen the current sandbox.
- `internal/daemonapp/peerpid_darwin.go:64-70` currently cannot verify CWD;
  `internal/daemonapp/grantserver.go:427-437` falls back to self-reported CWD.
- `macos/AgentjailTunnel/` is a Network Extension host with unrelated
  entitlements and must remain separate.

Relevant platform sources were checked on 2026-08-15 and are linked in
`plans/macos-app/DESIGN.md`. The executor must verify the same official Apple
pages and record the local macOS, Swift, and SDK/toolchain versions in the ADR.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Local version | `rtk sw_vers` | macOS version printed |
| Swift version | `rtk swift --version` | Apple Swift version printed; record any local cache warning |
| ADR inventory | `rtk rg --files docs/adr` | current filenames available for orchestrator reservation |
| ADR validation | `rtk make adr-check` | exit 0, no duplicate number/slug error |
| Scope | `rtk git diff --name-only` | only the new ADR and handoff from this task, plus pre-existing user paths |

## Scope

**In scope:**

- One new `docs/adr/NNNN-macos-menu-review.md` using the next free number on
  local `main` at execution time.
- `plans/macos-app/handoffs/015.md`.

**Out of scope:**

- All Go, Swift, plist, build, installer, and release files.
- Existing ADR edits.
- `README.md` and every pre-existing dirty path.
- Any GitHub/remote action.

## Git workflow

- Stay in the common `main` worktree.
- Follow the claim and commit-lock protocol in
  `plans/macos-app/COORDINATION.md`.
- One signed local commit: `docs(macos): decide menu review architecture`.

## Steps

### Step 1: Allocate and source the ADR

Ask the orchestrator to reserve the next free number from local `main` in the
claim acknowledgement. Recheck it while holding the commit lock immediately
before staging. Use a slug of at most three words: `macos-menu-review`. Record
Status `Accepted`, date `2026-08-15`, installed toolchain versions, official
Apple URLs, and the verification date. Do not cite remembered platform behavior.

**Verify:** `rtk make adr-check` exits 0.

### Step 2: Record the complete decision

The ADR must decide all of the following, without leaving them as executor
choices:

- separate `AgentjailApproval.app` under `macos/AgentjailApproval/`;
- exact SwiftPM product/binary `AgentjailApproval`, display name
  `AgentJail Approval`, and bundle ID `com.blinkerlm.agentjail.approval`;
- macOS 13+, SwiftUI `MenuBarExtra(.window)`, `LSUIElement`, Settings scene;
- direct-distribution, hardened-runtime, notarized public build;
- no App Sandbox in v1, with a future sandbox/XPC redesign requiring an ADR;
- existing `daemon-ctl.sock` + `control.token` as the only authority seam;
- token loaded per request and never persisted/logged;
- no direct SQLite, audit-log parsing, or policy writes in Swift;
- v1 actionable scope is project-host grants only;
- exact future-session semantics and forbidden “allow once/now” copy;
- macOS CWD verification/fail-closed behavior is a release prerequisite;
- server-time expiry is checked atomically by snapshot and claim; the periodic
  reaper is cleanup only;
- Codex command asks remain on the native one-use broker path and have no app
  Approve action;
- one newline-terminated JSON value per connection, including a strict 64-KiB
  frame limit and rejection of malformed/trailing-in-frame data;
- bounded review projection: at most three newest rows, authority fields full
  or typed-unrepresentable and deny-only, never truncated-and-actionable;
- two-second bounded polling rather than a new streaming dependency for MVP;
- notification permission is contextual opt-in; generic content; Review/Deny
  actions; no notification Approve; explicit foreground presentation;
- notification Deny is destructive/authentication-required and notification
  request identifiers contain no raw review ID;
- no Network Extension/system-extension entitlements and no tunnel-app merge;
- local packaging is ad-hoc signed with hardened runtime and an exact empty
  entitlement dictionary; Developer ID/notarization remain later, explicit work;
- all work and commits stay local until separately authorized.

Keep rationale in the ADR; future code comments should cite its full slug.

**Verify:** each decision phrase is findable with `rtk rg -n` in the new ADR,
and the ADR contains Context / Decision / Consequences.

### Step 3: Write the handoff and commit

Record exact sources, versions, ADR filename, verification results, and no
remote action in `plans/macos-app/handoffs/015.md`. Commit only the two owned
files using the shared commit lock.

**Verify:** `rtk git show --stat --oneline --show-signature HEAD` shows the two
owned paths and a `Signed-off-by:` trailer.

## Test plan

- `rtk make adr-check` guards numbering/slug rules.
- Structural reads confirm the required decision list is present.
- No product tests are appropriate because this task changes docs only.

## Done criteria

- [ ] Accepted ADR exists at the next free number with a three-word-or-shorter slug.
- [ ] All architecture/security/product decisions above are explicit.
- [ ] Apple source URLs, local versions, and verification date are recorded.
- [ ] `rtk make adr-check` passes.
- [ ] Only the ADR and `handoffs/015.md` are committed.
- [ ] Commit is conventional, signed, local-only.

## STOP conditions

- The next number is contested or an equivalent ADR already exists.
- Official current Apple docs contradict macOS 13, MenuBarExtra, SMAppService,
  or the chosen filesystem posture.
- The operator requires Mac App Store/App Sandbox distribution for v1.
- Any decision would require editing an existing ADR rather than superseding it.

## Maintenance notes

Reviewers should reject implementation that claims current-session access,
adds a second Codex approval path, copies the token, or combines the app with
the tunnel bundle. A future live grant, sandboxed app, or general policy
approval feature needs its own ADR.
