# Plan 023: Add privacy-bounded local notifications

> **Executor instructions:** Start after plans 020 and 021 are reviewed DONE.
> Read the accepted ADR, Apple notification sources in the design, and the
> coordination protocol. Own only Notifications files. Notification approval
> is forbidden; actions are Review and Deny.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact new Notifications/test paths and handoff. Committed
> transport/state drift is expected; uncommitted overlap stops the task.

## Status

- **Priority:** P1
- **Effort:** M
- **Risk:** MED
- **Depends on:** plans 020 and 021
- **Category:** app / privacy
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Notifications make approval requests timely, but their content may appear in
public and their callbacks may run while the app is backgrounded. The feature
must dedupe without creating authority, request permission only in context,
refetch before denial, and never approve a project-scoped change without the
panel's context.

## Current state

The repo has no UserNotifications code. Plan 020 provides an ID-only typed
client; plan 021 provides authoritative state. Apple requires categories and
actions to be registered at launch, the notification center delegate assigned
before launch completes, and every action handled. Apple also advises against
sensitive/confidential notification content and automatic first-launch
permission prompts.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Notification tests | `rtk swift test --package-path macos/AgentjailApproval --filter Notification` | pass |
| Full tests | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | pass |
| Privacy scan | `rtk rg -n 'Host|projectPath|reason|session|control.token|Approve|timeSensitive|critical' macos/AgentjailApproval/Sources/AgentjailApprovalApp/Notifications macos/AgentjailApproval/Sources/AgentjailApprovalCore/Notifications` | only deliberate guards/types; no payload interpolation or Approve action |

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/Notifications/**`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/Notifications/**`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/Notifications/**`
- `macos/AgentjailApproval/Tests/AgentjailApprovalAppTests/Notifications/**`
- `plans/macos-app/handoffs/023.md`

**Out of scope:** app entry/delegate wiring, Settings UI, state/transport edits,
Approve notification action, token persistence, host/path/reason content,
Time Sensitive/Critical alerts, push/APNs, Go, or Package.swift.

## Git workflow

One signed local commit: `feat(macos): add approval notifications`. Use the
shared commit lock; do not push.

## Steps

### Step 1: Define testable notification seams

Put scheduling/dedupe/action policy in core protocols and small Sendable types.
Wrap `UNUserNotificationCenter` in an app-layer adapter. Inject settings and
delivered/pending notification access so unit tests never invoke the real
permission dialog.

Register one category with unique **Review** and **Deny** actions. Review uses
`.foreground`; Deny uses `.destructive` and `.authenticationRequired`. No
Approve. The real delegate is assigned by plan 024 before launch completes.

The app-layer delegate implements `willPresent` and completes exactly once with
the accepted normal presentation options (`.banner`, `.list`, and `.sound`) so
foreground notifications are not silently suppressed. It also completes every
response callback exactly once.

**Verify:** mock tests prove category registration happens once, action options
match exactly, both IDs are unique/handled, and foreground/response completion
handlers each fire once on success and error paths.

### Step 2: Request permission only from an explicit method

Expose an `enableNotificationsFromUserAction()` method that requests normal
alert/sound authorization after explanatory Settings UI calls it. Initializing,
polling, or receiving the first review must never call authorization. Query
current settings before scheduling because the user may change them later.

**Verify:** construction/start/snapshot tests record zero permission calls;
explicit opt-in records one.

### Step 3: Schedule generic, deduplicated content

For each new stable review ID, schedule at most one local notification:

- title: “AgentJail approval requested”;
- body: “Review a project host request.”;
- category: the v1 review category;
- user info: stable review ID only.

The `UNNotificationRequest.identifier` is an app-owned fixed prefix plus a
CryptoKit SHA-256 digest of the review ID. Never interpolate raw IDs or any
agent-controlled string into that identifier. The raw ID is allowed only in
the minimal `userInfo` callback payload and bounded UX-only dedupe storage.

No host, project, path, agent reason, session, command, token, or challenge.
Maintain a bounded set of UX-only notified IDs (injected storage); it may live
in UserDefaults because IDs carry no authority. Prune it against authoritative
snapshots and remove delivered notifications for reviews no longer pending.

**Verify:** tests cover duplicate snapshots, restart with stored IDs, removal,
bounded pruning, permission denied, and no sensitive payload keys/values. IDs
containing controls/bidi/long input never appear raw in request identifiers or
logs, and the same ID maps to the same digest identifier.

### Step 4: Revalidate actions

- Review foregrounds/opens the matching row via an injected callback; it makes
  no control mutation.
- Deny first fetches a fresh snapshot, verifies the ID remains pending and
  `canDeny`, then sends exactly one deny. Stale/already-decided/unavailable is
  surfaced through app state and completes without retry.
- Unknown/default/dismiss actions perform no mutation.

Always complete the system callback, even on errors. Do not retry an ambiguous
deny automatically.

**Verify:** tests cover stale ID, daemon unavailable, duplicate callback,
unknown action, successful one-shot denial, and completion on every branch.

### Step 5: Verify and commit

Run tests/build/privacy scan, write the handoff, and commit under the lock.

## Done criteria

- [ ] Permission is contextual opt-in, never first-launch automatic.
- [ ] Categories/actions are registered and every callback completes.
- [ ] Foreground delivery selects normal presentation options exactly once.
- [ ] Deny is destructive/authentication-required; Review foregrounds.
- [ ] Content is generic and user info contains review ID only.
- [ ] Request identifiers contain only the app prefix and review-ID digest.
- [ ] Review is non-mutating; Deny refetches and is one-shot; Approve absent.
- [ ] Dedupe state is bounded/non-authoritative and stale notifications prune.
- [ ] Permission denial leaves core workflow unaffected.
- [ ] Tests/build pass in a signed local commit.

## STOP conditions

- Product requires Approve from the notification or sensitive context in it.
- Correct callback handling requires token/review details in notification payload.
- The notification delegate cannot be injected/wired before launch by plan 024.
- A third-party notification library is proposed.

## Maintenance notes

Apple can suppress/delay delivery; the menu badge/list remains the durable UX.
Future notification types require distinct categories and privacy review.
