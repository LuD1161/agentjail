# Plan 024: Compose the production menu-bar app

> **Executor instructions:** Begin only after plans 016, 018, 022, and 023 are
> reviewed DONE. Read every handoff and rerun their focused tests first. This is
> the sole task allowed to replace the placeholder app entry and wire real
> services, Settings, notifications, and login behavior.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the app entry, placeholder deletion, new Composition/Settings/Lifecycle
> paths, tests, and handoff. Committed prerequisites are expected; any
> uncommitted overlap is a STOP condition.

## Status

- **Priority:** P0
- **Effort:** M
- **Risk:** MED
- **Depends on:** plans 016, 018, 022, and 023
- **Category:** app / integration
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Independent components are not a product until lifecycle and authority are
wired correctly. Composition must assign the notification delegate early,
start exactly one polling loop, make application activation refresh state,
gate approval on server actionability, expose explicit notification/login
settings, and keep failures visible without inventing fallback authority.

## Current state

- Plan 019's `AgentjailApprovalApp.swift` is a placeholder and this task owns
  its only production edit.
- Plans 020/021 provide real client and store.
- Plan 022 provides panel/menu-label views with callbacks.
- Plan 023 provides notification adapter/coordinator but deliberately does not
  assign the system delegate.
- Plan 016 is the release gate: Darwin project binding is verified or approval
  fails closed.
- Plan 018 serves authenticated v1 snapshots.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Swift tests | `rtk swift test --package-path macos/AgentjailApproval` | all pass |
| Swift build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | pass |
| Go backend | `rtk go test ./internal/grantctl ./internal/daemonapp -race` | pass |
| Forbidden APIs | `rtk rg -n 'NetworkExtension|SystemExtensions|SQLite|agentjail.db|Process\(|/bin/|shell' macos/AgentjailApproval/Sources` | no production authority shortcut |
| Copy guard | `rtk rg -n 'Allow once|Allow now|current-session access|temporary grant' macos/AgentjailApproval/Sources` | no misleading copy |

## Scope

**In scope:**

- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/AgentjailApprovalApp.swift`
- delete/replace plan 019's `PlaceholderView.swift`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/Composition/**`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/Settings/**`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/Lifecycle/**`
- behavior/lifecycle update to `macos/AgentjailApproval/README.md`
- composition/lifecycle tests under
  `macos/AgentjailApproval/Tests/AgentjailApprovalAppTests/Composition/**`
- `plans/macos-app/handoffs/024.md`

**Out of scope:** Package.swift, root README, core models/transport/state logic, UI card
redesign, notification policy, Info.plist, entitlements/build scripts, Go,
installer, README, tunnel, dashboard spawning, or release workflow.

## Git workflow

One signed local commit: `feat(macos): compose approval companion`. Follow the
shared lock. No push.

## Steps

### Step 1: Build one dependency container

Instantiate one production token loader/socket client, one state store, one
notification adapter/coordinator, and one login service adapter. Own them for
the app lifetime. Do not create a client per view or multiple poll loops.

Use constructor injection/protocols for tests. Do not implement a global
service locator or dependency framework.

**Verify:** a composition test/spies prove one store start and one category
registration across scene refreshes.

### Step 2: Assign notification delegate before launch completes

Use `@NSApplicationDelegateAdaptor` (or the accepted ADR's equivalent) to
assign `UNUserNotificationCenter.current().delegate` and register categories
before application launch completes. Route callbacks to plan 023's handler and
always complete them. Route `willPresent` through plan 023's explicit
banner/list/sound policy. Foreground Review selects/focuses the matching row.

Do not request notification authorization here.

**Verify:** lifecycle test/order spy records delegate/category setup before
store polling, a foreground notification receives the exact accepted options
once, and source has no first-launch authorization call.

### Step 3: Replace the placeholder scene

Wire `MenuBarExtra` label to connection/pending state and the `.window` content
to `ApprovalPanelView`. Start polling once, stop/cancel on termination, refresh
on app activation and menu opening, and route explicit row buttons to store
ID-only methods.

Approve must remain disabled unless the latest server snapshot says
`can_approve=true`; composition must not override it based on local OS/version.

**Verify:** fake composition scenarios cover empty, pending, disconnected,
unsupported, approve refusal, deny race, and daemon recovery.

### Step 4: Add explicit Settings

Create a Settings scene with:

- daemon/control connection status and Retry;
- notification status, explanation, explicit Enable button, and link to system
  settings after denial where supported;
- “Launch AgentJail Approval at login” toggle backed by
  `SMAppService.mainApp`;
- precise future-session explanation and local-only/privacy statement.

Do not auto-register the login item. Surface `.requiresApproval`, enabled,
not-found, and error statuses truthfully.

**Verify:** fresh/default settings issue zero notification and login
registration calls; explicit user toggles issue exactly one matching call.

### Step 5: Handle foreground/background and errors

On activation, refresh. When the daemon/token is unavailable, retain rows only
as stale disabled context. App/notification callback errors show bounded UI
feedback; do not log token/request JSON or fall back to direct file/CLI access.

Quit stops polling and exits normally. Removing the menu extra must not affect
daemon authority; pending requests remain in the daemon.

### Step 6: Verify integration and commit

Run Swift/Go gates and source scans. Add/run a deterministic composition test
with injected fake client, notification adapter, login service, and lifecycle
events; it must prove one polling loop and no real permission/login mutation.
Update the subtree README with the now-real future-session behavior, explicit
notification/login settings, and local run/test commands (no install/public
claims). Record the exact real GUI checks left to plan 026, write the handoff,
and commit under the lock.

## Done criteria

- [ ] One dependency graph and one polling loop exist.
- [ ] Notification delegate/categories are ready before launch; permission is not auto-requested.
- [ ] Foreground notifications are explicitly presented through `willPresent`.
- [ ] Menu label/panel reflect all states and ID-only actions.
- [ ] Approve requires latest `can_approve`; no fallback authority exists.
- [ ] Notifications and login-at-startup are explicit user choices.
- [ ] Disconnect/version mismatch are distinct and cached rows disabled.
- [ ] No database, shell, tunnel, or token logging shortcut is added.
- [ ] Swift/Go tests and builds pass in a signed local commit.

## STOP conditions

- Plan 016 did not pass its live Darwin/CGO-off gates.
- Plan 018/020 protocol versions disagree.
- Wiring requires changing a prerequisite's security semantics rather than a
  narrow integration fix.
- `SMAppService.mainApp` or MenuBarExtra contradicts the accepted ADR/current
  official docs.
- Runtime bundle identity differs from `com.blinkerlm.agentjail.approval` or
  executable product `AgentjailApproval`.
- App Sandbox or notification Approve becomes a requirement.

## Maintenance notes

Composition is the only place concrete Apple services meet core protocols.
Keep policy and retry decisions in their domain components, not in SwiftUI
closures.
