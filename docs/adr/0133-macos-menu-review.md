# ADR 0133-macos-menu-review: macOS menu review companion

- **Status:** Accepted; application-boundary decision superseded by [ADR 0141-unified-macos-app](0141-unified-macos-app.md)
- **Date:** 2026-08-15
- **Related:** ADR 0047-daemon-grant-server, ADR 0067-control-plane-token-auth,
  ADR 0069-daemon-control-token, ADR 0118-codex-approval-broker,
  ADR 0119-command-approval-transport, ADR 0132-cli-command-surface

## Context

Project-host requests already have a daemon-owned approval path, but reviewing
them from a terminal is inconvenient during a coding session. A macOS companion
can improve that review experience only if it remains a presentation client of
the existing daemon control plane. It must not become a second policy authority,
weaken project binding, or present controls for the separate Codex command
approval protocol.

The current Darwin CWD implementation cannot independently verify a peer
process's working directory and can fall back to a self-reported value. The
periodic grant reaper also cannot be the authorization boundary for an item that
has just expired. Both conditions would make a UI approval promise unsafe.

### Platform verification

Verified against Apple primary sources on 2026-08-15:

- [MenuBarExtra](https://developer.apple.com/documentation/swiftui/menubarextra)
  is available on macOS 13.0+; its `window` style supports a richer menu-bar
  control and `LSUIElement` is the documented menu-only Dock/app-switcher
  posture.
- [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
  is available on macOS 13.0+ and supplies `mainApp` registration for login
  items, subject to user approval.
- [Declaring actionable notification types](https://developer.apple.com/documentation/usernotifications/declaring-your-actionable-notification-types)
  requires categories and actions to be registered at launch and every action
  to be handled.
- [Asking permission to use notifications](https://developer.apple.com/documentation/usernotifications/asking-permission-to-use-notifications),
  [`willPresent`](https://developer.apple.com/documentation/usernotifications/unusernotificationcenterdelegate/usernotificationcenter%28_%3Awillpresent%3Awithcompletionhandler%3A%29),
  and Apple's [notification guidance](https://developer.apple.com/design/human-interface-guidelines/notifications)
  support contextual permission, explicit foreground presentation, and generic
  notification content.
- [Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)
  describes container- and user-selection-based access, which does not fit the
  existing control-token and Unix-socket contract.
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
  documents hardened runtime for Developer ID distribution and per-executable
  signing rather than `--deep`.

Local environment checked on 2026-08-15: macOS 26.2 (build 25C56), Command Line
Tools developer directory, and macOS SDK 26.2 at
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`. `swift --version` could
not report a version: `xcrun` was denied creation of its cache file under
`/var/folders/.../T/xcrun_db-*` (`permissionDenied`). `xcodebuild -version`
also confirmed the active developer directory is Command Line Tools rather than
a full Xcode installation. No Swift version is inferred from the SDK.

## Decision

### App boundary and distribution

Ship a separate `macos/AgentjailApproval/` Swift package and application. Its
exact SwiftPM product and binary name is `AgentjailApproval`; its display name
is `AgentJail Approval`; and its bundle identifier is
`com.blinkerlm.agentjail.approval`.

The app targets macOS 13 and later, uses SwiftUI `MenuBarExtra` with `.window`
style, sets `LSUIElement=true`, and provides a Settings scene. Login startup is
an explicit opt-in through `SMAppService.mainApp`; it is never silently enabled.

`MenuBarExtra` remains the canonical manual review surface. Its public API does
not expose panel presentation state, so notification **Review** is allowed to
open one supplemental singleton SwiftUI `Window` through `OpenWindowAction`.
That window renders the same panel against the same store and ID-only actions;
it creates no second poller or authority. A generation-stamped route is observed
from the persistent menu-bar label, refreshes before focus, and treats a missing
or stale ID as non-actionable. Private `NSStatusItem`, window enumeration, and
dynamic-selector fallbacks are forbidden.

The app uses the `MenuBarExtra` insertion binding and terminates normally after
the user removes the extra, so an `LSUIElement` login app cannot keep polling
invisibly. A later explicit/login launch inserts it again without changing login
registration or daemon state. The Settings scene remains canonical; because
the public `openSettings` action starts at macOS 14 in the verified SDK, macOS
13 opens the same settings view in a separate public singleton SwiftUI window.
This refinement was verified on 2026-08-15 with Xcode 26.6, Swift 6.3.3, and
the macOS 26.5 SDK using strict macOS 13 type-check probes.

GitHub-hosted native-app jobs use `macos-15` with
`/Applications/Xcode_16.4.app/Contents/Developer`, and fail in a toolchain
preflight unless `-swift-version 6` is supported. The previous `macos-14`
default selected Xcode 15.4 and failed before compilation despite a valid local
build. GitHub's official
[`macos-15` runner inventory](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md)
listed Xcode 16.4 as the default and was verified on 2026-08-25.

V1 is directly distributed, uses hardened runtime, and must be Developer ID
signed and notarized before a public build. It has no App Sandbox in v1. A
sandboxed or Mac App Store version requires a future ADR and an XPC/IPC redesign;
it must not copy the bearer token into another container. The Approval app must
not merge with `macos/AgentjailTunnel/`, request Network Extension or
system-extension entitlements, or inherit the tunnel app's release lifecycle.

Local packaging is ad-hoc signed with hardened runtime and an exact empty
entitlement dictionary. Developer ID signing and notarization are explicit later
work, not properties claimed for a local build. All work and commits remain
local until separately authorized.

### Authority and review scope

`daemon-ctl.sock` plus `control.token` is the only authority seam. The app opens
a new connection for every operation and loads the token immediately before the
round trip. It neither persists nor logs the token, and never places it in
observable state, preferences, Keychain, crash metadata, notification payloads,
or diagnostics.

Swift has no direct SQLite access, audit-log parsing, or policy-file writes.
Only the daemon can authenticate, claim, audit, and persist a decision.

V1 actions are exclusively project-host grants. Approval is displayed exactly as
**Approve for future sessions**. Supporting copy must say that the running
sandbox remains unchanged and a new session is required. “Allow once”, “Allow
for 1 hour”, and “Allow now” are forbidden: they falsely claim current-session
authority under the daemon's persist-only contract.

Codex command `ask` decisions remain solely on the native, one-use broker path
defined by ADR 0118-codex-approval-broker and ADR
0119-command-approval-transport. The app provides no Codex Approve action,
challenge, raw command, or alternate redemption path.

Before an enabled Approve control can ship, Darwin CWD resolution and
verification must fail closed: a failed verification leaves a grant unbound and
unapprovable. Expiry must be checked against daemon server time atomically in
both review snapshot and claim. The periodic reaper is cleanup only, never the
authorization check.

### Protocol, data bounds, and polling

The control protocol uses one newline-terminated JSON value per connection. The
entire frame, including terminal newline, is limited to 64 KiB. The server
rejects invalid UTF-8, a missing delimiter, an over-limit frame, malformed JSON,
and trailing non-whitespace within the frame; it never dispatches a second frame
on that connection.

A snapshot returns at most the three newest rows, its total count, and a
truncation flag. Authority-bearing host and verified-project fields are supplied
in full or represented by a typed `unrepresentable` context state with
`can_approve=false`; they are never display-truncated while actionable.
Agent-provided prose may be bounded for display only and is explicitly marked
as such.

V1 polls the daemon at a bounded two-second interval, with refresh on focus and
after a mutation. It adds no streaming dependency. Disconnected state retains
cached context only as stale and disables every action.

### Notifications

Notification permission is contextual opt-in from Settings. Content is generic:
“AgentJail approval requested — review a project host request.” It contains no
project path, session ID, token, raw reason, command, or review ID. The only
actions are Review and Deny; Review explicitly foregrounds the app, and
foreground presentation is handled explicitly.

Review opens/focuses the public supplemental singleton review window rather
than attempting to programmatically present the MenuBarExtra panel. It refreshes
the snapshot before focusing and never performs a mutation.

There is no notification Approve action. Deny is destructive and requires device
authentication. Before denial, the app refetches the review and treats a stale,
expired, or resolved request as a benign race. Notification request identifiers
use an app-owned prefix plus a one-way hash of the review ID; no raw review ID
appears in the identifier.

## Consequences

- The GUI improves discoverability while keeping authorization, audit, project
  binding, expiry, and policy mutation in the daemon.
- Implementation may develop UI against fakes before the CWD and atomic-expiry
  gates land, but it cannot wire a live Approve control until both are verified
  on a real Mac.
- The v1 filesystem posture deliberately excludes App Sandbox and Mac App Store
  distribution. A future sandboxed design must establish a new least-privilege
  IPC authority without copying `control.token`.
- Polling is intentionally simple and bounded for the MVP; a future push or
  streaming protocol needs its own compatibility and security decision.
- Future code comments that depend on this architecture cite ADR
  0133-macos-menu-review rather than restating the rationale.
