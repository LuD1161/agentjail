# AgentJail Approval for macOS — product and architecture design

> Planning artifact only. Product source is unchanged. Written against commit
> `d2afaf2c` on 2026-08-15. The implementation ADR is plan 015.

## Product outcome

AgentJail Approval is a small, native menu-bar companion for macOS. It keeps
security review close at hand without turning the GUI into a second policy
authority.

The first shippable version does four things:

1. Shows daemon health and a count of pending project-host requests.
2. Opens a compact review panel from the menu bar.
3. Lets a human approve a host for that project's **future sessions**, or deny
   the request.
4. Sends privacy-bounded local notifications after an explicit opt-in.

It does not grant the current sandbox temporary access. It does not approve
Codex commands. It does not read AgentJail's SQLite database or write policy
files; the daemon remains the only writer and authorization authority.

## Architecture

```text
shielded agent
    |
    | grant_request on agent-reachable daemon.sock
    v
agentjail-daemon
    |  in-memory pending registry
    |  verified project binding
    |  fail-closed audit + policy persistence
    |
    | authenticated JSON over daemon-ctl.sock
    | control.token read by the unsandboxed human app
    v
AgentJail Approval.app
    |  2 s snapshot polling + refresh on focus/action
    |  no database access, no policy write, no token persistence
    v
MenuBarExtra panel + local notification
```

The app is a separate bundle under `macos/AgentjailApproval/`. It must not be
folded into `macos/AgentjailTunnel/`: that bundle owns Network Extension and
system-extension privileges, a different release lifecycle, and a different
failure domain.

## Platform decisions

- **Deployment target:** macOS 13 or later.
- **UI:** SwiftUI `MenuBarExtra` with `.window` style is the canonical manual
  review surface, plus a Settings scene. Notification **Review** may open one
  supplemental singleton SwiftUI review window that reuses the same panel,
  store, and ID-only actions. macOS 13 uses a separate singleton settings
  window as the public programmatic fallback for the Settings scene.
- **Dock behavior:** `LSUIElement=true`; the app is a menu-bar utility.
- **Identity:** SwiftPM product/binary `AgentjailApproval`, display name
  `AgentJail Approval`, bundle ID `com.blinkerlm.agentjail.approval`.
- **Startup:** opt-in `SMAppService.mainApp`, never silently enabled.
- **Distribution:** direct distribution, hardened runtime, Developer ID and
  notarization before public release. Local builds may be ad-hoc signed.
- **App Sandbox:** off for v1 because the companion must read the existing
  `~/.agentjail/control.token` and connect to the existing Unix socket. A Mac
  App Store/App Sandbox design requires a new ADR and a redesigned IPC seam;
  copying the bearer token into another container is forbidden.
- **Dependencies:** Apple frameworks and Swift/Go standard libraries only.

Apple source verification (accessed 2026-08-15):

- [`MenuBarExtra`](https://developer.apple.com/documentation/swiftui/menubarextra)
  is the native persistent menu-bar scene; `.window` is intended for richer
  controls, and `LSUIElement` hides a menu-only app from the Dock. Its public
  binding controls insertion, not whether its panel is presented.
- [`Window`](https://developer.apple.com/documentation/swiftui/window) and
  [`OpenWindowAction`](https://developer.apple.com/documentation/swiftui/openwindowaction)
  provide an addressable macOS 13+ singleton that is ordered forward when
  already open. A strict local Swift 6/macOS 13 probe passed on Xcode 26.6 and
  SDK 26.5 on 2026-08-15.
- [`Settings`](https://developer.apple.com/documentation/swiftui/settings) is
  available at the deployment floor. Local SDK interfaces show
  [`openSettings`](https://developer.apple.com/documentation/swiftui/environmentvalues/opensettings)
  and `SettingsLink` begin at macOS 14, so macOS 13 uses the public singleton
  settings-window route rather than selector-based AppKit fallbacks.
- [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice)
  is the macOS 13+ login-item API.
- [Actionable notifications](https://developer.apple.com/documentation/usernotifications/declaring-your-actionable-notification-types)
  require categories/actions registered at launch and handling every action.
- [`willPresent`](https://developer.apple.com/documentation/usernotifications/unusernotificationcenterdelegate/usernotificationcenter%28_%3Awillpresent%3Awithcompletionhandler%3A%29)
  must return presentation options for foreground delivery; without the method,
  the delegate path behaves as presentation-none.
- Apple recommends [requesting notification permission in context](https://developer.apple.com/documentation/usernotifications/asking-permission-to-use-notifications),
  not automatically on first launch.
- [App Sandbox file access](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)
  is container- and user-selection-based; it does not match the existing
  daemon token/socket contract.
- Apple's notification guidance says to avoid [sensitive or confidential
  content](https://developer.apple.com/design/human-interface-guidelines/notifications).
- Apple's [manual macOS signing guidance](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
  requires identifying every code item, signing inside-out, applying
  entitlements to main executables, enabling hardened runtime for Developer ID,
  and avoiding `--deep` as a signing shortcut.

## Authorization boundary

Only project-host grants are actionable in v1. They already have typed
`grant_list`, `grant_approve`, and `grant_deny` control verbs, a 0600 control
token that shielded agents cannot read, single-winner claim behavior, and
fail-closed audit before persistence.

The v1 control frame is one compact JSON value with no raw LF byte, followed by
one terminal LF, with a 64-KiB hard limit including the delimiter. Readers
reject invalid UTF-8, an over-limit/missing delimiter, and any bytes other than
space/tab/CR after the JSON value before the terminal LF. A second frame on the
same connection is never dispatched. Every operation uses a new connection.

Review snapshots are also bounded by construction. Authority-bearing host and
verified-project fields are either present in full or omitted with a typed
`unrepresentable` context state and `can_approve=false`; they are never visually
truncated and left actionable. Agent prose may be display-truncated with an
explicit flag. V1 returns at most three newest reviews, reports the total and a
truncation flag, and remains below 64 KiB for worst-case JSON escaping.

The exact approval copy is:

> Approve for future sessions

Supporting copy must say that the currently running sandbox is unchanged and a
new session is required. “Allow once”, “Allow for 1 hour”, and “Allow now” are
false claims for the current daemon contract and are forbidden.

Codex Bash `ask` decisions continue through ADR
0118-codex-approval-broker and ADR 0119-command-approval-transport. Their
one-use challenge, native Codex prompt observation, epoch, and fresh process
lineage cannot be satisfied by a menu click. A later read-only observer may
notify that Codex is waiting, but it must expose no Approve action, challenge,
or raw command.

## Security gate before Approve ships

The current Darwin implementation cannot verify another process's CWD and
`decideBoundCWD` falls back to the agent-reported path. That contradicts the
daemon's intended verified-binding guarantee and could persist a host into a
project chosen by untrusted input.

Plan 016 must deliver both properties before plan 024 can wire the Approve
button:

1. Any CWD verification failure leaves the grant unbound (fail closed).
2. A CGO-disabled Darwin implementation resolves and live-verifies the peer
   process CWD, or the task stops and reports that macOS approval remains
   unavailable.

The UI may be developed against fakes in parallel, but no composed app build
may enable approval until this gate passes on a real Mac.

Plan 029 must also make request expiry part of the atomic registry claim. The
periodic reaper is cleanup, not an authorization check: an item at or past its
server expiry is absent from snapshots and cannot be approved in the interval
before the next reap. Plan 030 then makes the shared control frame strictly
bounded before the new endpoint is served.

## UX specification

### Menu-bar icon

- Ready, zero pending: template shield icon, accessibility value “No pending
  approvals”.
- Ready, pending: shield plus numeric count; accessibility value includes the
  exact count.
- Connecting: neutral progress state.
- Disconnected/unauthorized/version mismatch: amber warning shape plus text in
  the panel; never rely on color alone.

### Panel (approximately 420 × 520 points)

1. Header: AgentJail, daemon state, pending count.
2. Pending requests, newest first. Each card shows:
   - requested host;
   - project display name and full verified path;
   - “Agent-provided reason” in a visually distinct, bounded block;
   - effect: “Adds this host to the project policy for future sessions.”
3. Actions:
   - primary: **Approve for future sessions**;
   - secondary/destructive: **Deny**;
   - one request can have only one in-flight action.
4. Empty state: “No approvals waiting.”
5. Disconnected state: explain that cached requests are not actionable and
   offer Retry.
6. Footer: Settings and Quit. Dashboard integration is deferred until its
   launch/URL contract is explicit.

The same `ApprovalPanelView` may appear in one supplemental singleton window
only when an explicit notification Review route needs an addressable surface.
This does not create a second client, store, poller, or authority path.

Agent-controlled strings are untrusted. Strip C0/C1 controls and bidi
overrides, replace line breaks/tabs with spaces, bound displayed length, and
label the reason as agent-provided. Never interpolate these strings into a
shell command, URL, notification identifier, or log format.

### Notifications

- Permission is requested only from a Settings action that explains why.
- Exactly one notification is scheduled per stable review ID.
- Default content is deliberately generic: “AgentJail approval requested —
  review a project host request.” It contains no path, session ID, token, raw
  reason, or command.
- Actions are **Review** (foreground) and **Deny**. Approve is intentionally not
  offered without the panel's project/effect context.
- Review uses the foreground action option. Deny is destructive and requires
  device authentication. Foreground delivery is handled explicitly through
  the notification delegate's `willPresent` callback.
- Review publishes a generation-stamped ID route, activates the app, opens the
  one supplemental review window through public SwiftUI `OpenWindowAction`,
  refreshes authority, and focuses the matching row. Repeated IDs are distinct
  events. Missing, expired, or resolved IDs remain non-actionable with bounded
  feedback. The persistent MenuBarExtra label owns the route bridge because
  menu content is not mounted while the panel is closed.
- Notification request identifiers use an app-owned prefix plus a one-way hash
  of the daemon review ID; raw IDs appear only in the minimal callback payload.
- Before Deny, refetch the snapshot and confirm the ID is still pending. A
  stale, expired, or already-decided request becomes a benign race result.
- Notification permission denial never degrades the menu-bar workflow.
- Do not request Time Sensitive or Critical alert capability.

The MenuBarExtra uses the public `isInserted` binding because the app also has
Settings and supplemental Window scenes. If the user removes the extra, the app
stops polling and terminates normally rather than remaining as an invisible
`LSUIElement` process. A later explicit/login launch inserts it again; removal
does not mutate daemon authority or silently change login-item registration.

## State model

```text
starting -> connecting -> ready(empty|pending)
               |              |
               v              v
          disconnected <- action_failed
                                |
                                v
                       refresh -> ready
```

Rules:

- Poll off the main actor every two seconds; refresh immediately on activation
  and after every action.
- Back off while disconnected, capped at 30 seconds; a manual Retry is
  immediate.
- On disconnect, keep cached rows only as visibly stale context and disable
  every action.
- Sort by server timestamp/review ID, not dictionary iteration.
- Dedupe by stable review ID. Local “already notified” state is UX-only and
  carries no authority.
- A protocol-version mismatch is a distinct unsupported state, not an empty
  queue.
- Local time may disable an apparently expired row early, but every mutation is
  ultimately rechecked by the daemon's atomic server-time expiry rule.

## Data minimization

Allowed in memory and panel:

- review ID, kind, host, verified project path, bounded agent reason, created
  and expiry timestamps, actionability, and future-session effect.

Forbidden everywhere in the app:

- original command text, Codex challenge, credential values, raw tool input,
  policy-file contents, database write handles, control token in logs or
  preferences, and audit details beyond the typed review projection.

The app loads `control.token` immediately before a request and keeps it scoped
to that round trip; it never retains it in observable app state or copies it
into UserDefaults, Keychain, crash metadata, notification payloads, or
diagnostics. Swift does not promise reliable memory zeroization of `String` or
`Data`, and the design makes no such claim.

## Release acceptance

Automated gates:

- Go contract/daemon tests, build, vet, race tests, smoke, and ADR check pass.
- Swift package builds and tests with no third-party package resolution.
- Universal app contains arm64 and x86_64 slices.
- `plutil -lint`, per-executable `codesign --verify --strict`, and bundle
  verification pass; `--deep` is supplemental, not the entitlement proof.
- The actual signature has the hardened-runtime flag, consumes the approved
  entitlement file, and its normalized entitlement dictionary is exactly empty.
  Notifications, `SMAppService.mainApp`, and local Unix sockets require no v1
  entitlement; any future key needs a new reviewed rationale.
- Contract fixture proves Swift and Go agree on v1 JSON.

Manual real-Mac gate:

- empty, pending, approve, deny, expired, double-action race, daemon restart,
  missing/bad token, protocol mismatch, notifications denied, notification
  Review/Deny while backgrounded, Focus/scheduled delivery, login-item
  approval, keyboard-only use, VoiceOver, Voice Control, Switch Control, and
  Accessibility Inspector.
- A real `agentjail allow host` request is approved into the verified project's
  overlay; the current session remains unchanged and a new session sees the
  policy.

## Explicitly deferred

- Generic command/file/MCP approval from the app.
- Current-session or time-limited host grants.
- Mac App Store/App Sandbox distribution.
- Replacing Codex's native approval broker.
- Editing policy, secrets, credentials, or network rules in the app.
- Combining the approval companion with AgentjailTunnel.
- Public release workflow changes; this work remains local until the operator
  explicitly authorizes publication.
