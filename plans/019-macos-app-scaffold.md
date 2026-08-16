# Plan 019: Scaffold the standalone Swift package

> **Executor instructions:** Read the accepted ADR, `AGENTS.md`, design and
> coordination files. Create a buildable dependency-free package and a
> placeholder menu-bar app only. Do not define the wire contract or real client;
> plan 020 owns those files.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for every listed scaffold path and handoff. Any existing uncommitted target
> or overlapping scaffold is a STOP condition.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** LOW
- **Depends on:** plan 015
- **Category:** dx / app foundation
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

The repository has ad-hoc Swift files for the privileged tunnel but no Swift
package, app target, or XCTest target. A small, separate package lets multiple
agents add auto-discovered files without contending on an Xcode project file.
It also gives every later task a fast compile/test gate and keeps third-party
dependencies out.

## Current state

- `macos/AgentjailTunnel/` is an `LSUIElement` Network Extension host built by
  `scripts/build-macos-app.sh`; it is not a reusable UI target.
- No `Package.swift` exists in the repo.
- Local host: macOS 26.2 arm64, Apple Swift 6.2.4; only Command Line Tools are
  selected, so full `xcodebuild` is unavailable. SwiftPM/`swiftc` is the local
  verification path.
- Apple `MenuBarExtra` and `SMAppService` establish macOS 13 as the target.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Resolve | `rtk swift package --package-path macos/AgentjailApproval describe` | product, two production + two test targets, no dependencies |
| Test | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Build | `rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval` | exact product passes |
| Dependency guard | `rtk rg -n 'package\(url:|dependencies:' macos/AgentjailApproval/Package.swift` | no external package entry |
| Plist | `rtk plutil -lint macos/AgentjailApproval/Resources/Info.plist` | OK |

If local `xcrun` cache permissions produce the already-observed warning, record
it and try a normal unsandboxed terminal. Do not hide a real compiler failure.

## Scope

**In scope:**

- `macos/AgentjailApproval/Package.swift`
- `macos/AgentjailApproval/Sources/AgentjailApprovalCore/BuildMarker.swift`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/AgentjailApprovalApp.swift`
- `macos/AgentjailApproval/Sources/AgentjailApprovalApp/PlaceholderView.swift`
- `macos/AgentjailApproval/Tests/AgentjailApprovalCoreTests/BuildMarkerTests.swift`
- `macos/AgentjailApproval/Tests/AgentjailApprovalAppTests/ScaffoldTests.swift`
- `macos/AgentjailApproval/Resources/Info.plist`
- `macos/AgentjailApproval/README.md`
- `plans/macos-app/handoffs/019.md`

**Out of scope:** transport/models, state, production UI, notifications,
SMAppService, entitlements, build/package scripts, Makefile, tunnel files, or
Xcode project generation.

## Git workflow

One signed local commit: `feat(macos): scaffold approval companion`. Follow the
shared commit lock; do not push.

## Steps

### Step 1: Create the package graph

Use `// swift-tools-version: 6.0`, platform `.macOS(.v13)`, library target
`AgentjailApprovalCore`, executable target `AgentjailApprovalApp`, and exactly
this executable product mapping:

```swift
.executable(name: "AgentjailApproval", targets: ["AgentjailApprovalApp"])
```

Add no remote packages and no `Package.resolved`.

Define two test targets up front because later plans may not edit Package.swift:

- `AgentjailApprovalCoreTests` depends on `AgentjailApprovalCore`;
- `AgentjailApprovalAppTests` depends on `AgentjailApprovalApp` and
  `AgentjailApprovalCore`.

SwiftPM has supported test targets linking executable targets since Swift 5.5,
as recorded in the official
[SwiftPM changelog](https://github.com/swiftlang/swift-package-manager/blob/main/CHANGELOG.md).
Add one minimal scaffold test to each target so the graph is compiled now.

The core marker should be a harmless typed version/build constant that gives
the test target something real to compile. Do not pre-empt plan 020's models.

**Verify:** `swift package describe` reports the exact product/target graph and
no dependencies; `swift test` imports both production modules.

### Step 2: Add a minimal native app scene

Create an `@main` SwiftUI app with `MenuBarExtra("AgentJail", systemImage:
"shield")` and `.menuBarExtraStyle(.window)`. Render a compile-only placeholder
that clearly says the review client is not connected. Plan 024 will be the sole
later owner of the app entry.

Do not ask for notification permission, register login-at-startup, connect a
socket, shell out, or import NetworkExtension.

**Verify:** `swift build` passes and a source scan finds no `NetworkExtension`,
`UserNotifications`, `ServiceManagement`, `socket(`, or `Process(`.

### Step 3: Define bundle metadata for packaging

Add an Info.plist with the accepted exact values:

- `CFBundleIdentifier = com.blinkerlm.agentjail.approval`;
- `CFBundleExecutable = AgentjailApproval`;
- `CFBundleName`/display name = `AgentJail Approval`;
- `CFBundlePackageType = APPL`;
- `CFBundleShortVersionString = 0.1.0` and `CFBundleVersion = 1` for the local MVP;
- minimum system macOS 13 and `LSUIElement=true`.

Do not add privacy usage strings or entitlements that the placeholder does not
use. Plan 025 may package only the binary whose basename exactly equals
`CFBundleExecutable`.

**Verify:** `plutil -lint` succeeds; `PlistBuddy` reads every exact value above;
the built product basename equals `CFBundleExecutable`.

### Step 4: Document local development

The subtree README states exact `swift build`/`swift test` commands, that this
is separate from AgentjailTunnel, that SwiftPM creates an executable rather
than a distributable `.app`, and plan 025 will assemble/sign the bundle. Keep
user-facing install instructions out until plan 027.

### Step 5: Test and commit

Run describe/test/build/plist gates, write the handoff, and commit only owned
paths under the shared lock.

## Done criteria

- [ ] Dependency-free macOS 13 package exposes product `AgentjailApproval` with
  core/app targets and independently importable core/app test targets.
- [ ] Placeholder `MenuBarExtra(.window)` compiles.
- [ ] Info.plist is valid and sets `LSUIElement=true`.
- [ ] No tunnel, notification, login, socket, or process behavior is present.
- [ ] Build and tests pass, or a genuine local toolchain blocker is reported.
- [ ] Signed local commit contains only owned paths.

## STOP conditions

- An `macos/AgentjailApproval` target already exists.
- The accepted ADR selects AppKit/NSStatusItem, a different deployment target,
  product name, or bundle identity.
- SwiftPM cannot compile a minimal MenuBarExtra with installed Command Line
  Tools; report the exact toolchain error instead of generating an Xcode project.
- A dependency appears necessary.

## Maintenance notes

Keep `Package.swift` stable after this commit. Later agents add files in owned
subdirectories that SwiftPM discovers automatically; only the composition task
may edit the app entry, and only packaging may add bundle assembly logic.
