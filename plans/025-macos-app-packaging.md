# Plan 025: Build, sign, and package the approval app locally

> **Executor instructions:** Begin only after plan 024 is reviewed DONE. Read
> its handoff and the accepted menu-review ADR. Build a new packaging path for
> `AgentjailApproval`; do not modify or reuse the privileged AgentjailTunnel
> bundle scripts as a shortcut.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for the exact new entitlement/scripts/tests, narrow Makefile hunk, and handoff.
> Any overlap with `scripts/dev-deploy.sh`, tunnel scripts, release automation,
> or an uncommitted Makefile edit is a STOP condition.

## Status

- **Priority:** P1
- **Effort:** M
- **Risk:** MED
- **Depends on:** plan 024
- **Category:** build / distribution
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

`swift build` produces an executable, not a correctly structured, signed macOS
application. The MVP needs a reproducible local `.app` and disk image whose
metadata, architectures, entitlements, and signature can be inspected before
any release work. Packaging must remain separate from the Network Extension
host so the approval UI inherits no privileged entitlements.

## Current state

- `scripts/build-macos-app.sh` and the `macos-app` Make target build
  AgentjailTunnel. Their identity, entitlements, and lifecycle are unrelated.
- Plan 019 owns approval-app Info.plist metadata; plan 024 provides the complete
  Swift executable.
- Only Command Line Tools are selected on the planning host. The local path
  must therefore work without generating an Xcode project.
- Public Developer ID signing/notarization is not authorized in this task.
  This task supports ad-hoc signing only; adding identity/notary inputs is
  separate work because timestamp/notary flows can contact external services.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Swift tests | `rtk swift test --package-path macos/AgentjailApproval` | pass |
| Exact product | `rtk swift build -c release --package-path macos/AgentjailApproval --product AgentjailApproval` | binary named `AgentjailApproval` |
| Build app | `rtk make macos-approval-app` | local `.app` produced |
| Package | `rtk make macos-approval-dmg` | local `.dmg` produced |
| Architectures | `rtk lipo -info <app>/Contents/MacOS/AgentjailApproval` | arm64 and x86_64 |
| Plist | `rtk plutil -lint <app>/Contents/Info.plist` | OK |
| Main signature | `rtk codesign --verify --strict --verbose=2 <app>/Contents/MacOS/AgentjailApproval` | pass |
| Bundle signature | `rtk codesign --verify --deep --strict --verbose=2 <app>` | supplemental pass |
| Signature flags | `rtk codesign -dvvv <app>/Contents/MacOS/AgentjailApproval` | runtime flag present |
| Entitlements | `rtk codesign -d --entitlements :- <app>/Contents/MacOS/AgentjailApproval` | normalized exact minimal allowlist |
| Gatekeeper note | `rtk spctl --assess --type execute --verbose=4 <app>` | expected local ad-hoc limitation is recorded, never hidden |

Replace `<app>` with the explicit artifact path printed by the build script.
Do not use a broad glob in signing or cleanup commands.

## Scope

**In scope:**

- `macos/AgentjailApproval/Resources/AgentjailApproval.entitlements`
- `scripts/build-macos-approval-app.sh`
- `scripts/package-macos-approval-dmg.sh`
- narrowly named `macos-approval-app` and `macos-approval-dmg` targets in
  `Makefile`
- packaging-command/status update to `macos/AgentjailApproval/README.md`
- packaging-focused tests under `test/macos-approval/packaging/`, if required
- `plans/macos-app/handoffs/025.md`

**Out of scope:** existing AgentjailTunnel files/scripts/targets, Package.swift,
Swift sources, installer, Homebrew, release workflow, GitHub release assets,
notarization submission, root README, version bump, or public upload.

## Git workflow

One signed local commit: `build(macos): package approval companion`. Follow the
shared commit lock. Never push, publish, notarize, or create a GitHub artifact.

## Steps

### Step 1: Define the minimal entitlement boundary

Create an explicit entitlement plist for the approval companion. It must not
contain App Sandbox, Network Extension, System Extension, privileged helper,
App Group, keychain sharing, or notification-critical-alert entitlements. The
accepted ADR explains why the direct-distribution MVP reads the existing local
control token/socket outside App Sandbox.

The v1 allowlist is the empty dictionary: notifications,
`SMAppService.mainApp`, and local Unix sockets require no entitlement. The file
must be a valid XML plist containing `<dict/>`; any actual signature key/value
is a failure, including hardened-runtime exception entitlements. Hardened
runtime is asserted as a code-signature flag, not an entitlement.

Use no inherited AgentjailTunnel entitlement file.

**Verify:** `plutil -lint` passes and a normalized deep-equality test proves the
source and actual signature dictionaries are both exactly empty.

### Step 2: Build a deterministic universal app bundle

The build script must:

1. resolve repository root relative to the script;
2. build product `AgentjailApproval` for arm64 and x86_64 with explicit Swift
   target triples supported by the installed toolchain;
3. combine them with `lipo`;
4. create `Contents/MacOS` and `Contents/Resources` beneath a task-specific
   artifact directory;
5. copy the plan-019 Info.plist and approved resources;
6. assert `CFBundleExecutable` is `AgentjailApproval`, its basename equals the
   lipo-built binary, and `CFBundleIdentifier` is
   `com.blinkerlm.agentjail.approval`;
7. sign the app bundle ad-hoc with identity `-`, `--options runtime`,
   `--timestamp=none`, and the exact approved entitlement file (no ambient
   identity environment variable); sign any future nested code explicitly
   before the outer bundle, never with `--deep` as a signing shortcut;
8. verify each executable and the bundle, compare actual normalized
   entitlements to the expected empty dictionary, assert the runtime signature flag,
   and print the exact output path.

Build in temporary/task-specific directories and replace only the explicit
approval artifact. Never run recursive deletion against a variable that has
not first been validated as a descendant of the artifact root.

**Verify:** run the script twice from explicit empty task-specific artifact
directories and compare sorted relative `Contents` path/type manifests plus
normalized Info.plist/entitlements; all match. `lipo`, exact executable/bundle
identity, minimum-system-version, runtime flag, and per-executable signature
checks pass. Signature bytes themselves need not be reproducible.

### Step 3: Package a local disk image

Create a separate script that accepts or builds the verified `.app`, stages it
with an `/Applications` symlink, and creates a compressed disk image under the
approval artifact root. It must not install the app, mutate `/Applications`,
contact Apple, or upload anything.

Reject an unsigned/invalid app before imaging. Print checksum and artifact path
for plan 026 evidence.

**Verify:** mount read-only, inspect the app and symlink, unmount, and verify
the packaged app signature again. Record exact commands in the handoff.

### Step 4: Add narrow Make targets

Add phony targets with approval-specific names. They invoke only the new
scripts and do not change `macos-app`, `install`, `release`, or tunnel targets.
Keep environment inputs documented in target help or script usage.

**Verify:** `rtk make -n macos-approval-app` and `rtk make -n
macos-approval-dmg` resolve only approval paths.

### Step 5: Test and commit

Run all commands above on the physical Mac. Record tool versions, artifact
paths, hashes, architecture output, signature details, ad-hoc Gatekeeper
result, and unavailable/deferred Developer ID status in the handoff. Update the
subtree README with exact local artifact commands/paths and the ad-hoc-only
limitation. Commit only owned files under the shared lock.

## Done criteria

- [ ] A universal, valid `AgentjailApproval.app` is reproducibly assembled.
- [ ] The approval app has none of the tunnel/sandbox/privileged entitlements.
- [ ] Source and actual entitlement dictionaries are exactly empty; no runtime
  exception entitlement is present.
- [ ] Local ad-hoc signing consumes the approved entitlements, enables hardened
  runtime, and cannot silently succeed after failure.
- [ ] A locally mountable DMG contains the verified app and Applications link.
- [ ] Make targets do not alter existing tunnel, installer, or release behavior.
- [ ] No network publication or notarization request occurred.
- [ ] Physical-Mac evidence is captured in a signed local commit handoff.

## STOP conditions

- Universal Swift compilation cannot be proven with the installed toolchain.
- Packaging requires changing production Swift behavior or bundle identity.
- Codesign verification fails, is weakened with `|| true`, or inherited tunnel
  entitlements appear.
- A real signing identity, Apple credentials, timestamp service, notarization, installation, or
  public upload would be required.
- A required Makefile hunk overlaps uncommitted user edits.

## Maintenance notes

This task produces local artifacts only. Release distribution, notarization,
update channels, and installer integration require separate authorization and
their own acceptance gates.
