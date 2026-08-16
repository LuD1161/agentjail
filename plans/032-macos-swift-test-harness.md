# Plan 032: Add a sandbox-safe Swift test harness

> **Executor instructions:** Automate the already-proven direct Xcode
> `swiftc`/Darwin `xctest` fallback. This is a test runner for the existing
> SwiftPM source graph, not a second package definition. Do not change product
> Swift files, Package.swift, AgentJail policy, or the operator's environment.

## Status

- **Priority:** P0
- **Effort:** S
- **Risk:** LOW
- **Depends on:** plan 019
- **Category:** test infrastructure
- **Added at:** commit `f3f10053`, 2026-08-15

## Why this matters

The running AgentJail sandbox permits direct official-toolchain compilation but
denies SwiftPM's atomic creation of generated `output-file-map.json` files.
Plan 019 proved that Xcode's `swiftc` can compile both modules and that Darwin
`xctest` discovers and runs the existing XCTest classes. Later Swift slices
need that repeatable gate without disabling enforcement or leaving build debris
in the shared worktree.

## Scope

**In scope:**

- `scripts/test-macos-approval.sh` (new);
- `plans/macos-app/handoffs/032.md`.

**Out of scope:** Swift product/tests, Package.swift, Makefile, policy changes,
`HOME`, Terminal/launchd/SSH workarounds, downloads, dependencies, packaging,
and every other script.

## Required behavior

The script resolves the repository/package paths from its own location and uses
only the installed `/Applications/Xcode.app` compiler, macOS SDK, XCTest
framework, and `xctest` runner. It must:

1. discover all current core/app production and matching XCTest Swift sources
   deterministically;
2. compile importable `AgentjailApprovalCore` and `AgentjailApprovalApp`
   modules/libraries with testing enabled, keeping the production target at
   macOS 13;
3. build valid core/app `.xctest` bundles in an isolated task-specific
   `/private/tmp` root and run both through Darwin `xctest` runtime discovery;
4. type-check production sources for both arm64 and x86_64 macOS 13 targets;
5. create no file under `macos/AgentjailApproval` and never call SwiftPM;
6. use no network, policy mutation, `HOME` override, third-party dependency, or
   external process escape;
7. validate any cleanup root has the exact task prefix before recursively
   removing it. Preserve and print the exact root on failure; clean it on
   success unless an explicit keep flag is supplied.

The installed XCTest framework requires macOS 14 for test bundles; this is a
runner constraint only and must not change the product's macOS 13 deployment
target.

## Acceptance criteria

- One command runs all currently discovered core and app XCTest cases and
  fails if compilation, discovery, or any assertion fails.
- Both existing Plan 019 tests are discovered and pass.
- arm64 and x86_64 production type-check gates pass.
- A deliberate temporary failing assertion makes the script non-zero (perform
  this only in a task-owned temporary copy, never by modifying repository
  source).
- A source scan proves the script contains no `swift test`, policy-disable,
  `HOME=`, Terminal, launchd, SSH, curl, or package-download shortcut.
- The shared worktree has no generated Swift build artifact afterward.
- `rtk shellcheck` is used if installed; otherwise `rtk bash -n` passes and the
  missing optional linter is recorded.
- Signed local commit `test(macos): add sandbox-safe Swift harness` contains
  only the script and handoff; no remote action.

## STOP conditions

- Runtime discovery stops finding normal XCTest methods.
- The harness needs to duplicate product source lists or alter Package.swift.
- Correct execution requires weakening AgentJail or installing/downloading a
  tool.
