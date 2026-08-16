# AgentJail Approval macOS task board

Generated on 2026-08-15 against `d2afaf2c`. Read
[`DESIGN.md`](./DESIGN.md) and [`COORDINATION.md`](./COORDINATION.md) before
claiming a task. Planning/review history is in
[`ORCHESTRATOR_LOG.md`](./ORCHESTRATOR_LOG.md). The orchestrator owns this board;
executors own only their assigned source paths and unique handoff file.

## Execution order and status

| Plan | Title | Priority | Effort | Depends on | Status |
|---|---|---:|---:|---|---|
| 015 | Record the menu-review architecture | P0 | S | — | DONE — e1220db9 |
| 016 | Verify macOS grant project binding | P0 | M | 015 | DONE — c72a4c44 |
| 017 | Add the versioned review wire contract | P0 | S | 015 | DONE — f3f10053 |
| 019 | Scaffold the standalone Swift package | P0 | S | 015 | DONE — 8e327f1a |
| 031 | Isolate daemon subprocess test state | P0 | XS | — | DONE — f3eed6e2 |
| 032 | Add sandbox-safe Swift test harness | P0 | S | 019 | DONE — de698f31 |
| 033 | Sanitize untrusted display text | P0 | S | 019, 032 | DONE — 5424f3d3 |
| 029 | Enforce atomic pending-grant expiry | P0 | S | 016, 017 | DONE — 980057e1 |
| 020 | Build the Swift Unix-socket client | P0 | M | 017, 019, 030 | CLAIMED — plan019_prep; acceptance waits on 030 |
| 030 | Enforce strict bounded control frames | P0 | M | 017, 029 | CLAIMED — plan017_protocol |
| 021 | Build the approval state store | P0 | M | 020 | TODO |
| 018 | Serve authenticated review snapshots | P0 | S | 029, 030 | TODO |
| 022 | Build the menu-bar review UI | P1 | M | 019, 021, 033 | TODO |
| 023 | Add privacy-bounded notifications | P1 | M | 020, 021 | TODO |
| 024 | Compose the production app and settings | P0 | M | 016, 018, 022, 023 | TODO |
| 025 | Build, sign, and package locally | P1 | M | 024 | TODO |
| 026 | Prove cross-language and real-Mac behavior | P0 | L | 018, 024, 025 | TODO |
| 027 | Publish local docs and install guidance | P2 | S | 026 + dirty-path clearance | BLOCKED — README has pre-existing edits |
| 028 | Add a read-only canonical-ask observer | P3 | M | 024 | DEFERRED — not required for MVP |

Status values: TODO | CLAIMED | IN PROGRESS | REVIEW | DONE | REWORK |
BLOCKED (reason) | DEFERRED (reason) | REJECTED (rationale).

## Safe parallel waves

```text
Wave A: 015
           |
Wave B: 016       017       019
           \      /
Wave C:     029
              \
Wave D:       030
               | \
Wave E:       018  020
                     |
Wave F:             021
                    /  \
Wave G:           022  023
                    \  /
Wave H:             024
                      |
Wave I:             025
                      |
Wave J:             026
                      |
Wave K:             027
```

Plans in a wave may share HEAD movement but not files. Commit operations are
serialized by the lock in `COORDINATION.md`.

## Ownership map

| Plan | Exclusive product paths |
|---|---|
| 015 | one new ADR allocated from current `main` |
| 016 | Darwin peer-CWD/grant binding files and tests; one GOTCHAS entry |
| 017 | `internal/grantctl/` review-contract files/tests/testdata |
| 018 | daemon review endpoint files/tests and the one serialized dispatch edit |
| 019 | `Package.swift`, BuildMarker, placeholder app, core/app test targets, plist, subtree README |
| 020 | Swift `Models/`, `Transport/`, and their tests |
| 021 | Swift `State/` and its tests |
| 022 | Swift `UI/`, core `Presentation/`, and their tests |
| 023 | app/core Swift `Notifications/` and their tests |
| 024 | Swift app entry, placeholder deletion, `Composition/`, `Settings/`, `Lifecycle/`, app composition tests, subtree behavior docs |
| 025 | approval build/package scripts, entitlement, Make targets, `test/macos-approval/packaging/`, subtree packaging docs |
| 026 | `test/macos-approval/acceptance/` plus local acceptance handoff only |
| 027 | root README, approval subtree README, and `macos/README.md` only after dirty-path clearance |
| 028 | separately assigned daemon/app observer paths after MVP |
| 029 | registry expiry/claim files, smallest daemon call-site edit, one GOTCHAS entry |
| 030 | grant control framing/client files, serialized daemon decoder/reply edit, one GOTCHAS entry |
| 031 | two SIGHUP subprocess tests in `internal/daemonapp/main_test.go` only |
| 032 | `scripts/test-macos-approval.sh` only |
| 033 | exact pure `DisplaySanitizer.swift` and its matching XCTest only |

Every task additionally owns only `plans/macos-app/handoffs/NNN.md`.

## Product-wide acceptance criteria

- The daemon is the sole authority and sole policy writer.
- Approve means future project sessions; the current sandbox is unchanged.
- macOS CWD binding is kernel-verified or approval fails closed.
- Expiry is checked atomically at snapshot and claim, not delegated to a reaper.
- Requests/responses use one strictly bounded newline-delimited JSON frame.
- The app never persists or logs `control.token`.
- No direct SQLite access and no raw log parsing from Swift.
- No external approval action for Codex command asks.
- Cached requests are non-actionable while disconnected.
- Notification permission is opt-in and notification content is non-sensitive.
- No Network Extension, system-extension, or App Sandbox entitlement.
- All tests and signing checks in plan 026 pass on a real Mac.
- Every commit is signed, scoped, local-only, and reviewed before a dependent
  task starts.

## Considered and rejected

- **Put the UI in AgentjailTunnel:** rejected because it combines unrelated
  privileges and release lifecycles.
- **Read pending work from SQLite:** rejected because pending grants are
  in-memory authorization state and the singleton store rule forbids a second
  writer/connection pattern.
- **Approve Codex challenges from the app:** rejected because it bypasses the
  native prompt observation and process-lineage contract in ADRs 0118/0119.
- **Show Approve directly in a privacy-redacted notification:** rejected because
  a host grant is project-scoped and informed approval needs the project/effect
  context shown in the panel.
- **Copy the daemon control token into Keychain/App Group:** rejected because it
  duplicates the bearer boundary instead of authenticating to the existing
  control plane.
- **Promise live/time-limited grants:** rejected because ADR
  0132-cli-command-surface defines the shipped grant as persist-only.
