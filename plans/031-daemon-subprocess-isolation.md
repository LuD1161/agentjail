# Plan 031: Isolate daemon subprocess test state

> **Executor instructions:** This supplemental acceptance-enabler is independent
> of the approval product. Change only the two existing SIGHUP subprocess tests
> so their daemon instances never inherit mutable state paths from the operator's
> home directory. Do not change production defaults or set `HOME`.

## Status

- **Priority:** P0
- **Effort:** XS
- **Risk:** LOW
- **Depends on:** none
- **Category:** test reliability
- **Added at:** commit `c72a4c44`, 2026-08-15

## Why this matters

`TestDaemon_SIGHUP_MCPDecisionChanges` and
`TestDaemon_SIGHUP_FailureKeepsOldPolicy` already isolate their socket and
policy, but their daemon subprocesses use the default `~/.agentjail/daemon.log`
and SQLite path. On a constrained or unusual home layout the daemon exits before
creating its socket, masking every later macOS acceptance gate.

## Scope

**In scope:**

- `internal/daemonapp/main_test.go`, limited to the two SIGHUP subprocess tests
  and a narrowly local helper if it reduces duplication;
- `plans/macos-app/handoffs/031.md`.

**Out of scope:** production code, daemon defaults, other tests, `HOME`, user
state, approval behavior, planning board/log, or dependencies.

## Required change

Pass explicit task-local `--log` and `--db` paths beneath each test's existing
`t.TempDir()` to both daemon subprocesses. Preserve their socket, policy, rules,
signals, assertions, and cleanup semantics. Do not read, create, rename, or
remove the real `~/.agentjail` path.

## Acceptance criteria

- Both tests pass when the operator home is unavailable or has an incompatible
  `.agentjail` entry because no required subprocess state path uses it.
- Log and database paths are distinct, explicit descendants of that test's
  temporary directory.
- No production source/default changes and no environment-wide `HOME` override.
- `rtk go test ./internal/daemonapp -run 'TestDaemon_SIGHUP_' -count=1` passes.
- The same focused tests pass with `-race`.
- `rtk go vet ./internal/daemonapp` and `rtk git diff --check` pass.
- One signed local commit, `test(daemon): isolate subprocess state`, touches
  only the owned test and handoff; no remote action.

## STOP conditions

- The daemon still requires an unowned home-derived path after explicit log and
  database arguments.
- Fixing the tests requires changing production behavior or disabling a
  security boundary.
