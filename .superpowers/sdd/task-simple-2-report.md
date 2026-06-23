# Task Simple-2 Report: Daemon Auto-Update

## Status: COMPLETE

## What was done

### `cmd/agentjail-daemon/updatechecker.go`
- Added `AutoUpdate`, `InstallDir`, `PlistPath`, `GOOS`, `GOARCH` fields to `UpdateChecker`
- Added package-level `osExitFn = os.Exit` variable (allows tests to intercept exit)
- Added `performAutoUpdate(ctx, latest)` method implementing the full download→verify→extract→backup→swap→exit flow
- Wired auto-update gates into `checkOnce` after `recordNotified`: checks `AutoUpdate`, `SigningPubKey`, `uc.GOOS == "darwin"`, and `!isBrew` (reuses the already-computed `isBrew` variable)

### `cmd/agentjail-daemon/main.go`
- Reads `AGENTJAIL_AUTO_UPDATE != "false"` to set `autoUpdate` (enabled by default, disabled by env)
- Computes `installDir` via `os.Executable()` + `filepath.Dir()`
- Computes `plistPath` as `~/Library/LaunchAgents/com.agentjail.daemon.plist`
- Passes `AutoUpdate`, `InstallDir`, `PlistPath`, `GOOS`, `GOARCH` to the `UpdateChecker`

### `cmd/agentjail-daemon/updatechecker_test.go`
- Added `newAutoUpdateChecker` helper
- Added 3 gate tests:
  - `TestUpdateChecker_AutoUpdate_SkipsWhenDisabled` — `AutoUpdate=false`
  - `TestUpdateChecker_AutoUpdate_SkipsBrew` — `isBrew=true`
  - `TestUpdateChecker_AutoUpdate_SkipsNonDarwin` — `GOOS="linux"`

## Test summary
- 57 tests pass (up from 54), 0 failures
- `go build ./... && go vet ./...` clean

## Commits
- `feat(daemon): add simple auto-update — download, verify, swap, exit`

## Concerns / notes
- The GOOS gate uses `uc.GOOS` (not `runtime.GOOS`) so it is testable without build tags. In production, `main.go` sets `GOOS: runtime.GOOS`.
- The `alreadyNotified` throttle gate runs before auto-update: if we've already sent the notification, we skip auto-update too. This means auto-update only triggers once per version detection cycle — on next check (6h later) the throttle file will still match and we'll skip again. This is intentional to avoid repeated download attempts on failures; on success we exit before the throttle matters.
- Full integration (actual download + swap) is not unit-tested — that requires a mock HTTP server and is integration-level.
