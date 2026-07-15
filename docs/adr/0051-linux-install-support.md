# ADR 0051: Linux is a first-class `agentjail install` target

**Status:** Accepted

## Context

`agentjail install` hard-gated any non-darwin platform: `runInstallCmd`
checked `currentGOOS != "darwin"`, printed a "hooks not wired" detection
report, and called `os.Exit(1)` unless `--allow-unsupported` was passed (which
only downgraded the exit code to 0 — hooks still weren't wired and no daemon
was started). Meanwhile:

- `README.md` claimed "Linux note: fully supported since v0.2.6. The daemon
  runs under systemd user services" — a forward-looking claim that did not
  match the actual gate in `cmd/agentjail/install.go`.
- `install.sh` (the `curl | sh` one-liner) detects `linux` as a supported
  `$OS` for binary download/extraction, then calls `"$INSTALL_DIR/agentjail"
  install` unconditionally under `set -eu` — so on Linux the script downloaded
  and installed the binaries, then aborted on the gate's `exit 1` before ever
  reaching the PATH setup at the bottom of the script.
- Linux scaffolding already existed and was unused in the install path:
  `internal/selfupdate/systemd_linux.go` implements `SystemdRestart` /
  `RestartDaemon` for the daemon's self-update flow, and per-OS `_linux.go`
  files exist throughout the shield, daemon, and netns packages. The hook
  wiring in `internal/agents/` (writing `~/.claude/settings.json`,
  `~/.cursor/hooks.json`, etc.) has always been OS-agnostic — it never touched
  the gate.

The product decision is that Linux is a supported target, not a "detect only"
platform. This ADR records what changed to make that real, mirroring the
precedent set for other per-OS decisions ([ADR 0034], platform backends share
a canonical contract; [ADR 0007], Windows is explicitly deferred rather than
half-supported).

## Decision

**Remove the Linux gate. `agentjail install` runs the same six-step daemon
preamble on Linux as on macOS, substituting a systemd `--user` service for the
launchd plist.**

1. **Steps 1-4 are already OS-agnostic** (copy `agentjail-hook` /
   `agentjail-daemon`, install `.rego` rules, write `policy.yaml`) and needed
   no change.
2. **Step 5 (service definition) branches by `currentGOOS`:**
   - macOS: unchanged — the launchd plist at
     `~/Library/LaunchAgents/com.agentjail.daemon.plist`.
   - Linux: a systemd `--user` unit at
     `~/.config/systemd/user/agentjail-daemon.service`, with
     `Restart=always` / `RestartSec=2` for the same self-recovery
     `KeepAlive=true` gives on macOS, and `WantedBy=default.target` (not
     `graphical-session.target`) so it starts in headless SSH sessions, not
     only desktop logins.
3. **Step 6 (start) branches by `currentGOOS`:**
   - macOS: unchanged — `launchctl` unload/load.
   - Linux: `systemctl --user enable --now agentjail-daemon.service`, then
     `restart` so a reinstall picks up a refreshed binary/unit — mirroring the
     launchd "unload then load" idempotency. This only runs when a systemd
     `--user` session is actually reachable (`systemctl --user
     show-environment` succeeds as a cheap, read-only capability probe). If no
     session is reachable — a bare container with no login session, a CI
     runner, `sudo`'d root shell with no lingering user session — the unit is
     still written and `agentjail install` prints the manual start command
     instead of failing the whole install. A missing daemon does not fail the
     install; hook wiring (the actual security enforcement point via the
     Claude Code / Codex / Cursor hooks) does not depend on the daemon being
     up at install time.
4. **`agentjail uninstall`** mirrors this: `systemctl --user disable --now`
   plus removing the unit file, tolerating "not loaded" / "unit not found"
   gracefully, same as the existing launchd teardown tolerates "Could not
   find specified service".
5. **`agentjail status`** reports the platform-appropriate service path/label
   ("systemd unit" vs "launchd plist") and asks the platform-appropriate
   command whether the daemon is active (`systemctl --user is-active` vs
   `launchctl list`).
6. **`--allow-unsupported` becomes a deprecated no-op**, kept for back-compat
   with any existing scripts/docs that pass it, printing a one-line notice
   instead of gating.
7. **`install.sh`** no longer lets a non-zero `agentjail install` exit kill
   the script under `set -eu` — the call is now `... install || echo
   "⚠️ ... continuing setup"`. This matters independent of the Linux gate
   removal: a partial per-agent hook-wiring failure (already possible on
   macOS today) should not prevent the PATH setup and next-steps banner at
   the bottom of the script from running.

**Testability:** `systemdUserAvailableFn` and `systemctlUserEnableStartFn` /
`systemctlUserDisableStopFn` are package-level function variables (the same
pattern `currentGOOS` already uses to let tests simulate a platform without
recompiling). Tests stub these to assert call/no-call behavior without ever
shelling out to a real `systemctl --user` — important because CI and local dev
boxes may have a real systemd `--user` session with a real agent install.
`uninstallSystemdDaemon` additionally short-circuits before calling
`systemctlUserDisableStopFn` at all when no unit file exists, so uninstall
tests against an empty tmp `$HOME` never touch systemd regardless of stubbing.

## Consequences

- Linux users installing via `curl | sh` or a release tarball now get a
  running, self-recovering daemon (`Restart=always`) with no manual setup,
  matching the macOS experience.
- Environments without a systemd `--user` session (some containers, some CI)
  degrade gracefully: hooks are wired, the unit is written, and the install
  succeeds with a printed manual-start instruction rather than a hard failure.
  This is a deliberate asymmetry with macOS, where launchd is always present.
- `docs/adr/0007-windows-support-deferred.md` is unaffected — Windows remains
  explicitly out of scope; this ADR only resolves the Linux/macOS parity gap.
- Follow-up (not in this change): a `systemd --user` linger check/prompt
  (`loginctl enable-linger`) so the daemon survives after the user logs out,
  the way launchd's per-user `LaunchAgents` do implicitly. Left as a manual
  step in the printed instructions for now.

[ADR 0034]: ./0034-platform-backend-shared-contract.md
[ADR 0007]: ./0007-windows-support-deferred.md
