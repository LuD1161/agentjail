# macOS build 1282 lifecycle acceptance — 2026-09-24

## Result

**Not a complete release-gate pass.** The installed policy smoke scenario passed
19 checks with zero failures or skips after correcting its obsolete assumption
that fresh installations enforce policy. The separate app/CLI lifecycle run
completed 105 assertions: 89 passed and 16 failed, grouped into the two remaining
issues below. No product binaries were changed during this run.

## Candidate and environment

- App and extension: version `1.9.0`, build `1282`.
- Binary source: `61a2e8e7487ea76f981aa4ba00c56533df88502f`.
- DMG SHA-256: `4f22d3e408c584a0d5b95fc4ccbde483372c1e167e9b017e819668cd335843f9`.
- Harness baseline: `9cfc80f5`; corrected smoke fixture accompanies this report.
- Disposable Tart VM: `tb-lifecycle-1282-e2e`, cloned from
  `golden-macos-mitm`, 4 GiB RAM; macOS 15.7.7 (24G720), Apple Silicon.
- SIP and Gatekeeper assessments enabled. The installed app was accepted as
  `Notarized Developer ID` with team `Q98Z3744J2`.
- Installed Codex CLI: `0.148.0`, selected by the existing gate's host-version
  discovery. No authenticated live vendor session was run.

The standard gate installed the exact notarized DMG through `install.sh` and
started the daemon successfully. Its first smoke run reported 13 passes and
three failures because it expected deny responses under the new monitor default.
The corrected scenario first requires a fresh durable `allow` / `would_action:
deny` record, then explicitly enables enforcement and requires a fresh durable
deny after acknowledged reload. It restores the original policy byte-for-byte
and re-attests monitor behavior. That installed-binary rerun passed 19/19.

The corrected standalone scenario is not a successful rerun of the complete
gate. Later native-approval, credentialed-CLI, and tunnel scenarios were not run.
The clone retained its golden's legacy extension `0.0.6/6`; build 1282 extension
activation was not requested or approved. No tunnel acceptance is claimed.

## Lifecycle coverage

The bounded Python acceptance runner used the real packaged app, bundled CLI,
installed CLI, daemon and launchd services. It created disposable Claude, Codex
and Cursor configuration fixtures; it did not start those clients. Two native
app launches used the executable in `/Applications/AgentJail.app`.

Passing checks established:

- Bundled and installed CLIs recognize matching payloads and reuse the running
  daemon without changing its PID or replacing the policy.
- Launching the native app adopts the existing installation without restarting
  the daemon.
- Uninstall stops/removes services and detaches owned hooks while preserving
  foreign commands, shared-group fields and extra configuration fields.
- All eleven previously captured hook commands and both status-line commands
  execute after uninstall with neutral responses and no stderr; status lines
  are quiet. Ordinary commands through the retired CLI fail as intended.
- Reopening the app recognizes explicit removal and does not restart the daemon
  or replace the uninstall receipt/compatibility responders.
- Explicit reinstall restores matching payloads and exactly one registration
  per owned event, clears the receipt and starts a healthy daemon. A subsequent
  install adopts that daemon without restarting it.
- Foreign hook command strings remain present after reinstall.

After a guest restart, the installed daemon was running and direct guest HTTPS
returned 200. This is basic restart/connectivity evidence, not a required-tunnel
or UI acceptance result. The DMG was supplied locally; no browser-download
quarantine or App Translocation acceptance is claimed.

## Remaining issues observed

1. **Status inspection recreates state after explicit uninstall.** The immediate
   teardown left only the two compatibility responders and `uninstalled.json`.
   Subsequent status/app inspection created `telemetry.json` and
   `update-check.timestamp`. A separate bounded check reproduced both files
   with only the bundled `status --json`, before any app launch, even with
   `AGENTJAIL_SEND_ANONYMOUS_USAGE_STATS=false`.
   The responder/receipt hashes stayed unchanged and the daemon remained absent,
   but the stricter minimal-retirement contract failed one assertion.
   The CLI root pre-run invokes telemetry consent initialization and update-check
   bookkeeping; the app uses this same status command.
2. **Codex/Cursor reinstall drops additional configuration fields.** Fifteen
   assertions found loss of synthetic unknown top-level, hook-entry and Codex
   matcher-group fields. Foreign command strings survived; Claude's extra fields
   and Cursor's separate CLI settings survived. This demonstrates lossless-merge
   gaps, not disappearance of all settings or loss of the foreign commands.

The second run deliberately continued after the extra-state finding so every
reinstall assertion executed. Its final result is `complete: true`,
`passed: false`; no failed assertion was converted to a pass.

## Evidence and cleanup

Private local evidence is retained alongside the build under `build/e2e-1282/`
in the `build-lifecycle-1282` worktree: the runner, result JSON, extra-state file
list and bounded run logs. Raw guest configuration/process captures remain in
the disposable VM and are not committed. Authentication was confirmed absent
from the guest after testing. Repository build, vet, full Go tests and smoke
checks passed for the fixture change; the local smoke suite retained its existing
missing-netproxy-listener skip. It is separate from the 19/19 VM scenario.

The disposable VM was stopped with a healthy reinstalled build 1282. The host
installation and golden image were not modified. The previously running
build-1281 VM was stopped temporarily with user authorization and restarted
after the checks.
