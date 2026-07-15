# 0070 — The supervisor must restart the daemon on a clean exit

Status: Accepted

## Context

The auto-updater swaps the daemon binaries and then exits 0, relying on the
service supervisor to start the replacement (`daemonapp.UpdateChecker`). This
is a deliberate design: the running process cannot re-exec itself over its own
binary safely, so "exit and let the supervisor bring back the new one" is the
handoff.

That contract was only ever honoured on macOS. The launchd plist sets
`KeepAlive=<true/>`, which restarts the job regardless of exit status. The
systemd unit used `Restart=on-failure`, which does **not** restart a clean
exit(0). ADR 0051, the `systemdUnitTemplate` comment, and the README all
asserted the two were equivalent. They are not.

Consequence on Linux: every auto-update permanently stopped the daemon. The
shield kept activating (it writes to the store on its own path, independent of
the daemon), so telemetry still showed activity while no decisions were
recorded and nothing surfaced the gap to the user — a silent unprotected
window.

## Decision

Both supervisors must restart the daemon on **any** exit, including exit 0:
launchd `KeepAlive=<true/>`, systemd `Restart=always` + `RestartSec=2`.

`Restart=always` does not fight an intentional stop: systemd does not
auto-restart a unit stopped via `systemctl --user stop`, which is how
`agentjail uninstall` and the stop path already work.

Per ADR 0034, the exit-0-handoff is a cross-platform contract, not a
per-backend detail. A supervisor that restarts only on failure does not
implement it, and drift here is a bug.

## Consequences

- The Linux daemon survives auto-update; parity with macOS is restored.
- Any future exit-and-be-restarted flow can rely on the handoff on both
  platforms.
- A genuine crash loop restarts forever rather than backing off. Accepted:
  ADR 0060's single-instance guard bounds concurrency, `RestartSec=2` bounds
  the rate, and `crash.log` is append-only across restarts. A daemon that
  stays down is strictly worse than one that restarts noisily — it silently
  disables enforcement.
- Pinned by `TestInstallSystemdUnitContent`, which rejects `Restart=on-failure`.

Related: ADR 0034 (platform contract), ADR 0050 (daemon-unreachable policy),
ADR 0051 (Linux install), ADR 0060 (daemon single-instance guard).
