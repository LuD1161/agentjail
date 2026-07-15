# ADR 0060: single-instance guard for the daemon agent socket

**Status:** Accepted

## Context

`daemon.sock` (the agent-facing policy socket every hook connects to) was bound with a
blind `os.Remove` + `net.Listen` and no single-instance guard, so a second daemon - a
different install channel (Homebrew vs curl), a manual run, or an upgrade transition -
could unlink the incumbent's socket and double-bind: two daemons, one orphaned on an
unlinked inode, hooks split across them, and a fail-open window against a dying daemon.
The netproxy (`internal/netproxyapp/control.go`) and the daemon's grant control socket
(`internal/daemonapp/grantserver.go`) already used an flock + probe-before-remove
pattern; this bind site was the one that skipped it.

## Decision

Acquire an exclusive `flock` on `daemon.lock` (beside `*socketPath`, honoring `--socket`)
before binding, with a bounded ~1s retry to absorb a supervised-restart handoff. Replace
the blind unlink with `stat -> ControlOpPing probe -> remove-only-if-stale -> ListenUnix`,
treating `EADDRINUSE` as "lost the race, stand down." A healthy incumbent (valid ping) ->
stand down with `exit 0`; an unresponsive/foreign squatter -> `exit 1`. `exit 0` is chosen
so systemd's `StartLimit` never pins the unit `failed`, while launchd's `KeepAlive`
throttle self-heals. A new side-effect-free `wire.ControlOpPing` op backs the probe so a
bare `connect()` cannot be mistaken for a live daemon. The guard lives in
`internal/daemonapp/singleton.go` and is wired into `daemonapp.Run`, which returns the
exit code (0 stand-down / 1 fatal) rather than calling `os.Exit`.

## Consequences

Exactly one daemon owns the socket regardless of install method, and the upgrade handoff
is race-safe. Residual: on systemd, a manual/old incumbent that the service stood down to
and which later exits leaves no supervised daemon until the service is restarted - a
documented, dev-inflicted edge, to be surfaced later by an `agentjail doctor` version-drift
check (out of scope here). The launchd/systemd service definitions are unchanged.
