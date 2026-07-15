# ADR 0061: daemon liveness is a socket probe, not a service-manager query

**Status:** Accepted

## Context

`agentjail status` reported `daemon ✗ not running` on a machine where the daemon was
demonstrably live: the process was up and `agentjail policy list` round-tripped through
`~/.agentjail/daemon.sock` normally.

`isDaemonRunning()` (`cmd/agentjail/install.go`) asked the platform service manager —
`launchctl list <label>` on macOS, `systemctl --user is-active <unit>` on Linux. That
answers "is the *unit* active?", which is a different question from "is a daemon
reachable?". The two disagree in ordinary, non-exotic situations:

- **Daemon not owned by a unit.** A daemon started by hand, by a test harness, or by
  `agentjail run` serves correctly but belongs to no unit, so the service manager calls
  it inactive and status contradicts a working install.
- **No D-Bus session.** `systemctl --user` needs one. In a bare container, an SSH session
  with no lingering user manager, or a cron/CI context, `XDG_RUNTIME_DIR` is unset and
  every call fails `Failed to connect to bus: No medium found` — indistinguishable from a
  dead daemon. `install` already tolerates this case (writes the unit, prints manual start
  instructions rather than failing); `status` did not.

Both fired on the reporting machine at once: no D-Bus session *and* a hand-started daemon.

The adjacent alternative — stat'ing the socket file, as the secrets-broker row does —
is also wrong here: a daemon that crashes leaves its socket file behind, so file existence
reports a dead daemon as running. ADR 0060 relies on exactly this (probe before removing a
socket that may be stale).

Deriving liveness from the OS-level sandbox state is not available either: Landlock exposes
no introspection API (no `/proc/self/landlock`; `/proc/self/status` carries `Seccomp` and
`NoNewPrivs` but nothing for Landlock), and macOS `sandbox_check()` requires cgo, which the
`CGO_ENABLED=0` release build forbids (ADR 0058).

## Decision

`isDaemonRunning()` dials `wire.DefaultSocketPath()` with a 200ms timeout and reports
whether the connection succeeds — the same socket every other client uses, and the same
probe shape as `sandbox.brokerReachable`.

Dialing distinguishes a live listener from a stale inode (`connect()` on an unbound socket
returns `ECONNREFUSED`), and answers the question status actually asks. Because a Unix
socket dial behaves identically on Linux and macOS, this replaces the per-OS
launchctl/systemctl split with a single code path: no `currentGOOS` branch, no subprocess.

The 200ms timeout only caps the pathological case (kernel accept queue full) so `status`
can never hang; a healthy local answer arrives in well under a millisecond.

The separate "systemd unit" / "launchd plist" row above continues to report
service-definition state, so the two facts stay distinct rather than conflated.

## Consequences

`status` now reports daemon reachability truthfully regardless of who started the daemon or
whether a service manager is reachable — including headless SSH, containers, and CI. One
fewer per-OS branch, and no `exec` on the status path.

A hand-started daemon now shows `daemon ✓ running` alongside its service row, i.e. visibly
running-but-unmanaged. That is the honest reading of the state, but it does mean `status`
alone no longer implies the daemon will survive a reboot; surfacing that drift belongs to
`agentjail doctor` (same follow-up noted in ADR 0060, still out of scope).

A daemon that is live but wedged (accepting but not serving) reports as running. Detecting
that needs a `wire.ControlOpPing` round-trip rather than a bare `connect()`; not adopted
here to keep the status path free of protocol coupling, and because the wedged case is not
the reported failure. ADR 0060's stand-down probe already pings where correctness demands it.
