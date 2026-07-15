# ADR 0065: uninstall stops the daemon before unhooking, and verifies it stopped

**Status:** Accepted

## Context

A real uninstall on a developer box reported total success:

```
Claude Code   ✓ unhooked
Codex         ✓ unhooked
daemon        ✓ stopped and systemd unit removed
~/.agentjail  ✓ removed
✓ agentjail fully removed
```

Every claim about the agents and the daemon was false. Afterwards,
`~/.claude/settings.json` and `~/.codex/hooks.json` both still contained a PreToolUse entry
pointing at `~/.agentjail/bin/agentjail-hook` — a binary the same run had just deleted — and
the daemon was still running with its executable unlinked (`/proc/<pid>/exe` → `(deleted)`).

The daemon's own log, still readable through its open fd, showed the mechanism:

```
18:02:23.811 WARN hookwatch: agentjail hook removed from config   agent=claude-code
18:02:23.815 WARN hookwatch: re-injected agentjail hook           hook_bin=~/.agentjail/bin/agentjail-hook
18:02:23.816 WARN hookwatch: agentjail hook removed from config   agent=codex
18:02:23.818 WARN hookwatch: re-injected agentjail hook           agent=codex
```

Four milliseconds. `hookwatch` (ADR 0026) exists to re-inject the hook when a
prompt-injected agent deletes it from an agent-writable config. It cannot distinguish
tampering from a legitimate uninstall, so **the anti-tamper mechanism reverted the
uninstall**.

Two independent defects combined:

1. **Ordering.** `performFullUninstall` unhooked every agent at step 1 and only tore the
   daemon down at step 2. Even on a correctly systemd-managed box that is a race: the
   window between unhook and stop is exactly when hookwatch fires.
2. **Unverified stop.** The teardown shells out to `launchctl unload` / `systemctl --user
   disable --now` and treats a clean exit as "stopped". Per ADR 0061, a service manager
   answers "is the unit active?", not "is a daemon reachable?" — and it can only stop
   daemons it owns. This daemon was started by hand, so the stop was a silent no-op, and on
   this box `systemctl --user` cannot work at all (no D-Bus session). The window was not a
   race here; it was permanent.

The result is worse than an incomplete uninstall: agentjail is gone from disk, but every
future Claude Code and Codex session still tries to exec a deleted hook binary, and the
summary told the user everything was fine.

## Decision

**Stop the daemon first.** Daemon teardown moves ahead of the agent unhook, so nothing is
alive to re-inject behind the teardown. This closes the race by construction rather than
narrowing it.

**Verify the stop.** After the service manager returns, `waitForDaemonStop` polls
`isDaemonRunning()` (the ADR 0061 socket probe) for up to 3s. A daemon still answering means
the stop did not happen, regardless of what the service manager reported.

**Never claim what did not happen.** `UninstallResult.DaemonStillRunning` marks the run as
hard-failed and the summary says so plainly — that the daemon was not started by the service
manager and therefore was not stopped, that it will re-inject hooks until killed, and how to
kill it. The previous "✓ stopped and systemd unit removed" is only printed when the socket
is actually dead.

## Consequences

Uninstall no longer fights itself, and no longer lies about the outcome. Once the daemon is
genuinely stopped, teardown is total: `~/.agentjail`, both rc PATH blocks (ADR 0062), the
hook entries, and the statusLine with any chained command restored (ADR 0063) — verified
end-to-end on the box where this was found.

An unmanaged daemon now fails the uninstall instead of being silently worked around. This is
intentional — a partial teardown that says so is strictly better than a total one that
isn't — but it means a developer who starts daemons by hand must kill them before
uninstalling, and `--keep-secrets`-style unattended flows will surface a new hard failure
where they previously (wrongly) reported success.

Uninstall still cannot *stop* a daemon it does not own; it can only detect and report. The
complete fix is a `wire.ControlOpShutdown` on the existing control socket (ADR 0060 already
established the socket and `ControlOpPing`), letting uninstall ask any daemon to exit
gracefully regardless of who started it — no PID hunting, no signals, no per-OS code. That
is deferred: it needs a daemon-side handler and its own auth consideration, since a shutdown
op is a denial-of-service primitive if reachable by a sandboxed agent.

hookwatch's inability to distinguish uninstall from tampering is left as-is. Ordering makes
the distinction unnecessary, and teaching hookwatch about an "uninstall in progress" state
would add a bypass flag to an anti-tamper control — a worse trade than sequencing the
teardown correctly.
