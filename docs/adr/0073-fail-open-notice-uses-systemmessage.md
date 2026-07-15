# 0073 — The fail-open notice must ride systemMessage, not stderr

Status: Accepted (amends ADR 0050)

## Context

ADR 0050 replaced the one-shot, sentinel-gated fail-open warning with a loud
banner printed on *every* fail-open occurrence, to fix silent protection drift.
The banner goes to **stderr**, and the hook then exits **0** to allow the call.

Claude Code does not show hook stderr on exit 0. Per the hooks documentation,
exit 0 sends both stdout and stderr to the **debug log only**; stderr reaches
the user just on exit 2 (fed back to Claude) or another non-zero exit (shown as
a hook error). So on the one path that matters — fail-open **allow** — the
banner went to a stream nobody reads. ADR 0050's fix was never visible.

This is not theoretical. AGE-212: the daemon exited cleanly on 2026-07-10 and
was not restarted until 07-14. The build in use predated neither ADR 0050 nor
the shield's hook re-assert, so the banner *was* firing — on every tool call,
for three days, into the debug log. The user worked through the whole window
unprotected, committing daily, and noticed nothing. The `decisions` table
stayed empty while `shield.activated` kept climbing, which is why the gap was
eventually found in a metrics review rather than at the time.

The deny path was always fine: level=deny exits 2, and stderr on exit 2 is
shown. Only the allow paths (level=allow, and degraded-with-no-rule-match) were
mute.

## Decision

Carry the fail-open notice in the `systemMessage` field of the hook's JSON
response, which Claude Code renders in the normal TUI on an exit-0 allow.

- `writeAllowWithSystemMessage` sets it; plain `writeAllow` (the normal,
  daemon-answered allow) passes "" and is unchanged — no banner on the
  healthy path.
- The stderr banner stays. It costs nothing, and it is what Codex (its own
  convention, no JSON allow response) and `--debug` users get.
- Deny paths are untouched: exit 2 already surfaces stderr.

## Consequences

- A daemon-down window is now visible to the user on every tool call, which is
  what ADR 0050 intended and did not achieve.
- The notice is per-occurrence and will be repetitive during an outage. That is
  deliberate: the failure mode this exists to prevent is a silent window that
  lasts for days.
- Cursor already had a message channel on its allow response
  (`writeCursorAllowWithMessage`) and is unaffected. Codex still relies on
  stderr — its hook contract has no equivalent field; a Codex user in a
  daemon-down window remains under-warned. Tracked separately.
- Any future user-facing notice on an exit-0 hook path must use
  `systemMessage`. Writing it to stderr is the same bug.

Refs: AGE-212. Amends ADR 0050 (daemon-unreachable policy). Related: ADR 0072.
