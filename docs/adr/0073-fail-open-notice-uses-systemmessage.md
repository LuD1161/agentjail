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

This is not theoretical. It was found in a real multi-day window: the daemon
exited cleanly, was not restarted, and the banner fired on every tool call for
three days straight — into the debug log. Work continued unprotected the whole
time and nothing surfaced it. `decisions` stayed empty while `shield.activated`
kept climbing, so the gap was eventually caught in a metrics review rather than
at the time it opened.

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
  (`writeCursorAllowWithMessage`) and is unaffected.
- Codex documents `systemMessage` as supported for PreToolUse and surfaces it
  as a warning, so it gets the notice too. Its allow convention is an empty
  stdout, so the fail-open response carries **only** `systemMessage` — no
  `permissionDecision`, which keeps default-allow semantics, and none of
  Claude's `hookSpecificOutput`, which Codex does not read. Normal Codex
  allows still write nothing at all.
- Any future user-facing notice on an exit-0 hook path must use
  `systemMessage`. Writing it to stderr is the same bug.

Amends ADR 0050 (daemon-unreachable policy). Related: ADR 0072.
