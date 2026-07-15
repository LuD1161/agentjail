# ADR 0064: the status line always attests, because stderr does not survive

**Status:** Accepted

## Context

`agentjail statusline` rendered the `secured by agentjail` byline only when
`AGENTJAIL_SHIELDED=1`, and rendered **nothing** otherwise. An unprotected session was
therefore indistinguishable from a protected one: same status line, minus a badge nobody
was looking for.

This was defended (in review) as acceptable because the unprotected state is already
announced elsewhere:

- `agentjail-hook` prints "⚠ agentjail: this session is not running under shield".
- The PATH shim, on a missing shield binary, prints "Running claude UNSHIELDED" (ADR 0063).

Both write to stderr at launch, and both are swallowed. Claude Code takes over the terminal
on startup; anything printed before or during that scrolls away and is never seen again. The
hook's warning fires per tool call but is rendered inside a collapsed tool-result block. The
status line is the only surface that is persistently visible for the life of the session, so
it is the only channel that can carry this signal — which makes silence there the worst
possible default: it reads as "fine".

This corrects an earlier framing that treated the badge as cosmetic. It cannot be a
security *attestation* — `statusLine` lives in agent-writable `~/.claude/settings.json`, so
anything able to forge the env var could rewrite the command outright (the same exposure
that motivates `shield_hook_reassert.go`). But it is the primary *notification* channel, and
it was failing at that job.

## Decision

`shieldBadge()` always returns a badge. Two states, keyed on shield activation only:

- `AGENTJAIL_SHIELDED=1` → `🔒 [secured by agentjail (<version>)]`
- anything else → `⚠ [UNSECURED · agentjail]`

Exactly `"1"` counts; no other value is an activation record.

The badge keys on shield activation rather than daemon reachability because it attests
kernel-level enforcement, which is what `AGENTJAIL_SHIELDED` records (ADR 0061 established
that daemon liveness is a socket probe — a separate fact, surfaced by `agentjail status` and
`doctor`, not by this badge). A shielded session with a dead daemon is still shielded.

Rendering nothing is reserved for "agentjail is not installed", and needs no code: uninstall
removes the `statusLine` entry and restores any chained statusline (ADR 0063), so this
binary is not invoked at all. Three visible states — secured, unsecured, absent — with only
two of them in this function.

Chained statuslines are unaffected: the badge is prepended, the chained command's output
follows.

## Consequences

An unprotected session is now visibly unprotected for its entire duration, on the one
surface that survives Claude Code's terminal takeover. This is the fix for the failure mode
in ADR 0062 (a silently dangling PATH shim) that no amount of stderr warning could reach.

Every user who installed the statusLine entry and runs claude outside the shield now sees a
red `UNSECURED` badge where they previously saw nothing. That is intended and is the point
of the change, but it is a visible, unrequested change in a surface users look at constantly
— and for anyone who deliberately runs unshielded, it is permanent chrome with no dismissal.
Accepted: the alternative is a security tool that stays quiet about not protecting you.

Two states were chosen over naming the cause (`no shield` vs `daemon down`) to keep the
badge to one glanceable fact. The cost is that `UNSECURED` does not say why; `agentjail
doctor` does, and the badge does not try to replace it.
