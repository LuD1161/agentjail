# ADR 0063: the PATH shim fails open, and uninstall removes every setting install wrote

**Status:** Accepted

## Context

Two gaps, both reachable from an ordinary install/uninstall cycle, and both landing on the
user's `claude` rather than on agentjail.

### The shim could brick claude

The PATH shim sits ahead of the real `claude`, so every failure mode of the shim is a
failure mode of the user's `claude`. It ended in an unconditional
`exec "<shield>" -- "$REAL_CLAUDE" "$@"`. When the shield binary was absent, `exec` failed
and the shell exited 127:

```
/home/u/.agentjail/bin/claude: exec: /home/u/.agentjail/bin/agentjail-shield: not found
```

`claude` was dead, with a cryptic message naming a binary the user never installed by hand.
Reaching this needs no exotic state: an interrupted upgrade, a partial or failed
`removeInstallDir`, a quarantined/corrupt binary, or a dangling
`agentjail-shield -> agentjail` role symlink whose target was removed.

This also contradicted a principle the codebase had already committed to. From
`shield_hook_reassert.go`: "refusing to launch over a settings-file write failure would
brick every session for a problem the daemon's live hookwatch watcher and the next shield
launch can also still repair. Fail-closed here would turn a self-protection nicety into a
new denial-of-service surface." The shim is that same Tier-1.5 convenience layer and had
the opposite behavior.

### Uninstall left a setting pointing at a deleted binary

`ClaudeCode.Install` writes two things into `~/.claude/settings.json`: the PreToolUse hook
entry and the `statusLine` entry (`claudeMergeStatusLineEntry`). `ClaudeCode.Uninstall`
removed only the hook. Uninstall therefore deleted `~/.agentjail` while leaving:

```json
"statusLine": { "type": "command", "command": "/home/u/.agentjail/bin/agentjail statusline --chain cship" }
```

Worse than a dangling reference: the merge preserves a pre-existing foreign statusline by
chaining it (`--chain cship`). Uninstall never handed it back, so a user who had their own
statusline lost it — agentjail deleted the binary that was the only remaining reference to
their original command.

Uninstall was otherwise thorough (agent hooks, daemon/launchd/systemd units, secrets broker,
IDE wrappers, shim, role symlinks, `~/.agentjail`, rc PATH blocks per ADR 0062, brew), which
is what made this single omission easy to miss.

## Decision

**The shim fails open.** Before exec'ing, it tests `[ -x "$SHIELD" ]` (which follows
symlinks, so it also catches a dangling role symlink). If the shield is missing or not
executable, it warns on stderr — naming the path, stating that claude is running UNSHIELDED,
and giving both the repair and removal commands — then `exec`s the real claude directly.
The shield path is bound once at the top of the script.

The pre-existing hard failures are kept: no real claude on PATH (exit 127) and shim
self-resolution (exit 1). Neither has a claude to fall through to, so there is nothing to
fail open onto.

**Uninstall inverts every write.** `claudeRemoveStatusLineEntry` mirrors
`claudeMergeStatusLineEntry`: a statusLine that is structurally ours and carries
`--chain <cmd>` is replaced by `<cmd>` verbatim; ours with no chain is deleted outright; a
foreign statusLine is left untouched. `ClaudeCode.Uninstall` now applies it alongside the
hook removal.

## Consequences

Installing and uninstalling agentjail can no longer break `claude`. A broken or half-removed
agentjail degrades to "claude runs, unshielded, loudly" instead of "claude does not run" —
and `agentjail uninstall` returns `~/.claude/settings.json` to its prior state, statusline
included.

Fail-open is a deliberate security trade: a user whose shield binary vanishes silently loses
kernel-level enforcement and keeps running. It is not silent (stderr warning every launch)
and not unguarded (the Tier-1 hook still applies and independently warns "this session is
not running under shield"). The alternative — refusing to launch — makes agentjail a
denial-of-service on the user's primary tool, which is the worse trade for this tier and is
already settled policy per ADR 0025 / `shield_hook_reassert.go`. Tiers that must fail closed
(credentials, policy) are unaffected.

Statusline restoration is verbatim and unconditional: if the user changed their statusline
after install such that agentjail's chained copy is stale, uninstall restores the stale
command. Preferring the recorded original over silently dropping it is the lesser harm, and
a foreign statusline set after install is not structurally ours, so it is left alone.

Remaining, out of scope here: the shim only covers profile-sourcing interactive shells (VS
Code uses `claudeProcessWrapper`; cron, non-interactive shells, and absolute-path
invocations are uncovered). Universal coverage is verified activation (draft ADR 0029).
