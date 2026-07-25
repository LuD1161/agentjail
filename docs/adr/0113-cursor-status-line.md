# ADR 0113: Cursor command status line

**Status:** Accepted

**Amends:** [ADR 0063-shim-fails-open-uninstall-is-total](./0063-shim-fails-open-uninstall-is-total.md),
[ADR 0064-statusline-always-attests](./0064-statusline-always-attests.md)

## Context

AgentJail installed its persistent protection badge only in Claude Code. Cursor CLI now
exposes the same command-based status-line model in `~/.cursor/cli-config.json`: it runs a
configured command after conversation updates, sends session JSON on stdin, and displays
stdout above the prompt.

Replacing a user's existing command would destroy unrelated configuration. Appending it as
plain command-line text is also lossy: quoted arguments, pipes, and redirects cannot survive
whitespace splitting or be recovered verbatim during uninstall.

Codex also exposes `/statusline`, but its `tui.status_line` setting is a closed ordered list
of built-in item identifiers. It cannot run an external command, so it cannot host the
AgentJail badge through its native footer.

## Decision

`Cursor.Install` owns the `statusLine.command` value in `~/.cursor/cli-config.json`:

- With no existing status line, configure
  `'<agentjail>' statusline --integration cursor`; the quoted path supports homes with spaces
  and the marker makes ownership independent of path parsing.
- Preserve an existing foreign command as unpadded base64 behind
  `--chain-base64`; `agentjail statusline` decodes it and executes it through `/bin/sh -c`
  with Cursor's stdin payload.
- Refresh an existing AgentJail command without nesting another wrapper.
- Preserve documented sibling fields such as padding, interval, and timeout.

`Cursor.Uninstall` inverts the write. It removes an unchained AgentJail entry, restores a
chained command byte-for-byte, and leaves foreign entries untouched. Malformed configuration
is rejected before hook installation mutates `hooks.json`.

Codex receives shield activation through its PATH shim. AgentJail does not rewrite
`tui.status_line` because none of its supported identifiers can truthfully report shield
and daemon state.

## Consequences

Cursor CLI now displays the same three-state badge as Claude Code, and the badge inherits
`AGENTJAIL_SHIELDED` when Cursor is launched through the PATH shim.

Cursor configuration gains the same ownership and total-uninstall guarantees as Claude
Code. Chained commands retain shell semantics instead of being reduced to argv tokens.

Codex remains without a persistent AgentJail footer badge until it supports custom status
commands. Its PATH shim still activates the shield, and hooks continue to enforce policy;
AgentJail does not present a built-in Codex field as equivalent protection evidence.
