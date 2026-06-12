# Package agentjail — CORE rule: no-hook-self-disable
#
# NOTE: The rule_id "library/no-hook-self-disable" retains its "library/" prefix
# for historical reasons (it was originally an opt-in library rule). The prefix
# is now purely cosmetic — this rule is always-on locked core, embedded in every
# install, and cannot be disabled. See resolver.rego locked_rules.
#
# WHAT IT BLOCKS
# --------------
# Writes (Write, Edit, or Bash redirect) to agent configuration files that
# control hook loading — thereby preventing the agent from disabling or
# bypassing agentjail's own hook enforcement:
#
#   ~/.claude/settings*.json         (Claude Code hook config)
#   ~/.codex/                        (Codex CLI config directory)
#   ~/.cursor/                       (Cursor editor config directory)
#   ~/.agentjail/policy.yaml        (agentjail policy — already in file_policy
#                                     core, but repeated here for clarity)
#   ~/.agentjail/rules/             (active rule directory)
#   ~/Library/LaunchAgents/com.agentjail.*  (agentjail daemon plist)
#
# WHY (attack scenario)
# ----------------------
# A prompt-injected or compromised agent could:
#   1. Overwrite ~/.claude/settings.json to remove the hooks.PreToolUse entry
#      so future tool calls skip policy evaluation entirely.
#   2. Write a new plist to LaunchAgents/ that replaces or kills the agentjail
#      daemon, removing the runtime policy check.
#   3. Clear ~/.agentjail/rules/ so the daemon loads no rules.
#
# This is a "hook self-disable" attack: the agent removes the very mechanism
# that limits its behaviour.
#
# ALWAYS ON (promoted from opt-in library to always-on locked core)
# -----------------------------------------------------------------
# This rule is active in every agentjail install without any configuration.
# It is locked in resolver.rego and cannot be disabled via policy.yaml or the CLI.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Write",
#    "tool_input":{"file_path":"/Users/dev/.claude/settings.json","content":"{}"},
#    "session_id":"s1","cwd":"/Users/dev/project"}

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: extract path from Write / Edit tool_input
# ---------------------------------------------------------------------------

_lib_hook_path := input.tool_input.file_path if {
	input.tool_input.file_path
}

_lib_hook_path := input.tool_input.path if {
	not input.tool_input.file_path
	input.tool_input.path
}

_lib_hook_path := input.tool_input.old_path if {
	not input.tool_input.file_path
	not input.tool_input.path
	input.tool_input.old_path
}

# Protected paths that control hook / daemon lifecycle.
_is_hook_config(p) if {
	# ~/.claude/settings*.json — Claude Code hook configuration
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.claude/settings[^/]*\.json$`, p)
}

_is_hook_config(p) if {
	# ~/.codex/ — Codex CLI config directory
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.codex(/|$)`, p)
}

_is_hook_config(p) if {
	# ~/.cursor/ — Cursor editor config directory
	regex.match(`^(/Users/[^/]+|/home/[^/]+|/root)/\.cursor(/|$)`, p)
}

_is_hook_config(p) if {
	# ~/Library/LaunchAgents/com.agentjail.* — daemon launchd plists
	regex.match(`^/Users/[^/]+/Library/LaunchAgents/com\.agentjail\.`, p)
}

# Note: ~/.agentjail/policy.yaml and ~/.agentjail/rules/ are intentionally
# omitted here. They are already covered by the core file_policy.rego
# is_sensitive_path rule (^/Users/[^/]+/\.agentjail(/|$)). Including them
# here would cause duplicate candidates for the same input — not a conflict
# error, but unnecessary noise. Users who opt in to this library rule get
# ~/.claude/settings*.json, ~/.codex/, ~/.cursor/, and
# ~/Library/LaunchAgents/com.agentjail.* coverage on top of core's
# ~/.agentjail/ coverage.

# ---------------------------------------------------------------------------
# Candidate: deny Write / Edit to hook config paths
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name in {"Write", "Edit"}
	p := _lib_hook_path
	_is_hook_config(p)
	msg := sprintf("write to hook/policy configuration %q is denied (library/no-hook-self-disable); self-disable risk", [p])
	r := {
		"action":  "deny",
		"rule_id": "library/no-hook-self-disable",
		"reason":  msg,
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny Bash commands that reference hook config paths
# Note: .agentjail is excluded here because command_policy.rego core already
# blocks Bash commands that mention ~/.agentjail via no-bash-touch-sensitive-path.
# Including it here would add a duplicate candidate — not harmful but redundant.
# ---------------------------------------------------------------------------

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
	c := input.tool_input.command
	regex.match(`(/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)/\.(claude|codex|cursor)\b`, c)
	r := {
		"action":  "deny",
		"rule_id": "library/no-hook-self-disable",
		"reason":  "Bash command references a hook/policy configuration directory; self-disable risk (library/no-hook-self-disable)",
	}
}
