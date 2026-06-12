# Tests for agentpolicy/policies/library/no_hook_self_disable.rego
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

hook_disable_rule_id := "library/no-hook-self-disable"

write_hook(fp) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Write",
	"tool_input": {"file_path": fp, "content": "{}"},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

edit_hook(fp) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Edit",
	"tool_input": {"file_path": fp, "old_string": "hooks", "new_string": "{}"},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

bash_hook(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.claude/settings.json
# ---------------------------------------------------------------------------

test_no_hook_write_claude_settings if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/.claude/settings.json")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.claude/settings.local.json (glob: settings*.json)
# ---------------------------------------------------------------------------

test_no_hook_write_claude_settings_local if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/.claude/settings.local.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/.claude/settings.local.json")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.codex/ directory
# ---------------------------------------------------------------------------

test_no_hook_write_codex if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/.codex/config.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/.codex/config.json")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.cursor/ directory
# ---------------------------------------------------------------------------

test_no_hook_write_cursor if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/.cursor/extensions.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/.cursor/extensions.json")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/Library/LaunchAgents/com.agentjail.daemon.plist
# (replaces the ~/.agentjail/rules/ case which is already covered by core
#  file_policy/sensitive_credential and would cause eval_conflict_error here)
# ---------------------------------------------------------------------------

test_no_hook_write_launchagents_rules if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/Library/LaunchAgents/com.agentjail.shield.plist")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/Library/LaunchAgents/com.agentjail.shield.plist")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/Library/LaunchAgents/com.agentjail.daemon.plist
# ---------------------------------------------------------------------------

test_no_hook_write_launchagents_plist if {
	agentjail.decision.action == "deny" with input as write_hook("/Users/dev/Library/LaunchAgents/com.agentjail.daemon.plist")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/Users/dev/Library/LaunchAgents/com.agentjail.daemon.plist")
}

# ---------------------------------------------------------------------------
# Deny: Edit to ~/.claude/settings.json
# ---------------------------------------------------------------------------

test_no_hook_edit_claude_settings if {
	agentjail.decision.action == "deny" with input as edit_hook("/Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as edit_hook("/Users/dev/.claude/settings.json")
}

# ---------------------------------------------------------------------------
# Deny: Bash command touching .claude directory
# ---------------------------------------------------------------------------

test_no_hook_bash_claude_dir if {
	agentjail.decision.action == "deny" with input as bash_hook("cp /tmp/settings.json /Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("cp /tmp/settings.json /Users/dev/.claude/settings.json")
}

# ---------------------------------------------------------------------------
# Not deny: Write to ~/Documents/notes.json (not a hook config)
# ---------------------------------------------------------------------------

test_no_hook_documents_not_denied if {
	not agentjail.decision.action == "deny" with input as write_hook("/Users/dev/Documents/notes.json")
}

# ---------------------------------------------------------------------------
# Not deny: Write to project-level settings file (unrelated)
# ---------------------------------------------------------------------------

test_no_hook_project_settings_not_denied if {
	not agentjail.decision.action == "deny" with input as write_hook("/Users/dev/project/config/settings.json")
}

# ---------------------------------------------------------------------------
# Linux home path coverage (plan 002)
# ---------------------------------------------------------------------------

test_no_hook_linux_home_claude_settings_denied if {
	agentjail.decision.action == "deny" with input as write_hook("/home/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as write_hook("/home/dev/.claude/settings.json")
}
