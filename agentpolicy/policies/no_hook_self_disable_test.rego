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

# ---------------------------------------------------------------------------
# A1: Allow read-only Bash ops on hook config dirs (no write indicators)
# ---------------------------------------------------------------------------

# cat on .codex dir → allow (read-only, no write indicator)
test_bash_cat_codex_rtk_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("cat /Users/dev/.codex/RTK.md")
}

# ls on .claude dir → allow (read-only)
test_bash_ls_claude_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("ls /Users/dev/.claude/")
}

# grep on .claude dir → allow (read-only)
test_bash_grep_claude_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("grep -r hooks /Users/dev/.claude/")
}

# rg (ripgrep) on .codex dir → allow (read-only)
test_bash_rg_codex_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("rg 'RTK' /Users/dev/.codex/")
}

# sed -n (print without in-place edit) on .claude → allow (read-only)
test_bash_sed_n_claude_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("sed -n '1p' /Users/dev/.claude/settings.json")
}

# head on .cursor config → allow (read-only)
test_bash_head_cursor_allows if {
	not agentjail.decision.action == "deny" with input as bash_hook("head -20 /Users/dev/.cursor/settings.json")
}

# ---------------------------------------------------------------------------
# A1: Still deny Bash commands with write indicators targeting hook config dirs
# ---------------------------------------------------------------------------

# cp (write indicator) to .claude dir → deny
test_bash_cp_to_claude_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("cp /tmp/settings.json /Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("cp /tmp/settings.json /Users/dev/.claude/settings.json")
}

# tee to .codex dir → deny
test_bash_tee_to_codex_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("echo 'x' | tee /Users/dev/.codex/config.toml")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("echo 'x' | tee /Users/dev/.codex/config.toml")
}

# redirect (>) to .claude dir → deny
test_bash_redirect_to_claude_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("echo '{}' > /Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("echo '{}' > /Users/dev/.claude/settings.json")
}

# sed -i on .cursor config → deny
test_bash_sed_i_cursor_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("sed -i 's/hooks//' /Users/dev/.cursor/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("sed -i 's/hooks//' /Users/dev/.cursor/settings.json")
}

# mv targeting .claude → deny
test_bash_mv_to_claude_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("mv /tmp/evil.json /Users/dev/.claude/settings.json")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("mv /tmp/evil.json /Users/dev/.claude/settings.json")
}

# dd targeting .codex → deny (note: also triggers no-dd-device-read if if=/dev/; use of=/dev/null to isolate)
# We test that the hook config write pattern fires by using dd without a device source
test_bash_dd_to_codex_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("dd bs=1 count=0 of=/Users/dev/.codex/config.toml")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("dd bs=1 count=0 of=/Users/dev/.codex/config.toml")
}

# rsync targeting .claude → deny
test_bash_rsync_to_claude_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("rsync -av /tmp/evil/ /Users/dev/.claude/")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("rsync -av /tmp/evil/ /Users/dev/.claude/")
}

# truncate targeting .codex → deny
test_bash_truncate_to_codex_denies if {
	agentjail.decision.action == "deny" with input as bash_hook("truncate -s 0 /Users/dev/.codex/config.toml")
	agentjail.decision.rule_id == hook_disable_rule_id with input as bash_hook("truncate -s 0 /Users/dev/.codex/config.toml")
}

# ---------------------------------------------------------------------------
# A1: Known false positive — cp with config as SOURCE still denied
# (cp matches write indicator regardless of direction)
# ---------------------------------------------------------------------------

# KNOWN FALSE POSITIVE: cp /Users/dev/.codex/config.toml /tmp/backup
# The cp pattern matches even when .codex is the source, not the destination.
# This is an accepted trade-off: we err on the side of safety.
test_bash_cp_from_codex_known_fp if {
	agentjail.decision.action == "deny" with input as bash_hook("cp /Users/dev/.codex/config.toml /tmp/backup")
}
