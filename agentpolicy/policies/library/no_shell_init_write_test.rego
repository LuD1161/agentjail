# Tests for agentpolicy/policies/library/no_shell_init_write.rego
#
# All tests use the hook-wire-format input shape (HookInput from engine.go).
# Helper functions construct canonical inputs; tests use `with input as`.
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

shell_init_rule_id := "library/no-shell-init-write"

write_init(fp) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Write",
	"tool_input": {"file_path": fp, "content": "export BAD=1"},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

edit_init(fp) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Edit",
	"tool_input": {"file_path": fp, "old_string": "a", "new_string": "b"},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

bash_init(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.zshrc
# ---------------------------------------------------------------------------

test_no_shell_init_write_zshrc if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.zshrc")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.zshrc")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.bashrc
# ---------------------------------------------------------------------------

test_no_shell_init_write_bashrc if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.bashrc")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.bashrc")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.bash_profile
# ---------------------------------------------------------------------------

test_no_shell_init_write_bash_profile if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.bash_profile")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.bash_profile")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.profile
# ---------------------------------------------------------------------------

test_no_shell_init_write_profile if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.profile")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.profile")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.zprofile
# ---------------------------------------------------------------------------

test_no_shell_init_write_zprofile if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.zprofile")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.zprofile")
}

# ---------------------------------------------------------------------------
# Deny: Write to ~/.zshenv
# ---------------------------------------------------------------------------

test_no_shell_init_write_zshenv if {
	agentjail.decision.action == "deny" with input as write_init("/Users/dev/.zshenv")
	agentjail.decision.rule_id == shell_init_rule_id with input as write_init("/Users/dev/.zshenv")
}

# ---------------------------------------------------------------------------
# Deny: Edit to ~/.bashrc
# ---------------------------------------------------------------------------

test_no_shell_init_edit_bashrc if {
	agentjail.decision.action == "deny" with input as edit_init("/Users/dev/.bashrc")
	agentjail.decision.rule_id == shell_init_rule_id with input as edit_init("/Users/dev/.bashrc")
}

# ---------------------------------------------------------------------------
# Deny: Bash redirect to ~/.bashrc (echo >> pattern)
# ---------------------------------------------------------------------------

test_no_shell_init_bash_redirect_bashrc if {
	agentjail.decision.action == "deny" with input as bash_init("echo 'export PATH=$PATH:/evil' >> /Users/dev/.bashrc")
	agentjail.decision.rule_id == shell_init_rule_id with input as bash_init("echo 'export PATH=$PATH:/evil' >> /Users/dev/.bashrc")
}

# ---------------------------------------------------------------------------
# Not deny by shell-init rule: Write to ~/.config/zsh/foo (not an init file).
# NOTE: file_policy/sensitive_credential may still deny this (it's in ~/.config/)
# — we only check that no_shell_init_write itself doesn't produce the verdict.
# ---------------------------------------------------------------------------

test_no_shell_init_config_subdir_not_denied if {
	d := agentjail.decision with input as write_init("/Users/dev/.config/zsh/foo.zsh")
	d.rule_id != "library/no-shell-init-write"
}

# ---------------------------------------------------------------------------
# Not deny: Write to a normal project file
# ---------------------------------------------------------------------------

test_no_shell_init_project_file_not_denied if {
	not agentjail.decision.action == "deny" with input as write_init("/Users/dev/project/setup.sh")
}

# ---------------------------------------------------------------------------
# Not deny: Bash command that doesn't touch init files
# ---------------------------------------------------------------------------

test_no_shell_init_bash_safe_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_init("echo 'hello world'")
}
