package agentjail_no_daemon_kill_test

import future.keywords.if
import data.agentjail

bash_input(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd, "description": ""},
	"session_id": "test-session",
	"cwd":        "/Users/dev/project",
}

# Single-line form still denies (regression guard for the existing behavior).
test_pkill_single_line_deny if {
	d := agentjail.decision with input as bash_input("pkill -f agentjail-daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

# THE BUG: newline-split form must now deny.
test_pkill_newline_split_deny if {
	d := agentjail.decision with input as bash_input("pkill -f\nagentjail-daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

test_killall_newline_split_deny if {
	d := agentjail.decision with input as bash_input("killall\nagentjail-hook")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

test_launchctl_newline_split_deny if {
	d := agentjail.decision with input as bash_input("launchctl stop\ncom.agentjail.daemon")
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

# A benign pkill of an unrelated process must NOT be denied by this rule.
test_unrelated_pkill_not_denied_by_this_rule if {
	d := agentjail.decision with input as bash_input("pkill -f my-dev-server")
	d.rule_id != "library/no-daemon-kill"
}
