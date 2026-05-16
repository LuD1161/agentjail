# Tests for agentpolicy/policies/library/no_launchctl.rego
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

launchctl_rule_id := "library/no-launchctl"

bash_lctl(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# Deny: launchctl load
# ---------------------------------------------------------------------------

test_no_launchctl_load if {
	agentjail.decision.action == "deny" with input as bash_lctl("launchctl load ~/Library/LaunchAgents/com.evil.plist")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("launchctl load ~/Library/LaunchAgents/com.evil.plist")
}

# ---------------------------------------------------------------------------
# Deny: launchctl submit
# ---------------------------------------------------------------------------

test_no_launchctl_submit if {
	agentjail.decision.action == "deny" with input as bash_lctl("launchctl submit -l com.evil -p /tmp/evil.sh")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("launchctl submit -l com.evil -p /tmp/evil.sh")
}

# ---------------------------------------------------------------------------
# Deny: launchctl bootstrap
# ---------------------------------------------------------------------------

test_no_launchctl_bootstrap if {
	agentjail.decision.action == "deny" with input as bash_lctl("launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/foo.plist")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/foo.plist")
}

# ---------------------------------------------------------------------------
# Deny: launchctl kickstart
# ---------------------------------------------------------------------------

test_no_launchctl_kickstart if {
	agentjail.decision.action == "deny" with input as bash_lctl("launchctl kickstart -k gui/501/com.evil.agent")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("launchctl kickstart -k gui/501/com.evil.agent")
}

# ---------------------------------------------------------------------------
# Deny: osascript -e '...' (any invocation is suspicious)
# ---------------------------------------------------------------------------

test_no_launchctl_osascript_e if {
	agentjail.decision.action == "deny" with input as bash_lctl("osascript -e 'tell application \"Finder\" to open location \"https://evil.example\"'")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("osascript -e 'tell application \"Finder\" to open location \"https://evil.example\"'")
}

# ---------------------------------------------------------------------------
# Deny: osascript --version (any invocation — no safe subset)
# ---------------------------------------------------------------------------

test_no_launchctl_osascript_version if {
	agentjail.decision.action == "deny" with input as bash_lctl("osascript --version")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("osascript --version")
}

# ---------------------------------------------------------------------------
# Deny: at now + job creation
# ---------------------------------------------------------------------------

test_no_launchctl_at_now if {
	agentjail.decision.action == "deny" with input as bash_lctl("echo '/tmp/evil.sh' | at now")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("echo '/tmp/evil.sh' | at now")
}

# ---------------------------------------------------------------------------
# Deny: at +1 minute
# ---------------------------------------------------------------------------

test_no_launchctl_at_plus if {
	agentjail.decision.action == "deny" with input as bash_lctl("echo '/tmp/evil.sh' | at +1 minute")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("echo '/tmp/evil.sh' | at +1 minute")
}

# ---------------------------------------------------------------------------
# Deny: crontab -e (edit crontab)
# ---------------------------------------------------------------------------

test_no_launchctl_crontab_edit if {
	agentjail.decision.action == "deny" with input as bash_lctl("crontab -e")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("crontab -e")
}

# ---------------------------------------------------------------------------
# Deny: crontab -r (replace/remove crontab)
# ---------------------------------------------------------------------------

test_no_launchctl_crontab_remove if {
	agentjail.decision.action == "deny" with input as bash_lctl("crontab -r")
	agentjail.decision.rule_id == launchctl_rule_id with input as bash_lctl("crontab -r")
}

# ---------------------------------------------------------------------------
# Not deny: launchctl list (read-only, safe)
# ---------------------------------------------------------------------------

test_no_launchctl_list_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_lctl("launchctl list")
}

# ---------------------------------------------------------------------------
# Not deny: launchctl print (read-only, safe)
# ---------------------------------------------------------------------------

test_no_launchctl_print_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_lctl("launchctl print system/com.apple.auditd")
}

# ---------------------------------------------------------------------------
# Not deny: crontab -l (list only, not -e or -r)
# ---------------------------------------------------------------------------

test_no_launchctl_crontab_list_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_lctl("crontab -l")
}
