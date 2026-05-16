# Tests for agentpolicy/policies/library/no_app_binary_write.rego
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

app_binary_rule_id := "library/no-app-binary-write"

write_app(fp) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Write",
	"tool_input": {"file_path": fp, "content": "evil"},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

bash_app(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# Deny: Write to /Applications/Slack.app/Contents/MacOS/Slack
# ---------------------------------------------------------------------------

test_no_app_binary_write_macos_binary if {
	agentjail.decision.action == "deny" with input as write_app("/Applications/Slack.app/Contents/MacOS/Slack")
	agentjail.decision.rule_id == app_binary_rule_id with input as write_app("/Applications/Slack.app/Contents/MacOS/Slack")
}

# ---------------------------------------------------------------------------
# Deny: Write to /Applications/Xcode.app/Contents/MacOS/Xcode
# ---------------------------------------------------------------------------

test_no_app_binary_write_xcode_binary if {
	agentjail.decision.action == "deny" with input as write_app("/Applications/Xcode.app/Contents/MacOS/Xcode")
	agentjail.decision.rule_id == app_binary_rule_id with input as write_app("/Applications/Xcode.app/Contents/MacOS/Xcode")
}

# ---------------------------------------------------------------------------
# Deny: Write to /Applications/Slack.app/Contents/Frameworks/libssl.dylib
# ---------------------------------------------------------------------------

test_no_app_binary_write_frameworks if {
	agentjail.decision.action == "deny" with input as write_app("/Applications/Slack.app/Contents/Frameworks/libssl.dylib")
	agentjail.decision.rule_id == app_binary_rule_id with input as write_app("/Applications/Slack.app/Contents/Frameworks/libssl.dylib")
}

# ---------------------------------------------------------------------------
# Deny: Write to /Applications/App.app/Contents/Resources/helper.dylib
# ---------------------------------------------------------------------------

test_no_app_binary_write_resources_dylib if {
	agentjail.decision.action == "deny" with input as write_app("/Applications/App.app/Contents/Resources/helper.dylib")
	agentjail.decision.rule_id == app_binary_rule_id with input as write_app("/Applications/App.app/Contents/Resources/helper.dylib")
}

# ---------------------------------------------------------------------------
# Deny: Bash cp targeting MacOS directory
# ---------------------------------------------------------------------------

test_no_app_binary_bash_cp if {
	agentjail.decision.action == "deny" with input as bash_app("cp /tmp/evil /Applications/Slack.app/Contents/MacOS/Slack")
	agentjail.decision.rule_id == app_binary_rule_id with input as bash_app("cp /tmp/evil /Applications/Slack.app/Contents/MacOS/Slack")
}

# ---------------------------------------------------------------------------
# Not deny: Write to /Applications/Slack.app/Contents/Resources/icon.png
#           (non-dylib resource — not a binary)
# ---------------------------------------------------------------------------

test_no_app_binary_resources_png_not_denied if {
	not agentjail.decision.action == "deny" with input as write_app("/Applications/Slack.app/Contents/Resources/icon.png")
}

# ---------------------------------------------------------------------------
# Not deny: Write to /Users/dev/Code/Applications/foo (user-owned dev path)
# ---------------------------------------------------------------------------

test_no_app_binary_user_code_not_denied if {
	not agentjail.decision.action == "deny" with input as write_app("/Users/dev/Code/Applications/foo/binary")
}

# ---------------------------------------------------------------------------
# Not deny: Write to a normal project binary in /tmp (not under /Applications)
# ---------------------------------------------------------------------------

test_no_app_binary_tmp_not_denied if {
	not agentjail.decision.action == "deny" with input as write_app("/tmp/mybinary")
}
