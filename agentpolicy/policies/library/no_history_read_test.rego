# Tests for agentpolicy/policies/library/no_history_read.rego
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

history_rule_id := "library/no-history-read"

read_hist(p) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Read",
	"tool_input": {"path": p},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

bash_hist(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name":  "Bash",
	"tool_input": {"command": cmd},
	"session_id": "s1",
	"cwd":        "/Users/dev/project",
}

# ---------------------------------------------------------------------------
# Deny: Read ~/.zsh_history
# ---------------------------------------------------------------------------

test_no_history_read_zsh_history if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/.zsh_history")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/.zsh_history")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/.bash_history
# ---------------------------------------------------------------------------

test_no_history_read_bash_history if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/.bash_history")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/.bash_history")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/.python_history
# ---------------------------------------------------------------------------

test_no_history_read_python_history if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/.python_history")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/.python_history")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/.psql_history
# ---------------------------------------------------------------------------

test_no_history_read_psql_history if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/.psql_history")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/.psql_history")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/Library/Safari/History.db
# ---------------------------------------------------------------------------

test_no_history_read_safari_history if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/Library/Safari/History.db")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/Library/Safari/History.db")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/Library/Application Support/Firefox/
# ---------------------------------------------------------------------------

test_no_history_read_firefox if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/Library/Application Support/Firefox/Profiles/foo.default/places.sqlite")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/Library/Application Support/Firefox/Profiles/foo.default/places.sqlite")
}

# ---------------------------------------------------------------------------
# Deny: Read ~/Library/Cookies/
# ---------------------------------------------------------------------------

test_no_history_read_cookies if {
	agentjail.decision.action == "deny" with input as read_hist("/Users/dev/Library/Cookies/Cookies.binarycookies")
	agentjail.decision.rule_id == history_rule_id with input as read_hist("/Users/dev/Library/Cookies/Cookies.binarycookies")
}

# ---------------------------------------------------------------------------
# Deny: Bash cat ~/.zsh_history
# ---------------------------------------------------------------------------

test_no_history_bash_cat_zsh_history if {
	agentjail.decision.action == "deny" with input as bash_hist("cat /Users/dev/.zsh_history | grep AWS")
	agentjail.decision.rule_id == history_rule_id with input as bash_hist("cat /Users/dev/.zsh_history | grep AWS")
}

# ---------------------------------------------------------------------------
# Deny: Bash cat ~/.bash_history (tilde form)
# ---------------------------------------------------------------------------

test_no_history_bash_cat_bash_history_tilde if {
	agentjail.decision.action == "deny" with input as bash_hist("cat ~/.bash_history")
	agentjail.decision.rule_id == history_rule_id with input as bash_hist("cat ~/.bash_history")
}

# ---------------------------------------------------------------------------
# Deny: Bash grep on Safari history db
# ---------------------------------------------------------------------------

test_no_history_bash_grep_safari if {
	agentjail.decision.action == "deny" with input as bash_hist("grep 'github.com' /Users/dev/Library/Safari/History.db")
	agentjail.decision.rule_id == history_rule_id with input as bash_hist("grep 'github.com' /Users/dev/Library/Safari/History.db")
}

# ---------------------------------------------------------------------------
# Not deny: Read ~/Documents/notes.md (not a history file)
# ---------------------------------------------------------------------------

test_no_history_documents_not_denied if {
	not agentjail.decision.action == "deny" with input as read_hist("/Users/dev/Documents/notes.md")
}

# ---------------------------------------------------------------------------
# Not deny: Bash cat on a project file
# ---------------------------------------------------------------------------

test_no_history_bash_cat_project_not_denied if {
	not agentjail.decision.action == "deny" with input as bash_hist("cat /Users/dev/project/README.md")
}
