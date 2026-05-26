# Package agentjail — library rule: no-history-read
#
# WHAT IT BLOCKS
# --------------
# Reads (Read tool, or Bash cat/less/head/tail/grep/awk/sed) of files that
# contain shell command history, browser history/cookies, or other forensic
# / credential-leaking artefacts:
#
#   ~/.zsh_history, ~/.bash_history, ~/.python_history, ~/.psql_history
#   ~/.lesshst, ~/.viminfo
#   ~/Library/Application Support/Firefox/
#   ~/Library/Application Support/Google/Chrome/
#   ~/Library/Cookies/
#   ~/Library/Safari/History.db
#   ~/Library/Application Support/com.apple.sharedfilelist/
#
# WHY (attack scenario)
# ----------------------
# Shell history files contain a chronicle of previous commands, often including:
#   - API keys passed on the command line (AWS_SECRET_ACCESS_KEY=... curl ...)
#   - Passwords typed to CLI tools (mysql -u root -psecret)
#   - Internal hostnames, bucket names, database connection strings
#
# Browser history and cookies enable session hijacking.  The sharedfilelist
# leaks recently-opened file paths (and therefore project structure).
#
# A prompt-injected agent that reads ~/.zsh_history can immediately exfiltrate
# secrets without any other exploit.  This rule closes that vector.
#
# WHY OPT-IN (false-positive risks)
# -----------------------------------
# Legitimate developer use-cases:
#   - An agent helping to analyse shell history for documentation purposes.
#   - A developer asking the agent to check if a command was run before.
#   - Dotfiles managers that inspect ~/.viminfo.
# Enable this rule in untrusted-prompt contexts or CI-like non-interactive runs.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Bash",
#    "tool_input":{"command":"cat ~/.zsh_history | grep AWS_SECRET"},
#    "session_id":"s1","cwd":"/Users/dev/project"}
#
# HOW TO ENABLE (MVP)
#   cp agentpolicy/policies/library/no_history_read.rego ~/.agentjail/rules/
#   kill -HUP $(pgrep -f agentjail-daemon)

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helper: extract path from Read tool_input (uses "path" key)
# ---------------------------------------------------------------------------

_lib_hist_path := input.tool_input.path if {
	input.tool_input.path
}

_lib_hist_path := input.tool_input.file_path if {
	not input.tool_input.path
	input.tool_input.file_path
}

# History / forensic artefact path patterns.
_is_history_path(p) if {
	regex.match(`^/Users/[^/]+/\.(zsh_history|bash_history|python_history|psql_history|lesshst|viminfo)$`, p)
}

_is_history_path(p) if {
	# Firefox profile directory
	regex.match(`^/Users/[^/]+/Library/Application Support/Firefox(/|$)`, p)
}

_is_history_path(p) if {
	# Chrome profile directory
	regex.match(`^/Users/[^/]+/Library/Application Support/Google/Chrome(/|$)`, p)
}

_is_history_path(p) if {
	# macOS Cookies directory
	regex.match(`^/Users/[^/]+/Library/Cookies(/|$)`, p)
}

_is_history_path(p) if {
	# Safari history database
	regex.match(`^/Users/[^/]+/Library/Safari/History\.db$`, p)
}

_is_history_path(p) if {
	# Apple shared file list (recently opened files)
	regex.match(`^/Users/[^/]+/Library/Application Support/com\.apple\.sharedfilelist(/|$)`, p)
}

# ---------------------------------------------------------------------------
# Candidate: deny Read tool access to history / forensic paths
# ---------------------------------------------------------------------------

candidate contains r if {
	input.tool_name == "Read"
	p := _lib_hist_path
	_is_history_path(p)
	msg := sprintf("read of history/forensic artefact %q is denied (library/no-history-read); credential leakage risk", [p])
	impact_msg := sprintf("would read history/forensic artefact %q", [p])
	r := {
		"action":  "deny",
		"rule_id": "library/no-history-read",
		"reason":  msg,
		"impact":  impact_msg,
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny Bash commands that read history / forensic paths
# (cat, less, head, tail, grep, awk, sed are the common read-via-shell tools)
# ---------------------------------------------------------------------------

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
	c := input.tool_input.command
	regex.match(`\b(cat|less|head|tail|grep|awk|sed)\b`, c)
	_bash_mentions_history(c)
	r := {
		"action":  "deny",
		"rule_id": "library/no-history-read",
		"reason":  "Bash command reads a history/forensic artefact (library/no-history-read); credential leakage risk",
		"impact":  "would read shell/browser history via Bash",
	}
}

# True when the Bash command string mentions a history/forensic path.
_bash_mentions_history(c) if {
	regex.match(`/Users/[^/\s'"]+/\.(zsh_history|bash_history|python_history|psql_history|lesshst|viminfo)\b`, c)
}

_bash_mentions_history(c) if {
	regex.match(`~/\.(zsh_history|bash_history|python_history|psql_history|lesshst|viminfo)\b`, c)
}

_bash_mentions_history(c) if {
	regex.match(`/Users/[^/\s'"]+/Library/Application Support/Firefox\b`, c)
}

_bash_mentions_history(c) if {
	regex.match(`/Users/[^/\s'"]+/Library/Application Support/Google/Chrome\b`, c)
}

_bash_mentions_history(c) if {
	regex.match(`/Users/[^/\s'"]+/Library/Cookies\b`, c)
}

_bash_mentions_history(c) if {
	regex.match(`/Users/[^/\s'"]+/Library/Safari/History\.db\b`, c)
}
