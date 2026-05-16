# Package agentjail — library rule: no-launchctl
#
# WHAT IT BLOCKS
# --------------
# Bash commands that invoke out-of-tree process spawning primitives:
#
#   launchctl submit|load|bootstrap|kickstart|enable  — macOS launchd service registration
#   osascript                                          — AppleScript / JXA execution
#   at now|+N                                          — POSIX at-job scheduler
#   crontab -e|-r                                      — crontab edit or remove
#
# WHY (attack scenario)
# ----------------------
# These commands spawn processes that are NOT children of the agentjail-shielded
# agent process.  Because agentjail-shield (sandbox-exec / Landlock) applies
# per-process and is inherited only by fork/exec children, a launchd daemon
# registered by the agent runs entirely outside the sandbox with full user
# privileges.  Example attack chain:
#
#   1. Agent calls: launchctl submit -l com.evil.persist -p /tmp/evil.sh
#   2. launchd launches /tmp/evil.sh immediately (and on every login)
#   3. evil.sh runs as the user, reads ~/.ssh/id_rsa, exfiltrates data
#   4. No hook intercept occurs because evil.sh is not a child of the agent
#
# osascript is equally dangerous: `osascript -e 'do shell script "curl ..."'`
# spawns an Apple-signed process that bypasses most endpoint controls.
#
# WHY OPT-IN (false-positive risks)
# -----------------------------------
# Legitimate uses:
#   - macOS dev tools registration (some Homebrew formulae use launchctl load).
#   - Automation scripts that legitimately use AppleScript for UI interaction.
#   - Scheduled tasks via crontab (uncommon in agent sessions but real).
# Enable this rule in interactive coding sessions; consider disabling in
# dedicated sysadmin or DevOps automation sessions.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Bash",
#    "tool_input":{"command":"launchctl load ~/Library/LaunchAgents/com.evil.plist"},
#    "session_id":"s1","cwd":"/Users/dev/project"}
#
# HOW TO ENABLE (MVP)
#   cp agentpolicy/policies/library/no_launchctl.rego ~/.agentjail/rules/
#   kill -HUP $(pgrep -f agentjail-daemon)

package agentjail

import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_is_bash_event if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
}

_cmd := input.tool_input.command

# ---------------------------------------------------------------------------
# Candidate: deny launchctl submit / load / bootstrap / kickstart / enable
# (These register new out-of-tree agents; bootout/remove already covered by
#  command_policy core rule `no-launchctl-remove`.)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\blaunchctl\s+(submit|load|bootstrap|kickstart|enable)\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-launchctl",
		"reason":  "launchctl service registration is denied (library/no-launchctl); out-of-tree spawn bypasses agentjail-shield sandbox",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny osascript (any invocation — no safe subset exists)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bosascript\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-launchctl",
		"reason":  "osascript is denied (library/no-launchctl); AppleScript/JXA spawns outside the shielded process tree",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny 'at' scheduler job creation
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bat\s+(now|[+-]\d)`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-launchctl",
		"reason":  "at-job creation is denied (library/no-launchctl); scheduled commands run outside the shielded session",
	}
}

# ---------------------------------------------------------------------------
# Candidate: deny crontab -e (edit) or crontab -r (remove/replace)
# ---------------------------------------------------------------------------

candidate contains r if {
	_is_bash_event
	regex.match(`\bcrontab\s+(-e|-r)\b`, _cmd)
	r := {
		"action":  "deny",
		"rule_id": "library/no-launchctl",
		"reason":  "crontab modification is denied (library/no-launchctl); cron jobs run outside the shielded session",
	}
}
