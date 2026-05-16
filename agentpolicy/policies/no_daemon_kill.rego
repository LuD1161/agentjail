# Package agentjail — CORE rule: no-daemon-kill
#
# NOTE: The rule_id "library/no-daemon-kill" retains its "library/" prefix for
# historical reasons (it was originally an opt-in library rule). The prefix is
# now purely cosmetic — this rule is always-on locked core, embedded in every
# install, and cannot be disabled. See resolver.rego locked_rules.
#
# WHAT IT BLOCKS
# --------------
# Bash commands that kill or stop the agentjail daemon (or its sibling binaries)
# by process name or launchd label:
#
#   pkill / killall   agentjail-daemon|agentjail-hook|agentjail-shield|agentjail-netproxy
#   launchctl stop|kill   com.agentjail.*
#
# WHY (attack scenario)
# ----------------------
# agentjail-hook FAILS OPEN: if it cannot reach the daemon socket it ALLOWS the
# call (and prints a stderr marker). A prompt-injected or adversarial agent can
# abuse this by killing the daemon and slipping a command through the fail-open
# window:
#
#   pkill -f agentjail-daemon && rm -rf ~/important   # second cmd hits fail-open
#
# launchd (KeepAlive=true) respawns the daemon, but the window between kill and
# respawn is enough for one unguarded call. This rule removes that vector.
#
# WHAT IT DOES NOT COVER (by design, to avoid eval_conflict_error)
# ----------------------------------------------------------------
#   - `launchctl bootout|unload|remove com.agentjail.*`  -> core no-launchctl-remove
#   - writes to ~/.agentjail/ or the daemon plist          -> core file_policy + no-hook-self-disable
#   - `kill <pid>` after manually resolving the PID        -> not matchable by name; partly mitigated by launchd respawn
#
# ALWAYS ON (promoted from opt-in library to always-on locked core)
# -----------------------------------------------------------------
# This rule is active in every agentjail install without any configuration.
# It is locked in resolver.rego and cannot be disabled via policy.yaml or the CLI.
#
# EXAMPLE triggering input
# -------------------------
#   {"hook_event":"PreToolUse","tool_name":"Bash",
#    "tool_input":{"command":"pkill -f agentjail-daemon"},
#    "session_id":"s1","cwd":"/Users/dev/project"}

package agentjail

import future.keywords.if
import future.keywords.contains

_is_bash_event if {
	input.hook_event == "PreToolUse"
	input.tool_name == "Bash"
}

_cmd := input.tool_input.command

# Match the hyphenated process names (agentjail-daemon, -hook, -shield, -netproxy)
# rather than the bare "agentjail" or the ~/.agentjail path, so this never fires on
# the same input as core's sensitive-path rule (which matches /.agentjail/).
_kills_agentjail if {
	regex.match(`\b(pkill|killall)\b[^\n]*agentjail-(daemon|hook|shield|netproxy)`, _cmd)
}

# launchctl stop|kill of the daemon label (bootout/unload/remove are core-covered).
_kills_agentjail if {
	regex.match(`\blaunchctl\s+(stop|kill)\b[^\n]*com\.agentjail`, _cmd)
}

# Candidate entry — resolver.rego is the sole producer of `decision`.
candidate contains r if {
	_is_bash_event
	_kills_agentjail
	msg := "killing or stopping the agentjail daemon is denied (library/no-daemon-kill); it would open the hook's fail-open window"
	r := {
		"action":  "deny",
		"reason":  msg,
		"rule_id": "library/no-daemon-kill",
	}
}
