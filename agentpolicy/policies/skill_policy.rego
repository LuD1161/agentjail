# skill_policy.rego -- per-skill allow/block/ask policy.
#
# Fires when input.tool_name == "Skill". Extracts the skill name from
# input.tool_input.skill and checks it against the configured lists.
#
# Config shape:
#   data.agentjail.config.skills.allowed : array<string> -- glob patterns
#   data.agentjail.config.skills.blocked : array<string> -- glob patterns
#   data.agentjail.config.skills.ask     : array<string> -- glob patterns
#
# Semantics:
#   1. If skills.blocked has a matching pattern -> deny
#   2. If skills.ask has a matching pattern (and not blocked) -> ask
#   3. If skills.allowed is non-empty and no pattern matches -> deny
#   4. Otherwise -> allow (backwards-compatible default: empty allowed = all allowed)
#
# Skill names use ":" as the namespace separator (e.g. "posthog:error-analyzer",
# "superpowers:brainstorming"). glob.match uses [":"] as separators so that
# "posthog:*" matches all posthog skills without crossing into other namespaces.

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# True only for Skill tool calls
is_skill_call if {
	input.tool_name == "Skill"
}

# Extract skill name from tool_input
skill_name := name if {
	name := input.tool_input.skill
}

# Safe defaults when config is absent.
skill_allowed_patterns := data.agentjail.config.skills.allowed if {
	data.agentjail.config.skills.allowed
} else := []

skill_blocked_patterns := data.agentjail.config.skills.blocked if {
	data.agentjail.config.skills.blocked
} else := []

skill_ask_patterns := data.agentjail.config.skills.ask if {
	data.agentjail.config.skills.ask
} else := []

# Helper: at least one blocked pattern matches the skill name.
skill_any_blocked if {
	some pattern in skill_blocked_patterns
	glob.match(pattern, [":"], skill_name)
}

# Helper: at least one allowed pattern matches the skill name.
skill_any_allowed if {
	some pattern in skill_allowed_patterns
	glob.match(pattern, [":"], skill_name)
}

# Helper: at least one ask pattern matches the skill name.
skill_any_ask if {
	some pattern in skill_ask_patterns
	glob.match(pattern, [":"], skill_name)
}

# ---------------------------------------------------------------------------
# Candidate rules
# ---------------------------------------------------------------------------

# Rule 1: blocked takes precedence over everything.
candidate contains r if {
	is_skill_call
	skill_any_blocked
	some pattern in skill_blocked_patterns
	glob.match(pattern, [":"], skill_name)
	r := {
		"action":  "deny",
		"rule_id": "skill_policy/blocked",
		"reason":  sprintf("skill %q matches blocked pattern %q", [skill_name, pattern]),
		"impact":  sprintf("would invoke blocked skill %q", [skill_name]),
	}
}

# Rule 2: ask pattern (not blocked).
candidate contains r if {
	is_skill_call
	not skill_any_blocked
	skill_any_ask
	some pattern in skill_ask_patterns
	glob.match(pattern, [":"], skill_name)
	r := {
		"action":  "ask",
		"rule_id": "skill_policy/ask",
		"reason":  sprintf("skill %q requires confirmation (matches ask pattern %q)", [skill_name, pattern]),
		"impact":  sprintf("would invoke skill %q -- requires approval", [skill_name]),
	}
}

# Rule 3: allowed list is non-empty but skill does not match any pattern -> deny.
candidate contains r if {
	is_skill_call
	not skill_any_blocked
	not skill_any_ask
	count(skill_allowed_patterns) > 0
	not skill_any_allowed
	r := {
		"action":  "deny",
		"rule_id": "skill_policy/not_allowed",
		"reason":  sprintf("skill %q is not in the allowed list", [skill_name]),
		"impact":  sprintf("would invoke unallowed skill %q", [skill_name]),
	}
}

# Rule 4: skill is allowed — either explicitly by pattern or by default when
# the allowed list is empty (backwards-compatible: empty allowed = allow all).
candidate contains r if {
	is_skill_call
	not skill_any_blocked
	not skill_any_ask
	count(skill_allowed_patterns) == 0
	r := {
		"action":  "allow",
		"rule_id": "skill_policy/allowed",
		"reason":  sprintf("skill %q is permitted", [skill_name]),
	}
}

# Rule 4b: skill matches an explicit allowed pattern.
candidate contains r if {
	is_skill_call
	not skill_any_blocked
	not skill_any_ask
	count(skill_allowed_patterns) > 0
	skill_any_allowed
	r := {
		"action":  "allow",
		"rule_id": "skill_policy/allowed",
		"reason":  sprintf("skill %q is permitted", [skill_name]),
	}
}
