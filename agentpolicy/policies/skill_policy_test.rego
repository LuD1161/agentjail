# Tests for skill_policy.rego -- per-skill allow/block/ask policy.
#
# Coverage:
#   1.  Skill blocked by exact pattern -> deny (skill_policy/blocked)
#   2.  Skill explicitly allowed by pattern -> allow (skill_policy/allowed)
#   3.  Empty allowed list (default) -> allow all (backwards-compatible)
#   4.  Non-empty allowed list, skill not in it -> deny (skill_policy/not_allowed)
#   5.  Ask pattern -> ask (skill_policy/ask)
#   6.  Blocked takes precedence over ask
#   7.  Glob pattern with ":" separator: "posthog:*" matches "posthog:error-analyzer"
#   8.  Glob pattern: "superpowers:*" matches "superpowers:brainstorming"
#   9.  Non-Skill tool calls do not trigger skill_policy rules
#  10.  No config at all -> allow (empty defaults)
#  11.  Blocked takes precedence over explicit allowed
#  12.  Ask pattern: "deep-research" matches exactly

package agentjail

import future.keywords.if

# ---------------------------------------------------------------------------
# Shared config fixtures
# ---------------------------------------------------------------------------

standard_skills_config := {
	"skills": {
		"allowed": ["deep-research", "posthog:*", "superpowers:*"],
		"blocked": ["superpowers:dispatching-parallel-agents"],
		"ask":     ["deep-research"],
	},
}

empty_skills_config := {
	"skills": {
		"allowed": [],
		"blocked": [],
		"ask":     [],
	},
}

# ---------------------------------------------------------------------------
# 1. Skill blocked by exact pattern -> deny
# ---------------------------------------------------------------------------

test_skill_blocked_exact if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "superpowers:dispatching-parallel-agents"},
	} with data.agentjail.config as standard_skills_config

	d.action == "deny"
	d.rule_id == "skill_policy/blocked"
	contains(d.reason, "superpowers:dispatching-parallel-agents")
	contains(d.reason, "blocked pattern")
}

# ---------------------------------------------------------------------------
# 2. Skill explicitly allowed by pattern -> allow
# ---------------------------------------------------------------------------

test_skill_explicitly_allowed if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "superpowers:brainstorming"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["superpowers:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
	contains(d.reason, "superpowers:brainstorming")
}

# ---------------------------------------------------------------------------
# 3. Empty allowed list (default) -> allow all (backwards-compatible)
# ---------------------------------------------------------------------------

test_empty_allowed_permits_any_skill if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "some-random-skill"},
	} with data.agentjail.config as empty_skills_config

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
}

test_empty_allowed_permits_posthog_skill if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "posthog:error-analyzer"},
	} with data.agentjail.config as empty_skills_config

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
}

# ---------------------------------------------------------------------------
# 4. Non-empty allowed list, skill not in it -> deny (skill_policy/not_allowed)
# ---------------------------------------------------------------------------

test_nonempty_allowed_rejects_unlisted_skill if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "some-unlisted-skill"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["posthog:*", "superpowers:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "deny"
	d.rule_id == "skill_policy/not_allowed"
	contains(d.reason, "some-unlisted-skill")
	contains(d.reason, "not in the allowed list")
}

test_nonempty_allowed_rejects_wrong_namespace if {
	# "posthog:*" should not match "superposthog:anything"
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "superposthog:anything"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["posthog:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "deny"
	d.rule_id == "skill_policy/not_allowed"
}

# ---------------------------------------------------------------------------
# 5. Ask pattern -> ask (skill_policy/ask)
# ---------------------------------------------------------------------------

test_ask_pattern_triggers_ask if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "deep-research"},
	} with data.agentjail.config as standard_skills_config

	d.action == "ask"
	d.rule_id == "skill_policy/ask"
	contains(d.reason, "deep-research")
	contains(d.reason, "requires confirmation")
}

test_ask_glob_pattern if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "posthog:error-analyzer"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": [],
			"blocked": [],
			"ask":     ["posthog:*"],
		},
	}

	d.action == "ask"
	d.rule_id == "skill_policy/ask"
	contains(d.reason, "posthog:error-analyzer")
}

# ---------------------------------------------------------------------------
# 6. Blocked takes precedence over ask
# ---------------------------------------------------------------------------

test_blocked_wins_over_ask if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "dangerous-skill"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": [],
			"blocked": ["dangerous-skill"],
			"ask":     ["dangerous-skill"],
		},
	}

	d.action == "deny"
	d.rule_id == "skill_policy/blocked"
}

# ---------------------------------------------------------------------------
# 7. Glob with ":" separator: "posthog:*" matches "posthog:error-analyzer"
# ---------------------------------------------------------------------------

test_posthog_glob_matches_error_analyzer if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "posthog:error-analyzer"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["posthog:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
}

test_posthog_glob_does_not_match_other_namespace if {
	# "posthog:*" must NOT match "superpowers:brainstorming"
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "superpowers:brainstorming"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["posthog:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "deny"
	d.rule_id == "skill_policy/not_allowed"
}

# ---------------------------------------------------------------------------
# 8. Glob: "superpowers:*" matches "superpowers:brainstorming"
# ---------------------------------------------------------------------------

test_superpowers_glob_matches_brainstorming if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "superpowers:brainstorming"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["superpowers:*"],
			"blocked": [],
			"ask":     [],
		},
	}

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
}

# ---------------------------------------------------------------------------
# 9. Non-Skill tool calls do not trigger skill_policy rules
# ---------------------------------------------------------------------------

test_bash_not_a_skill_call if {
	not is_skill_call with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Bash",
		"tool_input": {"command": "ls -la"},
	}
}

test_mcp_not_a_skill_call if {
	not is_skill_call with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "mcp__filesystem__read_file",
		"tool_input": {},
	}
}

test_non_skill_decision_has_no_skill_policy_rule_id if {
	# A Bash tool call must not carry a skill_policy/* rule_id.
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Bash",
		"tool_input": {"command": "echo hello"},
	} with data.agentjail.config as empty_skills_config
	not startswith(d.rule_id, "skill_policy/")
}

# ---------------------------------------------------------------------------
# 10. No config at all -> allow (empty defaults -- backwards-compatible)
# ---------------------------------------------------------------------------

test_no_config_allows_skill if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "deep-research"},
	}
	# No `with data.agentjail.config as ...` -- exercises else := [] fallbacks.

	d.action == "allow"
	d.rule_id == "skill_policy/allowed"
}

# ---------------------------------------------------------------------------
# 11. Blocked takes precedence over explicit allowed
# ---------------------------------------------------------------------------

test_blocked_wins_over_explicit_allowed if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "posthog:signals"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": ["posthog:signals"],
			"blocked": ["posthog:*"],
			"ask":     [],
		},
	}

	d.action == "deny"
	d.rule_id == "skill_policy/blocked"
}

# ---------------------------------------------------------------------------
# 12. Ask pattern: exact skill name "deep-research" triggers ask
# ---------------------------------------------------------------------------

test_exact_ask_pattern_deep_research if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "deep-research"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": [],
			"blocked": [],
			"ask":     ["deep-research"],
		},
	}

	d.action == "ask"
	d.rule_id == "skill_policy/ask"
	contains(d.reason, "deep-research")
}
