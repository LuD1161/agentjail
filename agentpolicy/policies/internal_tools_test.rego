# Tests for internal_tools.rego — harness-internal tool allow-list.
#
# Coverage:
#   1. Each internal tool (TaskCreate, ToolSearch, plan-mode, etc.) → allow
#   2. A non-internal, unmatched tool → falls through to resolver/default ask
#      (proves the rule is scoped to the named set and doesn't blanket-allow)
#   3. A governed side-effectful tool name is NOT in the set (Bash stays governed)

package agentjail

import future.keywords.if
import future.keywords.in

# Expected allow verdict for any tool in the internal set.
internal_allow := {
	"action": "allow",
	"rule_id": "internal_tools/allow",
	"reason": "agent internal tool — no external side effects",
	"impact": "in-session orchestration only (task list / plan mode / tool-schema load)",
}

# 1. Every internal tool resolves to the allow verdict.
test_all_internal_tools_allowed if {
	every tool in internal_tools {
		decision == internal_allow with input as {
			"hook_event": "PreToolUse",
			"tool_name": tool,
			"tool_input": {},
		}
	}
}

# Spot-check a couple explicitly (readable failures if the set changes).
test_taskcreate_allowed if {
	decision == internal_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "TaskCreate",
		"tool_input": {},
	}
}

test_toolsearch_allowed if {
	decision == internal_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "ToolSearch",
		"tool_input": {"query": "anything"},
	}
}

# 2. An unrelated tool name is NOT auto-allowed — falls through to the fail-safe
#    default-ask owned by resolver.rego.
test_unknown_tool_falls_through_to_default_ask if {
	decision == {
		"action": "ask",
		"reason": "no policy candidate fired — defaulting to ask",
		"rule_id": "resolver/default",
	} with input as {
		"hook_event": "PreToolUse",
		"tool_name": "SomeFutureToolNotInTheSet",
		"tool_input": {},
	}
}

# 3. Bash is deliberately NOT in the internal set (stays governed by command_policy).
test_bash_not_in_internal_set if {
	not "Bash" in internal_tools
}

# Expected allow verdict for any tool in the benign set.
benign_allow := {
	"action": "allow",
	"rule_id": "internal_tools/benign_allow",
	"reason": "benign harness tool — read-only path enumeration, in-session shell lifecycle, or subagent dispatch (whose calls are independently hooked)",
	"impact": "no ungoverned side effect (paths only / already-approved shell / hooked subagent calls)",
}

# 4. Every benign tool resolves to the benign-allow verdict.
test_all_benign_tools_allowed if {
	every tool in benign_tools {
		decision == benign_allow with input as {
			"hook_event": "PreToolUse",
			"tool_name": tool,
			"tool_input": {},
		}
	}
}

# Spot-checks with realistic inputs.
test_glob_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Glob",
		"tool_input": {"pattern": "**/*.go"},
	}
}

test_bashoutput_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "BashOutput",
		"tool_input": {"bash_id": "1"},
	}
}

test_subagent_dispatch_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Agent",
		"tool_input": {"prompt": "do x"},
	}
}

test_skill_allowed if {
	# Skill is now governed by skill_policy.rego (not benign_tools).
	# With an empty skills.allowed list (default), all skills are permitted.
	skill_allow := {
		"action":  "allow",
		"rule_id": "skill_policy/allowed",
		"reason":  "skill \"some-skill\" is permitted",
	}
	decision == skill_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name":  "Skill",
		"tool_input": {"skill": "some-skill"},
	} with data.agentjail.config as {
		"skills": {
			"allowed": [],
			"blocked": [],
			"ask":     [],
		},
	}
}

# 5. New internal tools: cron, LSP, scheduling, messaging
test_cron_create_allowed if {
	decision == internal_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "CronCreate",
		"tool_input": {},
	}
}

test_lsp_allowed if {
	decision == internal_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "LSP",
		"tool_input": {"action": "references"},
	}
}

test_send_message_allowed if {
	decision == internal_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "SendMessage",
		"tool_input": {"to": "agent-1", "message": "hello"},
	}
}

# 6. New benign tools: Workflow, worktree
test_workflow_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Workflow",
		"tool_input": {"script": "export const meta = {}"},
	}
}

test_enter_worktree_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "EnterWorktree",
		"tool_input": {},
	}
}

test_exit_worktree_allowed if {
	decision == benign_allow with input as {
		"hook_event": "PreToolUse",
		"tool_name": "ExitWorktree",
		"tool_input": {},
	}
}

# 7. Grep is deliberately NOT auto-allowed: it returns file contents and must
#    stay governed (otherwise it bypasses file_policy's sensitive-path deny).
test_grep_not_auto_allowed if {
	not "Grep" in internal_tools
	not "Grep" in benign_tools
}
