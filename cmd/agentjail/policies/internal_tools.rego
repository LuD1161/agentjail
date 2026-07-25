# internal_tools.rego — allow coding-agent harness-internal tools.
#
# Some agents route their own orchestration/UI tools through the PreToolUse hook
# (Claude Code is the notable one: TaskCreate, ToolSearch, plan-mode, the todo
# list, etc.). These manage in-session state or load tool schemas — they never
# touch the filesystem, shell, network, or MCP servers, so there is nothing for
# agentjail to guard. Without this rule each one hits `resolver/default` and
# escalates to the user, which is pure noise.
#
# Scope note: Codex's orchestration tools can surface to agentjail alongside
# side-effectful hooks. They are listed below explicitly; unknown tools still
# fall through to resolver/default. Cursor's configured matchers cover only
# side-effectful tools (Bash/Read/MCP).
#
# A second set (benign_tools, below) auto-allows tools that DO touch the
# filesystem/shell but only in ways already governed elsewhere or with no new
# side effect: Glob (read-only path enumeration), BashOutput / KillShell
# (in-session lifecycle of an already-approved background shell), Task / Agent /
# Workflow (subagent dispatch — the subagent's own tool calls fire this same
# hook), and EnterWorktree / ExitWorktree (worktree lifecycle — tool calls
# within the worktree are independently hooked).
# NOTE: Skill is NOT in benign_tools. Per-skill allow/block/ask is governed by
# skill_policy.rego, which reads data.agentjail.config.skills.
#
# Deliberately NOT included (these keep their normal governance because they have
# real, ungoverned side effects): Bash, Read, Write, Edit, NotebookEdit,
# the MCP resource tools, and all MCP tools.
# Grep is excluded on purpose: it returns file CONTENTS, so allowing it would
# bypass file_policy's sensitive-path deny (a Read of ~/.ssh/id_rsa is blocked, a
# grep of it would not be) — it must stay governed. WebFetch / WebSearch are
# network egress, governed separately by web_policy.rego (allowed by default,
# with a WebFetch host blocklist).
#
# Pattern: `candidate contains r if { ... }` (partial rule entry). resolver.rego
# owns `decision`. An "allow" candidate only wins when no deny/ask candidate
# fires for the same input, so this can never override a real block.

package agentjail

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Harness-internal, side-effect-free tools to auto-allow.
internal_tools := {
	"TaskCreate",
	"TaskUpdate",
	"TaskGet",
	"TaskList",
	"TaskOutput",
	"TaskStop",
	"TodoWrite",
	"ToolSearch",
	"EnterPlanMode",
	"ExitPlanMode",
	"AskUserQuestion",
	"CronCreate",
	"CronDelete",
	"CronList",
	"ScheduleWakeup",
	"LSP",
	"DesignSync",
	"SendMessage",
	"UpdatePlan",
	"update_plan",
	"create_goal",
	"get_goal",
	"update_goal",
	"wait_agent",
	"collaborationlist_agents",
	"collaborationwait_agent",
	"collaboration.list_agents",
	"collaboration.wait_agent",
}

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name in internal_tools
	r := {
		"action": "allow",
		"rule_id": "internal_tools/allow",
		"reason": "agent internal tool — no external side effects",
		"impact": "in-session orchestration only (task list / plan mode / tool-schema load)",
	}
}

# Benign tools that touch the filesystem/shell only in already-governed or
# side-effect-free ways. Kept separate from internal_tools (and given a distinct
# rule_id) so the allow reason stays accurate and telemetry can tell them apart.
#   - Glob:            read-only path enumeration (returns paths, never file content).
#   - BashOutput:      reads stdout/stderr of an ALREADY-approved background shell.
#   - KillShell:       terminates an agent-spawned background shell by id.
#   - Task/Agent:      dispatches a subagent — whose own tool calls fire this same
#                      PreToolUse hook, so they remain independently governed.
#   - Workflow:        orchestrates multi-agent workflows — like Agent, subagent
#                      calls are independently hooked.
#   - EnterWorktree:   creates a git worktree for isolated work — tool calls
#                      within the worktree are independently hooked.
#   - ExitWorktree:    exits/cleans up an agent-owned worktree.
# NOTE: Skill is NOT in this set. Per-skill allow/block/ask is governed by
# skill_policy.rego (data.agentjail.config.skills).
benign_tools := {
	"Glob",
	"BashOutput",
	"KillShell",
	"Task",
	"Agent",
	"Workflow",
	"EnterWorktree",
	"ExitWorktree",
	"spawn_agent",
	"followup_task",
	"send_message",
	"interrupt_agent",
	"collaborationspawn_agent",
	"collaborationfollowup_task",
	"collaborationsend_message",
	"collaborationinterrupt_agent",
	"collaboration.spawn_agent",
	"collaboration.followup_task",
	"collaboration.send_message",
	"collaboration.interrupt_agent",
}

candidate contains r if {
	input.hook_event == "PreToolUse"
	input.tool_name in benign_tools
	r := {
		"action": "allow",
		"rule_id": "internal_tools/benign_allow",
		"reason": "benign harness tool — read-only path enumeration, in-session shell lifecycle, or subagent dispatch (whose calls are independently hooked)",
		"impact": "no ungoverned side effect (paths only / already-approved shell / hooked subagent calls)",
	}
}
