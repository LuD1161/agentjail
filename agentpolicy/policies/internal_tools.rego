# internal_tools.rego — allow coding-agent harness-internal tools.
#
# Some agents route their own orchestration/UI tools through the PreToolUse hook
# (Claude Code is the notable one: TaskCreate, ToolSearch, plan-mode, the todo
# list, etc.). These manage in-session state or load tool schemas — they never
# touch the filesystem, shell, network, or MCP servers, so there is nothing for
# agentjail to guard. Without this rule each one hits `resolver/default` and
# escalates to the user, which is pure noise.
#
# Scope note: Codex and Cursor do NOT surface internal tools to agentjail — their
# hooked surfaces are only side-effectful tools (Codex: Bash/apply_patch/MCP;
# Cursor: Bash/Read/MCP), which the core policies intentionally govern. So this
# allow-list is effectively Claude-only by virtue of the tool names; there is no
# Codex/Cursor internal-tool surface to add.
#
# A second set (benign_tools, below) auto-allows tools that DO touch the
# filesystem/shell but only in ways already governed elsewhere or with no new
# side effect: Glob (read-only path enumeration), BashOutput / KillShell
# (in-session lifecycle of an already-approved background shell), and Task /
# Agent (subagent dispatch — the subagent's own tool calls fire this same hook).
#
# Deliberately NOT included (these keep their normal governance because they have
# real, ungoverned side effects): Bash, Read, Write, Edit, NotebookEdit, the
# worktree / cron / schedule tools, the MCP resource tools, and all MCP tools.
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
#   - Glob:       read-only path enumeration (returns paths, never file content).
#   - BashOutput: reads stdout/stderr of an ALREADY-approved background shell.
#   - KillShell:  terminates an agent-spawned background shell by id.
#   - Task/Agent: dispatches a subagent — whose own tool calls fire this same
#                 PreToolUse hook, so they remain independently governed.
benign_tools := {
	"Glob",
	"BashOutput",
	"KillShell",
	"Task",
	"Agent",
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
