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
# Deliberately NOT included (these keep their normal governance because they have
# real side effects): Bash, Read, Write, Edit, NotebookEdit, the worktree / cron /
# schedule tools, and all MCP tools. WebFetch / WebSearch are network egress and
# are governed separately by web_policy.rego (allowed by default, with a
# WebFetch host blocklist) rather than lumped in here.
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
