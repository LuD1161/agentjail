# mcp_github_writes_ask.rego
#
# For the GitHub MCP server: read calls (search, get_issue, get_pull_request)
# auto-allow; write calls (create_pull_request, merge_pull_request,
# update_issue, add_comment) escalate to ask.
#
# Why: reading public GitHub data is cheap and reversible. Creating PRs,
# merging them, or commenting on issues is visible to humans and hard to
# undo cleanly. Have the operator confirm.
#
# Pattern: uses `candidate contains r if { ... }` (partial rule set entry) so this
# rule coexists cleanly with the core policies via resolver.rego. Do NOT use
# `decision = ...` (complete rule) — that would conflict with resolver.rego's
# single complete `decision` rule.

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name in {
        "mcp__github__create_pull_request",
        "mcp__github__merge_pull_request",
        "mcp__github__create_issue",
        "mcp__github__update_issue",
        "mcp__github__add_issue_comment",
        "mcp__github__create_branch",
        "mcp__github__delete_branch",
        "mcp__github__create_release",
        "mcp__github__create_or_update_file",
        "mcp__github__push_files",
    }
    r := {
        "action":  "ask",
        "rule_id": "samples/mcp-github-write-confirm",
        "reason":  sprintf("GitHub MCP write %q affects a shared repo — confirm before proceeding", [input.tool_name]),
        "impact":  "would create or modify GitHub-visible state (PR, merge, comment)",
    }
}
