# mcp_filesystem_readonly.rego
#
# Lock the filesystem MCP server to READ-ONLY operations. Block write_file,
# move_file, create_directory, delete — but allow read_file, list_directory,
# search_files, get_file_info.
#
# Why opt in to this: the filesystem MCP server is widely used (it's how
# agents read your project to understand context). Most of the time the
# agent only NEEDS read access. Limiting it to read-only means a confused
# agent can't accidentally overwrite source files, delete a directory it
# misread, or create persistence files in your project.
#
# Companion config — drop into ~/.agentjail/policy.yaml so the filesystem
# server stays in the allowlist:
#
#   mcp:
#     allowed: ["filesystem"]
#     servers:
#       filesystem:
#         allowed_tools: ["read_file", "list_directory", "search_files", "get_file_info"]
#
# With that YAML alone, the core mcp_policy.rego already enforces
# this. This file is a TEACHING EXAMPLE that does the same thing in pure
# Rego — useful if you want to express more nuanced logic than the YAML
# allows (e.g., "allow write_file but only in /tmp").
#
# Pattern: uses `candidate contains r if { ... }` (partial rule set entry) so this
# rule coexists cleanly with the core policies via resolver.rego. Do NOT use
# `decision = ...` (complete rule) — that would conflict with resolver.rego's
# single complete `decision` rule.

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# Block the destructive subset of filesystem MCP tools.
candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name in {
        "mcp__filesystem__write_file",
        "mcp__filesystem__move_file",
        "mcp__filesystem__create_directory",
        "mcp__filesystem__delete",
    }
    r := {
        "action":  "deny",
        "rule_id": "samples/mcp-filesystem-readonly",
        "reason":  sprintf("filesystem MCP tool %q is denied by samples/mcp-filesystem-readonly", [input.tool_name]),
        "impact":  "would mutate the filesystem via MCP — locked to read-only by policy",
    }
}
