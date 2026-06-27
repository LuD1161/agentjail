# Package agentjail — MCP server allowlist policy.
#
# Evaluated by hookOPAEngine (engine.go) via query data.agentjail.decision.
# Only fires on MCP tool calls (tool_name starts with "mcp__").
#
# Each rule contributes a candidate entry to the shared partial rule set
# `candidate` (defined via resolver.rego). The resolver picks the most
# restrictive candidate (deny > ask > allow) and produces `decision`.
#
# Config path: data.agentjail.config.mcp (pluggable, not hardcoded).
# Typically projected from ~/.agentjail/policy.yaml by the daemon before
# calling Eval; tests inject it via `with data.agentjail.config as {...}`.
#
# Config shape:
#   data.agentjail.config.mcp.allowed : array<string>  — glob patterns for allowed server names
#   data.agentjail.config.mcp.blocked : array<string>  — glob patterns for blocked server names
#   data.agentjail.config.mcp.servers : object         — per-server config (optional)
#     data.agentjail.config.mcp.servers[<server>].allowed_tools : array<string>
#       When non-empty, only listed tool names are permitted for that server.
#       When absent or empty, all tools of the server are permitted (back-compat).
#     data.agentjail.config.mcp.servers[<server>].blocked_tools : array<string>
#       Tools listed here are always denied, even if the server is allowed.
#     data.agentjail.config.mcp.servers[<server>].ask_tools : array<string>
#       Tools listed here require user confirmation before execution.
#
# Semantics:
#   1. If the MCP server matches a blocked pattern → deny (blocked takes precedence).
#   2. If the MCP server matches an allowed pattern AND the tool is in blocked_tools
#      → deny (mcp_policy/tool_blocked).
#   2b. If the MCP server matches an allowed pattern AND has a non-empty allowed_tools
#      list AND the tool is not in that list → deny (mcp_policy/tool_not_allowed).
#   2c. If the MCP server matches an allowed pattern AND the tool is in ask_tools
#      → ask (mcp_policy/tool_ask).
#   3. If the MCP server matches an allowed pattern → allow.
#   4. If it matches neither (or the allowlist is empty) → deny (unknown / not in allowlist).
#   5. Non-MCP tool calls → no candidate from this rule (falls through to other policies).
#
# Safe defaults when config is absent:
#   allowed: []  (deny all — fail-closed for unknown environments)
#   blocked: ["*stripe*", "*payment*", "*billing*", "*twilio*", "*sendgrid*"]
#
# Example ~/.agentjail/policy.yaml:
#   mcp:
#     allowed:
#       - "filesystem"
#       - "fetch"
#     blocked:
#       - "*stripe*"
#       - "*payment*"
#     servers:
#       filesystem:
#         allowed_tools: ["read_file", "list_directory"]
#         blocked_tools: ["delete_file"]
#         ask_tools: ["write_file", "create_directory"]
#       fetch:
#         allowed_tools: ["fetch"]
#
# Hook input shape (Claude Code PreToolUse):
#   {
#     "hook_event": "PreToolUse",
#     "tool_name":  "mcp__filesystem__read_file",
#     "tool_input": {"path": "/tmp/foo"},
#     "session_id": "...",
#     "cwd": "/Users/dev/project"
#   }
#
# MCP tool names follow the pattern mcp__<server_name>__<tool_name>.
# Tools with underscores in their name use double-underscore as the only
# separator: mcp__filesystem__read_multiple_files → server=filesystem,
# tool=read_multiple_files.

package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Extract the MCP server name from tool_name "mcp__<server>__<tool>".
# Undefined (no value) when the input is not an MCP tool call.
mcp_server_name := server if {
    parts := split(input.tool_name, "__")
    count(parts) >= 3
    parts[0] == "mcp"
    server := parts[1]
}

# True only for MCP tool calls.
is_mcp_call if {
    startswith(input.tool_name, "mcp__")
}

# Safe default: empty allowlist (deny all MCP) when config absent.
allowed_patterns := data.agentjail.config.mcp.allowed if {
    data.agentjail.config.mcp.allowed
} else := []

# Safe default: standard high-risk blocked patterns when config absent.
blocked_patterns := data.agentjail.config.mcp.blocked if {
    data.agentjail.config.mcp.blocked
} else := ["*stripe*", "*payment*", "*billing*", "*twilio*", "*sendgrid*"]

# True if any blocked pattern matches the server name.
any_blocked if {
    some pattern in blocked_patterns
    glob.match(pattern, [], mcp_server_name)
}

# True if any allowed pattern matches the server name.
any_allowed if {
    some pattern in allowed_patterns
    glob.match(pattern, [], mcp_server_name)
}

# Extract the MCP tool name from "mcp__<server>__<tool>" (parts[2:] joined).
# For a tool like "read_multiple_files" in "mcp__filesystem__read_multiple_files",
# parts = ["mcp", "filesystem", "read_multiple_files"] and tool = "read_multiple_files".
# For multi-segment tools (if any), parts[2:] are re-joined with "__".
mcp_tool_name := tool if {
    parts := split(input.tool_name, "__")
    count(parts) >= 3
    parts[0] == "mcp"
    tool := concat("__", array.slice(parts, 2, count(parts)))
}

# Per-server allowed_tools list from config. Returns the list if defined,
# otherwise returns an empty array (back-compat: all tools allowed).
server_allowed_tools := tools if {
    tools := data.agentjail.config.mcp.servers[mcp_server_name].allowed_tools
} else := []

# True when this server has a non-empty per-tool allowlist AND the requested
# tool is NOT in it AND is not in ask_tools or blocked_tools — i.e., the
# call is genuinely unknown and should be denied at the tool level.
# Tools in ask_tools or blocked_tools are handled by their own rules.
tool_not_allowed if {
    count(server_allowed_tools) > 0
    not mcp_tool_name in server_allowed_tools
    not mcp_tool_name in server_ask_tools
    not mcp_tool_name in server_blocked_tools
}

# Per-server blocked_tools list. Tools here are always denied.
server_blocked_tools := tools if {
    tools := data.agentjail.config.mcp.servers[mcp_server_name].blocked_tools
} else := []

# Per-server ask_tools list. Tools here trigger a user prompt.
server_ask_tools := tools if {
    tools := data.agentjail.config.mcp.servers[mcp_server_name].ask_tools
} else := []

# True when this tool is in the per-server blocked list.
tool_blocked if {
    count(server_blocked_tools) > 0
    mcp_tool_name in server_blocked_tools
}

# True when this tool is in the per-server ask list.
tool_ask if {
    count(server_ask_tools) > 0
    mcp_tool_name in server_ask_tools
}

# ---------------------------------------------------------------------------
# Candidate rules — all guarded by is_mcp_call so non-MCP tools contribute
# no MCP candidates.
# Priority (deny > ask > allow) is enforced by the resolver.
# ---------------------------------------------------------------------------

# Rule 1: blocked patterns take precedence over the allowlist.
candidate contains r if {
    is_mcp_call
    some pattern in blocked_patterns
    glob.match(pattern, [], mcp_server_name)
    msg := sprintf("MCP server %q matches blocked pattern %q", [mcp_server_name, pattern])
    impact_msg := sprintf("would call blocked MCP server %q", [mcp_server_name])
    r := {
        "action":  "deny",
        "rule_id": "mcp_policy/blocked",
        "reason":  msg,
        "impact":  impact_msg,
    }
}

# Rule 2: server is allowed but the specific tool is not in the per-tool allowlist.
candidate contains r if {
    is_mcp_call
    not any_blocked
    any_allowed
    tool_not_allowed
    msg := sprintf(
        "MCP tool %q on server %q is not in the allowed_tools list",
        [mcp_tool_name, mcp_server_name],
    )
    r := {
        "action":  "deny",
        "rule_id": "mcp_policy/tool_not_allowed",
        "reason":  msg,
    }
}

# Rule 2b: server allowed but specific tool is in blocked_tools.
candidate contains r if {
    is_mcp_call
    not any_blocked
    any_allowed
    tool_blocked
    msg := sprintf(
        "MCP tool %q on server %q is in the blocked_tools list",
        [mcp_tool_name, mcp_server_name],
    )
    r := {
        "action":  "deny",
        "rule_id": "mcp_policy/tool_blocked",
        "reason":  msg,
        "impact":  sprintf("would call blocked tool %q on MCP server %q", [mcp_tool_name, mcp_server_name]),
    }
}

# Rule 2c: server allowed but specific tool requires user confirmation.
candidate contains r if {
    is_mcp_call
    not any_blocked
    any_allowed
    not tool_blocked
    not tool_not_allowed
    tool_ask
    msg := sprintf(
        "MCP tool %q on server %q requires user confirmation (ask_tools)",
        [mcp_tool_name, mcp_server_name],
    )
    r := {
        "action":  "ask",
        "rule_id": "mcp_policy/tool_ask",
        "reason":  msg,
        "impact":  sprintf("would call %q on MCP server %q — requires approval", [mcp_tool_name, mcp_server_name]),
    }
}

# Rule 3: server is in the allowlist (and not blocked, tool is permitted, and
# not in blocked_tools or ask_tools).
candidate contains r if {
    is_mcp_call
    not any_blocked
    some pattern in allowed_patterns
    glob.match(pattern, [], mcp_server_name)
    not tool_not_allowed
    not tool_blocked
    not tool_ask
    msg := sprintf("MCP server %q is in the allowlist", [mcp_server_name])
    r := {
        "action":  "allow",
        "rule_id": "mcp_policy/allowed",
        "reason":  msg,
    }
}

# Rule 4: MCP server not in the allowlist — deny with guidance.
candidate contains r if {
    is_mcp_call
    not any_blocked
    not any_allowed
    msg := sprintf("MCP server %q is not in the allowlist — add it to ~/.agentjail/policy.yaml", [mcp_server_name])
    impact_msg := sprintf("would call unallowlisted MCP server %q", [mcp_server_name])
    r := {
        "action":  "deny",
        "rule_id": "mcp_policy/unknown",
        "reason":  msg,
        "impact":  impact_msg,
    }
}
