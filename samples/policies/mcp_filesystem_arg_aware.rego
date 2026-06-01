# mcp_filesystem_arg_aware.rego
#
# Inspect the PATH argument of mcp__filesystem__read_file and reject reads
# that target sensitive locations — even though the filesystem server itself
# is allowed.
#
# This closes the gap where an agent calls a permitted MCP server but with
# a dangerous argument. Core mcp_policy.rego gates by tool name
# (Level 1); this is Level 2 — argument validation. See ADR 0003 for the
# strategic direction.
#
# Demonstrates two things worth copying into your own rules:
#   1. Reading nested fields out of input.tool_input
#   2. Reusing the same sensitive-path patterns the file_policy uses, so
#      your custom rule stays consistent with the rest of the policy stack.
#
# Pattern: uses `candidate contains r if { ... }` (partial rule set entry) so this
# rule coexists cleanly with the core policies via resolver.rego. Do NOT use
# `decision = ...` (complete rule) — that would conflict with resolver.rego's
# single complete `decision` rule.

package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "mcp__filesystem__read_file"
    path := input.tool_input.path
    sensitive_path_pattern(path)
    r := {
        "action":  "deny",
        "rule_id": "samples/mcp-filesystem-sensitive-arg",
        "reason":  sprintf("filesystem.read_file requested sensitive path %q", [path]),
        "impact":  "would read sensitive file via MCP filesystem server (bypasses file_policy)",
    }
}

# Mirrors file_policy.rego is_sensitive_path predicates. In a real deployment
# you'd factor these into a shared module under agentpolicy/policies/lib/
# rather than duplicating — kept inline here so the sample is self-contained.
sensitive_path_pattern(p) if regex.match(`/Users/[^/]+/\.ssh(/|$)`, p)
sensitive_path_pattern(p) if regex.match(`/Users/[^/]+/\.aws(/|$)`, p)
sensitive_path_pattern(p) if regex.match(`/Users/[^/]+/\.gnupg(/|$)`, p)
sensitive_path_pattern(p) if regex.match(`/Users/[^/]+/\.agentjail(/|$)`, p)
sensitive_path_pattern(p) if regex.match(`^/etc/`, p)
sensitive_path_pattern(p) if regex.match(`\.env(\.[a-zA-Z0-9_]+)?$`, p)
sensitive_path_pattern(p) if regex.match(`\.(pem|p12|pfx|jks|keystore)$`, p)
sensitive_path_pattern(p) if regex.match(`(^|/)id_(rsa|ed25519|ecdsa|dsa)$`, p)
sensitive_path_pattern(p) if regex.match(`(^|/)credentials$`, p)
sensitive_path_pattern(p) if regex.match(`(^|/)\.netrc$`, p)
