# Tests for the MCP server allowlist policy (mcp_policy.rego).
#
# Coverage:
#   1. Known-good MCP server in allowlist → allow
#   2. Unknown MCP server not in allowlist → deny (mcp_policy/unknown)
#   3. Blocked pattern match ("stripe") → deny (mcp_policy/blocked)
#   4. Non-MCP tool call → no decision from this policy (falls through)
#   5. Empty allowlist → deny all MCP (fail-closed default)
#   6. Multiple blocked patterns — all fire correctly
#   7. Blocked takes precedence over allowlist
#  19. Tool in blocked_tools → deny (mcp_policy/tool_blocked)
#  20. Tool in ask_tools → ask (mcp_policy/tool_ask)
#  21. Tool in both blocked_tools and ask_tools → deny wins
#  22. Tool in allowed_tools AND ask_tools → ask
#  23. Tool not in any list on allowed server → allow (backwards compatible)
#  24. Empty blocked_tools/ask_tools → no effect (backwards compatible)
#   8. Default blocked patterns fire when config is absent
#   9. Exact server name in allowlist (no glob wildcard needed)
#  10. Wildcard in allowlist pattern

package agentjail

import future.keywords.if

# ---------------------------------------------------------------------------
# Shared config fixtures
# ---------------------------------------------------------------------------

standard_config := {
    "mcp": {
        "allowed": ["filesystem", "fetch", "github"],
        "blocked": ["*stripe*", "*payment*", "*billing*", "*twilio*", "*sendgrid*"],
    },
}

# ---------------------------------------------------------------------------
# 1. Known-good MCP server in allowlist → allow
# ---------------------------------------------------------------------------

test_known_mcp_allowed if {
    decision == {
        "action": "allow",
        "reason": "MCP server \"filesystem\" is in the allowlist",
        "rule_id": "mcp_policy/allowed",
    } with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {"path": "/tmp/foo"},
        "session_id": "sess-123",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config
}

test_fetch_mcp_allowed if {
    decision == {
        "action": "allow",
        "reason": "MCP server \"fetch\" is in the allowlist",
        "rule_id": "mcp_policy/allowed",
    } with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__fetch__get",
        "tool_input": {"url": "https://example.com"},
        "session_id": "sess-456",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config
}

test_github_mcp_allowed if {
    decision == {
        "action": "allow",
        "reason": "MCP server \"github\" is in the allowlist",
        "rule_id": "mcp_policy/allowed",
    } with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__github__list_repos",
        "tool_input": {},
        "session_id": "sess-789",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config
}

# ---------------------------------------------------------------------------
# 2. Unknown MCP server not in allowlist → deny (mcp_policy/unknown)
# ---------------------------------------------------------------------------

test_unknown_mcp_denied if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__unknown_server__some_tool",
        "tool_input": {},
        "session_id": "sess-abc",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
    contains(d.reason, "unknown_server")
    contains(d.reason, "not in the allowlist")
}

test_custom_server_not_in_allowlist_denied if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__my_custom_server__do_thing",
        "tool_input": {},
        "session_id": "sess-def",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

# ---------------------------------------------------------------------------
# 3. Blocked pattern match ("stripe") → deny (mcp_policy/blocked)
# ---------------------------------------------------------------------------

test_stripe_mcp_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__stripe__charge_card",
        "tool_input": {"amount": 100},
        "session_id": "sess-ghi",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "stripe")
    contains(d.reason, "blocked pattern")
}

test_my_stripe_integration_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__my_stripe_integration__pay",
        "tool_input": {},
        "session_id": "sess-jkl",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "my_stripe_integration")
}

# ---------------------------------------------------------------------------
# 4. Non-MCP tool call → MCP rules must not fire (falls through to file_policy)
#
# Non-MCP tools (Bash, Write, Read) do not start with "mcp__" so is_mcp_call
# is false and none of the three mcp_policy decision rules can fire.  The
# package-level `default decision` in file_policy.rego handles those paths.
# We verify here that is_mcp_call is false for such tools (i.e. the MCP gate
# correctly excludes them), and that the resulting decision does NOT carry any
# mcp_policy/* rule_id.
# ---------------------------------------------------------------------------

test_bash_tool_not_mcp if {
    # is_mcp_call must be false for a plain Bash tool.
    not is_mcp_call with input as {
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "session_id": "sess-mno",
        "cwd": "/Users/dev/project",
    }
}

test_write_tool_not_mcp if {
    not is_mcp_call with input as {
        "hook_event": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/out.txt", "content": "hello"},
        "session_id": "sess-pqr",
        "cwd": "/Users/dev/project",
    }
}

test_read_tool_not_mcp if {
    not is_mcp_call with input as {
        "hook_event": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/hosts"},
        "session_id": "sess-stu",
        "cwd": "/Users/dev/project",
    }
}

test_non_mcp_decision_has_no_mcp_rule_id if {
    # For a Bash tool, whatever decision is produced must NOT have an
    # mcp_policy/* rule_id — the MCP rules must not touch non-MCP tool calls.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "session_id": "sess-mno",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config
    not startswith(d.rule_id, "mcp_policy/")
}

# ---------------------------------------------------------------------------
# 5. Empty allowlist → deny all MCP (fail-closed default)
# ---------------------------------------------------------------------------

test_empty_allowlist_denies_any_mcp if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {},
        "session_id": "sess-vwx",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": [],
            "blocked": [],
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

test_empty_allowlist_even_fetch_denied if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__fetch__get",
        "tool_input": {},
        "session_id": "sess-yz1",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": [],
            "blocked": [],
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

# ---------------------------------------------------------------------------
# 6. Multiple blocked patterns — billing, twilio, sendgrid all fire
# ---------------------------------------------------------------------------

test_billing_server_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__billing_service__invoice",
        "tool_input": {},
        "session_id": "sess-234",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "billing_service")
}

test_twilio_server_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__twilio__send_sms",
        "tool_input": {},
        "session_id": "sess-345",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "twilio")
}

test_sendgrid_server_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__sendgrid__send_email",
        "tool_input": {},
        "session_id": "sess-456",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "sendgrid")
}

test_payment_gateway_blocked if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__payment_gateway__charge",
        "tool_input": {},
        "session_id": "sess-567",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as standard_config

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
    contains(d.reason, "payment_gateway")
}

# ---------------------------------------------------------------------------
# 7. Blocked takes precedence over allowlist
# ---------------------------------------------------------------------------

test_blocked_overrides_allowlist if {
    # Even if the server name is explicitly in the allowlist,
    # the blocked pattern takes precedence.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__stripe__charge",
        "tool_input": {},
        "session_id": "sess-678",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["stripe"],
            "blocked": ["*stripe*"],
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
}

# ---------------------------------------------------------------------------
# 8. Default blocked patterns fire when config is absent
# ---------------------------------------------------------------------------

test_default_blocked_stripe_no_config if {
    # When no config is provided at all, the default blocked list fires.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__stripe__charge",
        "tool_input": {},
        "session_id": "sess-789",
        "cwd": "/Users/dev/project",
    }
    # No `with data.agentjail.config as ...` — exercises the else := [] / else := [...] fallbacks.

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
}

test_default_deny_unknown_no_config if {
    # No config: allowed defaults to [] → any non-blocked server is denied as unknown.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {},
        "session_id": "sess-890",
        "cwd": "/Users/dev/project",
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

# ---------------------------------------------------------------------------
# 9. Wildcard in allowlist pattern
# ---------------------------------------------------------------------------

test_wildcard_allowlist_pattern if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__anthropic_internal_tools__query",
        "tool_input": {},
        "session_id": "sess-901",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["anthropic_*"],
            "blocked": [],
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

test_wildcard_allowlist_no_match if {
    # Pattern "*_tools" does not match "filesystem".
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {},
        "session_id": "sess-012",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["*_tools"],
            "blocked": [],
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

# ---------------------------------------------------------------------------
# 11. Per-tool gating: server allowed, allowed_tools=["read_file"],
#     call read_file → allow (tool is in the list).
# ---------------------------------------------------------------------------

test_per_tool_allowed_read_file if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {"path": "/tmp/foo"},
        "session_id": "sess-T133-1",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file", "list_directory"],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# ---------------------------------------------------------------------------
# 12. Per-tool gating: server allowed, allowed_tools=["read_file"],
#     call write_file → deny (tool NOT in list).
# ---------------------------------------------------------------------------

test_per_tool_denied_write_file if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {"path": "/tmp/out.txt", "content": "oops"},
        "session_id": "sess-T133-2",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_not_allowed"
    contains(d.reason, "write_file")
    contains(d.reason, "filesystem")
}

# ---------------------------------------------------------------------------
# 13. Back-compat: server allowed, allowed_tools=[] → allow any tool.
# ---------------------------------------------------------------------------

test_per_tool_empty_tools_allows_all if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {},
        "session_id": "sess-T133-3",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": [],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# ---------------------------------------------------------------------------
# 14. Back-compat: server allowed, servers key absent → allow any tool.
# ---------------------------------------------------------------------------

test_per_tool_servers_absent_allows_all if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {},
        "session_id": "sess-T133-4",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# ---------------------------------------------------------------------------
# 15. Blocked server + allowed_tools specified → blocked wins (precedence).
# ---------------------------------------------------------------------------

test_blocked_wins_over_per_tool_allowlist if {
    # Even if stripe is in the allowed list and has allowed_tools,
    # the blocked pattern "*stripe*" takes precedence.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__stripe__charge_card",
        "tool_input": {},
        "session_id": "sess-T133-5",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["stripe"],
            "blocked": ["*stripe*"],
            "servers": {
                "stripe": {
                    "allowed_tools": ["charge_card"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/blocked"
}

# ---------------------------------------------------------------------------
# 16. Server not in allowlist → unknown-deny rule still fires regardless of
#     whether servers config is present for it.
# ---------------------------------------------------------------------------

test_unknown_server_deny_despite_servers_config if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__dangerous__exploit",
        "tool_input": {},
        "session_id": "sess-T133-6",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "dangerous": {
                    "allowed_tools": ["exploit"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/unknown"
}

# ---------------------------------------------------------------------------
# 17. Tool name with underscores: mcp__filesystem__read_multiple_files
#     is parsed as server=filesystem, tool=read_multiple_files.
# ---------------------------------------------------------------------------

test_per_tool_underscore_in_tool_name_allowed if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_multiple_files",
        "tool_input": {},
        "session_id": "sess-T133-7a",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file", "read_multiple_files", "list_directory"],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

test_per_tool_underscore_in_tool_name_denied if {
    # read_multiple_files is not in the list — should be denied.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_multiple_files",
        "tool_input": {},
        "session_id": "sess-T133-7b",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file", "list_directory"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_not_allowed"
    contains(d.reason, "read_multiple_files")
}

# ---------------------------------------------------------------------------
# 18. Multiple servers with independent per-tool allowlists.
#     filesystem has read_file; fetch has fetch. Each call evaluated correctly.
# ---------------------------------------------------------------------------

test_multiple_servers_independent_allowlists_filesystem if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {},
        "session_id": "sess-T133-8a",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem", "fetch"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                },
                "fetch": {
                    "allowed_tools": ["fetch"],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

test_multiple_servers_independent_allowlists_filesystem_denied if {
    # write_file is not in filesystem's allowed_tools.
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {},
        "session_id": "sess-T133-8b",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem", "fetch"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                },
                "fetch": {
                    "allowed_tools": ["fetch"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_not_allowed"
}

test_multiple_servers_independent_allowlists_fetch if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__fetch__fetch",
        "tool_input": {"url": "https://example.com"},
        "session_id": "sess-T133-8c",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem", "fetch"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                },
                "fetch": {
                    "allowed_tools": ["fetch"],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# ---------------------------------------------------------------------------
# 19. Tool in blocked_tools → deny (mcp_policy/tool_blocked)
# ---------------------------------------------------------------------------

test_tool_in_blocked_tools_denied if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__delete_file",
        "tool_input": {"path": "/tmp/foo"},
        "session_id": "sess-T34-1",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": [],
                    "blocked_tools": ["delete_file"],
                    "ask_tools": [],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_blocked"
    contains(d.reason, "delete_file")
    contains(d.reason, "filesystem")
}

# ---------------------------------------------------------------------------
# 20. Tool in ask_tools → ask (mcp_policy/tool_ask)
# ---------------------------------------------------------------------------

test_tool_in_ask_tools_ask if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {"path": "/tmp/out.txt", "content": "data"},
        "session_id": "sess-T34-2",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": [],
                    "blocked_tools": [],
                    "ask_tools": ["write_file"],
                },
            },
        },
    }

    d.action == "ask"
    d.rule_id == "mcp_policy/tool_ask"
    contains(d.reason, "write_file")
    contains(d.reason, "filesystem")
}

# ---------------------------------------------------------------------------
# 21. Tool in both blocked_tools and ask_tools → deny wins (resolver priority)
# ---------------------------------------------------------------------------

test_tool_in_blocked_and_ask_deny_wins if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__dangerous_tool",
        "tool_input": {},
        "session_id": "sess-T34-3",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": [],
                    "blocked_tools": ["dangerous_tool"],
                    "ask_tools": ["dangerous_tool"],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_blocked"
}

# ---------------------------------------------------------------------------
# 22. Tool in allowed_tools AND ask_tools → ask (ask_tools takes precedence
#     for listed tools over the generic allow).
# ---------------------------------------------------------------------------

test_tool_in_allowed_and_ask_tools_ask_wins if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__write_file",
        "tool_input": {},
        "session_id": "sess-T34-4",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file", "write_file"],
                    "blocked_tools": [],
                    "ask_tools": ["write_file"],
                },
            },
        },
    }

    d.action == "ask"
    d.rule_id == "mcp_policy/tool_ask"
}

# ---------------------------------------------------------------------------
# 23. Tool NOT in any list on an allowed server → allow (backwards compatible)
# ---------------------------------------------------------------------------

test_tool_not_in_any_list_allowed if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {"path": "/tmp/foo"},
        "session_id": "sess-T34-5",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": [],
                    "blocked_tools": [],
                    "ask_tools": [],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# ---------------------------------------------------------------------------
# 24. Empty blocked_tools/ask_tools → no effect (backwards compatible)
# ---------------------------------------------------------------------------

test_empty_blocked_ask_tools_no_effect if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__read_file",
        "tool_input": {},
        "session_id": "sess-T34-6",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                    "blocked_tools": [],
                    "ask_tools": [],
                },
            },
        },
    }

    d.action == "allow"
    d.rule_id == "mcp_policy/allowed"
}

# Tool in blocked_tools also blocks when allowed_tools is set and includes it.
test_blocked_tools_overrides_allowed_tools if {
    d := decision with input as {
        "hook_event": "PreToolUse",
        "tool_name": "mcp__filesystem__delete_file",
        "tool_input": {},
        "session_id": "sess-T34-7",
        "cwd": "/Users/dev/project",
    } with data.agentjail.config as {
        "mcp": {
            "allowed": ["filesystem"],
            "blocked": [],
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file", "delete_file"],
                    "blocked_tools": ["delete_file"],
                    "ask_tools": [],
                },
            },
        },
    }

    d.action == "deny"
    d.rule_id == "mcp_policy/tool_blocked"
}
