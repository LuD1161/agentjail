package agentjail.default

import future.keywords.if

# --- cred rules (Phase 2 / Stream B.2) ---

test_cred_allow_when_auto_approve if {
	decision == {"action": "allow", "rule_id": "cred-auto-approve"} with input as {
		"action": "cred_use",
		"principal": {"attr": {"agent": "comp-intel"}},
		"resource":  {"attr": {"cap_id": "postgres.analytics_ro"}},
		"context": {"home": "/Users/me"},
	} with data.agentjail.caps as {
		"comp-intel": {
			"postgres.analytics_ro": {"auto_approve": true},
		},
	}
}

test_cred_ask_when_not_auto_approve if {
	decision == {"action": "ask", "rule_id": "cred-needs-approval"} with input as {
		"action": "cred_use",
		"principal": {"attr": {"agent": "comp-intel"}},
		"resource":  {"attr": {"cap_id": "postgres.prod_ro"}},
		"context": {"home": "/Users/me"},
	} with data.agentjail.caps as {
		"comp-intel": {
			"postgres.prod_ro": {"auto_approve": false},
		},
	}
}

test_cred_deny_when_cap_missing if {
	decision == {"action": "deny", "rule_id": "cred-not-granted",
	             "reason": "capability postgres.x not assigned to comp-intel"} with input as {
		"action": "cred_use",
		"principal": {"attr": {"agent": "comp-intel"}},
		"resource":  {"attr": {"cap_id": "postgres.x"}},
		"context": {"home": "/Users/me"},
	} with data.agentjail.caps as {
		"comp-intel": {"other.cap": {"auto_approve": true}},
	}
}

test_cred_deny_when_slug_unknown if {
	decision == {"action": "deny", "rule_id": "cred-not-granted",
	             "reason": "capability c.x not assigned to ghost"} with input as {
		"action": "cred_use",
		"principal": {"attr": {"agent": "ghost"}},
		"resource":  {"attr": {"cap_id": "c.x"}},
		"context": {"home": "/Users/me"},
	} with data.agentjail.caps as {}
}

# --- self-tamper rule ---

test_self_tamper_direct_write if {
	decision == {"action": "deny", "rule_id": "self-tamper-agentjail-dir",
	             "reason": "wrapped agents may not write inside ~/.agentjail/"} with input as {
		"action": "write",
		"principal": {"attr": {"agent": "comp-intel"}},
		"resource": {"attr": {"path": "/Users/me/.agentjail/capabilities.yaml"}},
		"context": {"home": "/Users/me"},
	}
}

test_self_tamper_rename_over if {
	decision == {"action": "deny", "rule_id": "self-tamper-agentjail-dir",
	             "reason": "wrapped agents may not write inside ~/.agentjail/"} with input as {
		"action": "write",
		"principal": {"attr": {"agent": "comp-intel"}},
		"resource": {"attr": {"path": "/Users/me/.agentjail/pending.jsonl"}},
		"context": {"home": "/Users/me"},
	}
}

test_self_tamper_append if {
	decision == {"action": "deny", "rule_id": "self-tamper-agentjail-dir",
	             "reason": "wrapped agents may not write inside ~/.agentjail/"} with input as {
		"action": "write",
		"principal": {"attr": {"agent": "seo-agent"}},
		"resource": {"attr": {"path": "/Users/me/.agentjail/leases.jsonl"}},
		"context": {"home": "/Users/me"},
	}
}

test_self_tamper_no_agent_slug_allows_write if {
	# Operator outside a wrapped session can still write -- the rule
	# checks principal.attr.agent is non-empty.
	decision == {"action": "allow"} with input as {
		"action": "write",
		"principal": {"attr": {"agent": ""}},
		"resource": {"attr": {"path": "/Users/me/.agentjail/capabilities.yaml"}},
		"context": {"home": "/Users/me"},
		"hook": "file",
	}
}

# --- exec: rm -rf ~ ---

test_rm_rf_home if {
	decision == {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"} with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"positional": ["/Users/me"],
		"argv_raw": ["rm", "-rf", "~"],
		"paths_resolved": ["/Users/me"],
		"context": {"home": "/Users/me"},
	}
}

# --- exec: rm -fr ~/ ---

test_rm_fr_home_slash if {
	decision == {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"} with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-f", "-r"],
		"positional": ["/Users/me/"],
		"argv_raw": ["rm", "-fr", "~/"],
		"paths_resolved": ["/Users/me/"],
		"context": {"home": "/Users/me"},
	}
}

# --- exec: rm -r -f $HOME ---

test_rm_r_f_home_var if {
	decision == {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"} with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"positional": ["/Users/me"],
		"argv_raw": ["rm", "-r", "-f", "$HOME"],
		"paths_resolved": ["/Users/me"],
		"context": {"home": "/Users/me"},
	}
}

# --- exec: find ~ -delete ---

test_find_delete_in_home if {
	decision == {"action": "deny", "rule_id": "no-find-delete-in-home"} with input as {
		"hook": "exec",
		"program": "find",
		"flags": [],
		"positional": ["/Users/me/projects"],
		"argv_raw": ["find", "~", "-delete"],
		"paths_resolved": ["/Users/me/projects"],
		"context": {"home": "/Users/me"},
	}
}

# --- file: write to .env ---

test_write_dotenv if {
	decision == {"action": "ask", "rule_id": "confirm-dotfile-write"} with input as {
		"hook": "file",
		"op": "writeFile",
		"path": "/Users/me/app/.env",
		"context": {"home": "/Users/me"},
	}
}

# --- file: write to .ssh/config ---

test_write_ssh_config if {
	decision == {"action": "ask", "rule_id": "confirm-dotfile-write"} with input as {
		"hook": "file",
		"op": "writeFile",
		"path": "/Users/me/.ssh/config",
		"context": {"home": "/Users/me"},
	}
}

# --- http: evil.example.com (denied) ---

test_http_evil_denied if {
	decision == {"action": "deny", "rule_id": "api-allowlist"} with input as {
		"hook": "http",
		"method": "POST",
		"host": "evil.example.com",
		"port": 443,
		"context": {"home": "/Users/me"},
	}
}

# --- http: api.anthropic.com (allowed) ---

test_http_anthropic_allowed if {
	decision == {"action": "allow"} with input as {
		"hook": "http",
		"method": "POST",
		"host": "api.anthropic.com",
		"port": 443,
		"context": {"home": "/Users/me"},
	}
}

# --- http: githubusercontent.com subdomain (allowed) ---

test_http_githubusercontent_allowed if {
	decision == {"action": "allow"} with input as {
		"hook": "http",
		"host": "raw.githubusercontent.com",
		"port": 443,
		"context": {"home": "/Users/me"},
	}
}
