package agentjail.experimental

import future.keywords.if

# Demonstrates the principal-shape rule firing end-to-end against the
# Cerbos-shape input the daemon now layers alongside the legacy fields.

test_comp_intel_read_in_repo_allowed if {
	decision == {"action": "allow", "rule_id": "comp-intel-read-in-cwd-repo"} with input as {
		"principal": {
			"id": "comp-intel:sid",
			"attr": {"agent": "comp-intel", "user": "alice", "cwd_repo": "/Users/alice/repo"},
		},
		"resource": {
			"kind": "file",
			"id":   "file:/Users/alice/repo/main.go",
			"attr": {"path": "/Users/alice/repo/main.go"},
		},
		"action": "read",
	}
}

test_comp_intel_write_outside_repo_denied if {
	decision == {"action": "deny", "rule_id": "comp-intel-no-write-outside-cwd-repo"} with input as {
		"principal": {
			"id": "comp-intel:sid",
			"attr": {"agent": "comp-intel", "user": "alice", "cwd_repo": "/Users/alice/repo"},
		},
		"resource": {
			"kind": "file",
			"id":   "file:/Users/alice/secrets/.env",
			"attr": {"path": "/Users/alice/secrets/.env"},
		},
		"action": "write",
	}
}

test_other_agent_unaffected if {
	# A different agent's writes outside cwd_repo are NOT denied by the
	# experimental rule (it gates on agent == comp-intel).
	decision == {"action": "allow"} with input as {
		"principal": {
			"id": "claude-code-mbp:sid",
			"attr": {"agent": "claude-code-mbp", "user": "alice", "cwd_repo": "/Users/alice/repo"},
		},
		"resource": {
			"kind": "file",
			"id":   "file:/tmp/x",
			"attr": {"path": "/tmp/x"},
		},
		"action": "write",
	}
}

test_default_allow_when_nothing_matches if {
	decision == {"action": "allow"} with input as {}
}
