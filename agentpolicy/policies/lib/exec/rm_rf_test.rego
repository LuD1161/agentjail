# Tests for data.agentpolicy.lib.exec.rm_rf
#
# 8 protected-path variants, each with:
#   - a deny case: `rm -rf <protected>` triggers the rule
#   - a control case: a benign exec (or `rm` against a non-protected path)
#     leaves the rule silent (no decision set)
#
# Variants (8 protected-path patterns):
#   1. /
#   2. $HOME           (input.context.home)
#   3. $HOME/.ssh
#   4. ~/.config       (caller has expanded ~ into input.context.home)
#   5. /etc
#   6. /usr/local
#   7. /var
#   8. /opt
package agentpolicy.lib.exec.rm_rf_test

import future.keywords.if
import data.agentpolicy.lib.exec.rm_rf

deny_verdict := {"action": "deny", "rule_id": "no-recursive-delete-of-protected-paths"}

# ---------------------------------------------------------------------------
# 1. /
# ---------------------------------------------------------------------------

test_deny_rm_rf_root if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_non_recursive_root if {
	# control: rm without -r/-R/--recursive must not trigger.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-f"],
		"paths_resolved": ["/"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 2. $HOME (exact match)
# ---------------------------------------------------------------------------

test_deny_rm_rf_home if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/Users/me"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_outside_home if {
	# control: a path outside any protected set must not trigger.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/tmp/build"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 3. $HOME/.ssh
# ---------------------------------------------------------------------------

test_deny_rm_rf_home_ssh if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["--recursive", "--force"],
		"paths_resolved": ["/Users/me/.ssh"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_ls_home_ssh if {
	# control: a non-rm program with the same paths must not trigger.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "ls",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/Users/me/.ssh"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 4. ~/.config (caller has expanded ~ to $HOME)
# ---------------------------------------------------------------------------

test_deny_rm_rf_home_config if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-R", "-f"],
		"paths_resolved": ["/Users/me/.config"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_missing_force_flag if {
	# control: missing -f must not trigger.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r"],
		"paths_resolved": ["/Users/me/.config"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 5. /etc
# ---------------------------------------------------------------------------

test_deny_rm_rf_etc if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/etc"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_etc_lookalike if {
	# control: /etcetera is NOT under /etc/ and is not protected.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/etcetera/scratch"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 6. /usr/local
# ---------------------------------------------------------------------------

test_deny_rm_rf_usr_local if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/usr/local"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_usr_local_lookalike if {
	# control: /usrland is NOT under /usr/ and is not protected.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/usrland/cache"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 7. /var
# ---------------------------------------------------------------------------

test_deny_rm_rf_var if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/var/log"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_var_lookalike if {
	# control: /vargrant is NOT under /var/ and is not protected.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/vargrant/data"],
		"context": {"home": "/Users/me"},
	}
}

# ---------------------------------------------------------------------------
# 8. /opt
# ---------------------------------------------------------------------------

test_deny_rm_rf_opt if {
	rm_rf.decision == deny_verdict with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/opt/homebrew"],
		"context": {"home": "/Users/me"},
	}
}

test_allow_rm_rf_opt_lookalike if {
	# control: /optical is NOT under /opt/ and is not protected.
	not rm_rf.decision with input as {
		"hook": "exec",
		"program": "rm",
		"flags": ["-r", "-f"],
		"paths_resolved": ["/optical/iso"],
		"context": {"home": "/Users/me"},
	}
}
