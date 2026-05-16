# Tests for agentpolicy/policies/resolver.rego — effective_candidate + locked_rules.
#
# Test taxonomy (ADR 0014):
#   A. Disabled non-locked deny is suppressed (falls through to allow/ask)
#   B. Disabled locked rules still fire (self-protection cannot be turned off)
#   C. Glob boundary: file_policy/* suppresses non-locked but not agentjail_self
#   D. All non-locked candidates disabled → resolver/default ask
#   E. effective_candidate set: disabled rule_id is absent
#   F. locked_rules constant sanity check
#
# Input shape (hook-wire format):
#   input.hook_event  "PreToolUse"
#   input.tool_name   "Write" | "Edit" | "Read" | "Bash"
#   input.tool_input  {file_path?, command?, ...}
#   input.cwd         string
package agentjail_test

import future.keywords.if
import data.agentjail

# ---------------------------------------------------------------------------
# Helpers (plain data, no `with` in rule head)
# ---------------------------------------------------------------------------

write_input(fp) := {
	"hook_event": "PreToolUse",
	"tool_name": "Write",
	"tool_input": {"file_path": fp, "content": "x"},
	"session_id": "s-resolver-test",
	"cwd": "/Users/dev/myproject",
}

read_input(p) := {
	"hook_event": "PreToolUse",
	"tool_name": "Read",
	"tool_input": {"path": p},
	"session_id": "s-resolver-test",
	"cwd": "/Users/dev/myproject",
}

bash_input_r(cmd) := {
	"hook_event": "PreToolUse",
	"tool_name": "Bash",
	"tool_input": {"command": cmd, "description": ""},
	"session_id": "s-resolver-test",
	"cwd": "/Users/dev/myproject",
}

unknown_tool_input := {
	"hook_event": "PreToolUse",
	"tool_name":  "UnknownTool",
	"tool_input": {},
	"session_id": "s",
	"cwd":        "/Users/dev/project",
}

# Config with a single disabled non-locked rule.
cfg_disable_sensitive_credential := {"disabled_rules": ["file_policy/sensitive_credential"]}

# Config disabling all file_policy/* rules (non-locked ones suppressed; agentjail_self locked).
cfg_disable_file_policy_star := {"disabled_rules": ["file_policy/*"]}

# Config listing EVERY locked rule + file_policy/* and command_policy/* —
# the ultimate adversarial policy.yaml to prove self-protection holds.
cfg_disable_all_locked := {"disabled_rules": [
	"file_policy/agentjail_self",
	"library/no-daemon-kill",
	"command_policy/no-policy-mutation",
	"resolver/*",
	"resolver/default",
	"file_policy/*",
	"command_policy/*",
	"library/*",
]}

cfg_disable_file_and_command_star := {"disabled_rules": ["file_policy/*", "command_policy/*"]}

# ---------------------------------------------------------------------------
# Section A: Disabled non-locked deny is suppressed
#
# file_policy/sensitive_credential is NOT locked. Disabling it suppresses
# its candidate. A read of ~/.aws/credentials normally denies via
# file_policy/sensitive_credential. With it disabled, the decision should
# NOT be deny from that rule.
# ---------------------------------------------------------------------------

test_resolver_disabled_sensitive_credential_suppressed if {
	d := agentjail.decision with input as read_input("/Users/dev/.aws/credentials")
	               with data.agentjail.config as cfg_disable_sensitive_credential
	d.rule_id != "file_policy/sensitive_credential"
}

test_resolver_disabled_sensitive_credential_not_in_effective_candidate if {
	cands := {c | some c in agentjail.effective_candidate; c.rule_id == "file_policy/sensitive_credential"}
	        with input as read_input("/Users/dev/.aws/credentials")
	        with data.agentjail.config as cfg_disable_sensitive_credential
	count(cands) == 0
}

test_resolver_disabled_file_policy_star_falls_to_ask if {
	# Disable all file_policy/* rules. ~/.aws/credentials has no other deny rule
	# that fires, so the resolver/default (ask) takes over.
	d := agentjail.decision with input as read_input("/Users/dev/.aws/credentials")
	               with data.agentjail.config as cfg_disable_file_policy_star
	d.action == "ask"
	d.rule_id != "file_policy/sensitive_credential"
}

# ---------------------------------------------------------------------------
# Section B: Disabled locked rules STILL fire
#
# Key security test: even if policy.yaml lists every locked rule_id in
# disabled_rules, those candidates must still appear in effective_candidate
# and win the decision. This proves a hand-edited policy.yaml cannot unlock
# self-protection.
# ---------------------------------------------------------------------------

# B1: file_policy/agentjail_self is LOCKED — cannot be disabled.
# Write to ~/.agentjail/policy.yaml must STILL deny even when all locked
# rule_ids are listed in disabled_rules.
test_resolver_agentjail_self_locked_cannot_be_disabled if {
	d := agentjail.decision with input as write_input("/Users/dev/.agentjail/policy.yaml")
	               with data.agentjail.config as cfg_disable_all_locked
	d.action == "deny"
	d.rule_id == "file_policy/agentjail_self"
}

# B2: agentjail_self appears in effective_candidate even when listed in disabled_rules.
test_resolver_agentjail_self_in_effective_candidate_even_when_listed_disabled if {
	cands := {c | some c in agentjail.effective_candidate; c.rule_id == "file_policy/agentjail_self"}
	        with input as write_input("/Users/dev/.agentjail/policy.yaml")
	        with data.agentjail.config as cfg_disable_all_locked
	count(cands) > 0
}

# B3: library/no-daemon-kill is LOCKED — cannot be disabled.
test_resolver_no_daemon_kill_locked_cannot_be_disabled if {
	d := agentjail.decision with input as bash_input_r("pkill -f agentjail-daemon")
	               with data.agentjail.config as cfg_disable_all_locked
	d.action == "deny"
	d.rule_id == "library/no-daemon-kill"
}

# B4: command_policy/no-policy-mutation is LOCKED — cannot be disabled.
test_resolver_no_policy_mutation_locked_cannot_be_disabled if {
	d := agentjail.decision with input as bash_input_r("agentjail policy disable file_policy/sensitive_credential")
	               with data.agentjail.config as cfg_disable_all_locked
	d.action == "deny"
	d.rule_id == "command_policy/no-policy-mutation"
}

# B5: resolver/default cannot be disabled via resolver/* glob.
# When no other candidate fires (unknown tool), resolver/default must fire.
test_resolver_default_cannot_be_disabled_via_glob if {
	d := agentjail.decision with input as unknown_tool_input
	               with data.agentjail.config as cfg_disable_all_locked
	d.rule_id == "resolver/default"
	d.action == "ask"
}

# ---------------------------------------------------------------------------
# Section C: Glob boundary
#
# file_policy/* matches file_policy/sensitive_credential (single segment)
# but NOT file_policy/agentjail_self (it is locked).
# Also verifies that * does not cross / boundaries (two-segment path test).
# ---------------------------------------------------------------------------

test_resolver_glob_boundary_file_policy_star_suppresses_sensitive_credential if {
	cands := {c | some c in agentjail.effective_candidate; c.rule_id == "file_policy/sensitive_credential"}
	        with input as read_input("/Users/dev/.aws/credentials")
	        with data.agentjail.config as cfg_disable_file_policy_star
	count(cands) == 0
}

test_resolver_glob_boundary_file_policy_star_does_not_suppress_agentjail_self if {
	# file_policy/agentjail_self is locked; glob file_policy/* matches it
	# lexicographically but locked_rules check prevents suppression.
	cands := {c | some c in agentjail.effective_candidate; c.rule_id == "file_policy/agentjail_self"}
	        with input as write_input("/Users/dev/.agentjail/policy.yaml")
	        with data.agentjail.config as cfg_disable_file_policy_star
	count(cands) > 0
}

# * does NOT cross / — rule_disabled must return false for file_policy/x/y
# when pattern is file_policy/* (only single-segment matches).
test_resolver_glob_boundary_no_cross_segment_match if {
	not agentjail.rule_disabled("file_policy/x/y")
	    with data.agentjail.config as cfg_disable_file_policy_star
}

# file_policy/* DOES match file_policy/sensitive_credential (one segment).
test_resolver_glob_boundary_single_segment_matches if {
	agentjail.rule_disabled("file_policy/sensitive_credential")
	    with data.agentjail.config as cfg_disable_file_policy_star
}

# Exact match also disables.
test_resolver_glob_exact_match_disables if {
	agentjail.rule_disabled("file_policy/sensitive_in_project")
	    with data.agentjail.config as {"disabled_rules": ["file_policy/sensitive_in_project"]}
}

# ---------------------------------------------------------------------------
# Section D: All non-locked candidates disabled → resolver/default ask
#
# Disable all file_policy/* and command_policy/* rules.
# An unknown path (no temp, no project, no sensitive) with file_policy/*
# disabled gets resolver/default ask.
# ---------------------------------------------------------------------------

test_resolver_all_non_locked_disabled_falls_to_default_ask if {
	# An unknown out-of-project path: no temp, not sensitive basename, not in cwd.
	d := agentjail.decision with input as read_input("/Users/other/unknown/file.txt")
	               with data.agentjail.config as cfg_disable_file_and_command_star
	d.action == "ask"
}

# ---------------------------------------------------------------------------
# Section E: effective_candidate composition sanity
#
# Without any disabled_rules, effective_candidate == candidate (no suppression).
# ---------------------------------------------------------------------------

test_resolver_no_disabled_rules_effective_contains_default_allow if {
	cands := {c | some c in agentjail.effective_candidate; c.rule_id == "command_policy/default-allow"}
	        with input as bash_input_r("echo hello")
	        with data.agentjail.config as {}
	count(cands) > 0
}

# ---------------------------------------------------------------------------
# Section F: locked_rules constant sanity
#
# The locked_rules set must be exactly the expected constant.
# Any change to locked_rules triggers this test — deliberate.
# ---------------------------------------------------------------------------

test_resolver_locked_rules_constant if {
	agentjail.locked_rules == {
		"file_policy/agentjail_self",
		"library/no-daemon-kill",
		"library/no-hook-self-disable",
		"command_policy/no-policy-mutation",
		"resolver/default",
	}
}
