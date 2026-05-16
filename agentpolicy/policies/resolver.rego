# Package agentjail — resolver.
#
# All policy files (core + library + user custom) contribute entries to the
# partial rule set `data.agentjail.candidate`. This file is the ONLY place
# that produces `data.agentjail.decision` — a complete rule that picks the
# most restrictive candidate.
#
# Priority: deny > ask > allow. Within a priority class, the candidate with
# the lexicographically smallest rule_id wins, so the same input always
# returns the same (rule_id, reason, impact) triple. This matters for cache
# hits and audit replay.
#
# When no candidate fires, the default falls back to a single default-ask —
# fail-safe (escalate to user) rather than silent allow. The default-ask is
# owned here (not in file_policy/command_policy) so there is exactly one
# default in the package and no conflicts.
#
# User-authored rules: use `candidate[r] if { ... ; r := {...} }` partial
# rule entries. Do NOT declare `decision = ...` in your own files — only
# this file produces `decision`, so adding another complete `decision` rule
# in any file loaded into package agentjail will cause OPA to raise an
# eval_conflict_error.
#
# disabled_rules / effective_candidate (ADR 0014):
#   Users may add rule_ids (or globs) to data.agentjail.config.disabled_rules
#   to suppress non-locked rules. The resolver routes ALL decision logic
#   through effective_candidate — no reference to `candidate` appears in the
#   deny/ask/allow branches.
#
#   locked_rules is a hardcoded constant in this file (NOT in policy.yaml or
#   config). It lists rule_ids whose candidates can NEVER be suppressed.
#   Entries matching resolver/* are always locked (the fail-safe default is
#   never disableable).

package agentjail

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ---------------------------------------------------------------------------
# Self-protection: locked rule set.
#
# These rule_ids can NEVER be suppressed by disabled_rules regardless of
# what appears in policy.yaml. The constant lives here (in Rego, not in
# config or Go) so no amount of policy.yaml editing can weaken it.
#
# Any rule_id matching resolver/* is also implicitly locked (see rule_disabled).
# ---------------------------------------------------------------------------

locked_rules := {
	"file_policy/agentjail_self",
	"library/no-daemon-kill",
	"library/no-hook-self-disable",
	"command_policy/no-policy-mutation",
	"resolver/default",
}

# ---------------------------------------------------------------------------
# disabled_rules — read from data.agentjail.config; absent/empty ⇒ nothing
# suppressed (fail-safe default).
# ---------------------------------------------------------------------------

disabled := object.get(data.agentjail.config, "disabled_rules", [])

# rule_disabled(id) returns true iff:
#   1. id is NOT in locked_rules, AND
#   2. id does NOT match the resolver/* namespace (always locked), AND
#   3. some pattern in disabled matches id (glob with "/" separators, or exact).
rule_disabled(id) if {
	not id in locked_rules
	not glob.match("resolver/*", ["/"], id)
	some p in disabled
	glob.match(p, ["/"], id)
}

# effective_candidate filters out candidates whose rule_id is disabled.
# ALL decision logic in this file uses effective_candidate, never candidate
# directly, so disabled rules are truly suppressed.
effective_candidate contains c if {
	some c in candidate
	not rule_disabled(c.rule_id)
}

# ---------------------------------------------------------------------------
# default decision — fires when no candidate fires at all.
# ---------------------------------------------------------------------------
default decision = {
	"action":  "ask",
	"reason":  "no policy candidate fired — defaulting to ask",
	"rule_id": "resolver/default",
}

# ---------------------------------------------------------------------------
# deny wins: pick the deny candidate with the lowest rule_id
# ---------------------------------------------------------------------------

decision = d if {
	deny_ids := {c.rule_id | some c in effective_candidate; c.action == "deny"}
	count(deny_ids) > 0
	min_id := min(deny_ids)
	some d in effective_candidate
	d.action == "deny"
	d.rule_id == min_id
}

# ---------------------------------------------------------------------------
# ask wins (only when no deny): pick the ask candidate with the lowest rule_id
# ---------------------------------------------------------------------------

else = d if {
	deny_ids := {c.rule_id | some c in effective_candidate; c.action == "deny"}
	count(deny_ids) == 0
	ask_ids := {c.rule_id | some c in effective_candidate; c.action == "ask"}
	count(ask_ids) > 0
	min_id := min(ask_ids)
	some d in effective_candidate
	d.action == "ask"
	d.rule_id == min_id
}

# ---------------------------------------------------------------------------
# allow wins (only when no deny and no ask): pick the allow candidate with
# the lowest rule_id
# ---------------------------------------------------------------------------

else = d if {
	deny_ids := {c.rule_id | some c in effective_candidate; c.action == "deny"}
	count(deny_ids) == 0
	ask_ids := {c.rule_id | some c in effective_candidate; c.action == "ask"}
	count(ask_ids) == 0
	allow_ids := {c.rule_id | some c in effective_candidate; c.action == "allow"}
	count(allow_ids) > 0
	min_id := min(allow_ids)
	some d in effective_candidate
	d.action == "allow"
	d.rule_id == min_id
}
