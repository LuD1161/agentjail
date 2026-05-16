# Phase 1 / Stream B.1 — experimental, principal-shape rule set.
#
# This package is the side-by-side target for perm.Service when
# AGENTJAIL_SHAPE_DISAGREEMENT=log is set. The DEFAULT package
# (policies/default.rego) is the sole source of truth for verdicts;
# anything authored here is observed but never enforced until it is
# explicitly promoted (manual two-step migration per the rollout plan).
#
# Rules match on the Cerbos-shape input fields the daemon now layers
# alongside the legacy flat ones:
#
#   input.principal.id           -- "<agent_slug>:<session_id>"
#   input.principal.attr.agent   -- agent slug
#   input.principal.attr.user    -- operator unix username
#   input.principal.attr.home    -- $HOME at session start
#   input.principal.attr.cwd_repo -- git-root of cwd at session start
#   input.principal.attr.enforce -- bool
#   input.resource.kind          -- "subprocess"|"file"|"http_request"|...
#   input.resource.id            -- stable per-kind id
#   input.resource.attr.*        -- kind-specific attrs
#   input.action                 -- "exec"|"read"|"write"|"fetch"|...
#   input.context.home / cwd_repo -- snapshot

package agentjail.experimental

import future.keywords.in
import future.keywords.if

default decision := {"action": "allow"}

# Demonstration rule from the Phase 1 plan: agent "comp-intel" is
# auto-allowed to read files under its cwd_repo. We express this as an
# explicit allow whose RULE ID surfaces in audit so an operator can
# verify the new shape fires end-to-end.
rule_comp_intel_read_in_repo := r if {
	input.principal.attr.agent == "comp-intel"
	input.resource.kind == "file"
	input.action == "read"
	input.principal.attr.cwd_repo != ""
	startswith(input.resource.attr.path, sprintf("%s/", [input.principal.attr.cwd_repo]))
	r := {"action": "allow", "rule_id": "comp-intel-read-in-cwd-repo"}
}

# Counter-example: same agent attempting to write OUTSIDE its cwd_repo
# would be denied. This demonstrates the principal-shape access pattern
# without affecting prod (everything in this package is observed only).
rule_comp_intel_no_write_outside_repo := r if {
	input.principal.attr.agent == "comp-intel"
	input.resource.kind == "file"
	input.action == "write"
	input.principal.attr.cwd_repo != ""
	not startswith(input.resource.attr.path, sprintf("%s/", [input.principal.attr.cwd_repo]))
	r := {"action": "deny", "rule_id": "comp-intel-no-write-outside-cwd-repo"}
}

# Decision ordering: explicit rules first, then default allow.
decision := r if {
	r := rule_comp_intel_no_write_outside_repo
} else := r if {
	r := rule_comp_intel_read_in_repo
}
