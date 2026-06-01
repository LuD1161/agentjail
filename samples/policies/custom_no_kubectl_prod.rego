# custom_no_kubectl_prod.rego
#
# Block any `kubectl` command when the current context contains "prod" or "production".
# Read by parsing the command for `--context=prod*` or warning about ambient
# context (the agent might invoke kubectl without explicit context, which means
# it inherits whatever kubeconfig is current — possibly prod).
#
# Why opt in: lots of teams keep prod and staging kubeconfigs side-by-side.
# An agent told "check the deployment" can accidentally hit prod if the
# current context is prod. This rule forces the agent to use a non-prod
# context explicitly OR escalates to ask.
#
# Pattern: uses `candidate contains r if { ... }` (partial rule set entry) so this
# rule coexists cleanly with the core policies via resolver.rego. Do NOT use
# `decision = ...` (complete rule) — that would conflict with resolver.rego's
# single complete `decision` rule.

package agentjail

import future.keywords.if
import future.keywords.contains

# Deny any kubectl call that explicitly targets a prod-named context.
candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "Bash"
    cmd := input.tool_input.command
    regex.match(`\bkubectl\b.*--context[=\s]+\S*(prod|production)`, cmd)
    r := {
        "action":  "deny",
        "rule_id": "samples/no-kubectl-prod-explicit",
        "reason":  "kubectl explicitly targeting a prod context is blocked — confirm via a non-agent path",
        "impact":  "would run kubectl against a production cluster",
    }
}

# Escalate when kubectl is invoked without an explicit context — the ambient
# context might be prod. Forces the agent to be explicit.
candidate contains r if {
    input.hook_event == "PreToolUse"
    input.tool_name == "Bash"
    cmd := input.tool_input.command
    regex.match(`\bkubectl\b`, cmd)
    not regex.match(`\bkubectl\b.*--context[=\s]`, cmd)
    # Only ask for state-changing commands; read-only kubectl is fine
    regex.match(`\bkubectl\s+(apply|delete|patch|edit|scale|rollout|exec|cp|drain|cordon)\b`, cmd)
    r := {
        "action":  "ask",
        "rule_id": "samples/no-kubectl-ambient-context",
        "reason":  "kubectl invoked without --context — current kubeconfig may be prod",
        "impact":  "may run kubectl against the current (possibly production) cluster",
    }
}
