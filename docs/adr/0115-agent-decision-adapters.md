# ADR 0115 — Agent decision adapters

## Status

Accepted

## Context

Policy has one canonical vocabulary: `allow`, `ask`, and `deny`. Hook protocols
do not share that vocabulary. Some can display a native ask, while a particular
event may require a binary response. Recording only the rendered response made
the policy decision ambiguous; recording only the policy decision hid what the
agent actually received.

The prior Codex PreToolUse integration illustrates the risk: a canonical `ask`
was rendered as a fail-closed deny, but audit history could be read as if policy
had denied the action. This decision does not select a future Codex approval
mechanism; that requires a separately verified integration contract.

## Decision

`internal/agentpolicy` owns a small adapter seam. The daemon evaluates policy,
then asks the adapter for the agent/event-specific effective response. The
adapter cannot change `PolicyAction`; it can only report an `EffectiveAction`
and a reason for a difference.

Every decision row persists:

- `policy_action`: immutable canonical policy verdict;
- `effective_action`: response rendered for the agent protocol;
- `adapter` and `translation_reason`: the translation provenance;
- existing `final_action` and `enforcer`: the observed outcome and responsible
  enforcement layer from ADR 0112-final-action-outcome.

The daemon is the sole writer. Its socket response, structured log, SQLite
read path, CLI raw log output, and UI state all expose the same fields.

## Consequences

- A Codex PreToolUse `ask` is queryable as `policy_action=ask` and
  `effective_action=deny`, with a fail-closed explanation; it is never
  misreported as a policy deny.
- Cursor's binary `beforeReadFile` response is represented the same way.
- Final sandbox attribution remains independent: a policy/adapter allow that
  later receives a Seatbelt or Landlock EPERM becomes `final_action=blocked`,
  `enforcer=sandbox`.
- New agent integrations add an adapter and conformance fixtures rather than
  branching policy or storage code.
