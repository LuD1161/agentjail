# 0116 — Custom rule surface

Status: Accepted

## Context

Custom Rego is intentionally allowed to contribute policy candidates. The
previous validation rejected direct `decision` declarations but used text
matching. Rego permits multiple bodies for a predicate, so a custom
`rule_disabled` body could extend the resolver and remove a locked candidate
before deny/ask/allow priority ran.

## Decision

Parse every custom module with OPA's AST. Only `package agentjail` modules
whose rules are partial `candidate` set or object entries are accepted. Default,
else, resolver, and helper rules are rejected. Apply this validation both at
`policy add` and when the daemon loads custom files, where violations are
quarantined without affecting the core and library baseline.

## Consequences

Custom rules can add scoped allow, ask, or deny candidates, but cannot alter
resolution or suppression. A custom allow cannot outrank a core ask or deny;
locked candidates remain present. Same-user users retain authority to modify
their own installation outside a shielded agent session; Tier 1 is not a
privilege boundary against that local administrator.
