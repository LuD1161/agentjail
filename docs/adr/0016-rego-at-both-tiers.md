# 0016 — Rego at both tiers: one DSL, one engine

Status: Accepted

## Context

agentjail runs OPA/Rego at Tier 1 (the hook layer) today. As Tier 2 (the
microVM wire gateway, ADR 0016-pending in the research notes) becomes real, a
question arises: which policy DSL does the wire gateway use?

The design exploration (`research-notes/2026-06-19-aws-pack-secret-server-wire-inspection.md`
§6) went through four rounds:

1. "Keep both — Rego Tier 1, CEL Tier 2."
2. "Unify on CEL."
3. "Keep both — Rego is more powerful."
4. **"Rego at both tiers."**

The driver for round 4: the CEL-specific concerns that motivated a second DSL
are solvable with Rego, and the perpetual cost of maintaining two
engines/DSLs/docs-paths has no capability benefit.

The two CEL-specific concerns and their Rego resolutions:

- **Compile-time type checking** ("`k8s.veerb` is a silent miss in Rego"):
  the wire gateway's protocol parser is our Go code. We validate the fact
  schema before injecting it into OPA, and `opa compile` (already run by
  `agentjail policy add`) catches undefined variables and builtin type
  mismatches. The fact schema is controlled at the Go boundary.
- **Body-buffering gating** ("only buffer the HTTP body if a rule reads it"):
  solvable in Go with a one-time load-time check — walk the loaded Rego
  module AST (or string-check the source) for references to
  `input.http.body`. If present, buffer; otherwise don't. Less elegant than
  CEL's `AST.References()` but functionally equivalent. For the initial CUD
  pack the destructive verb is in the `X-Amz-Target` header / method+path,
  so body buffering is not even needed.

## Decision

**One DSL (Rego), one engine (OPA), both tiers.** cel-go is not added as a
dependency.

- Tier 1 rules inject tool-call JSON as OPA input
  (`input.tool_input.command`, `input.tool_input.path`, `input.tool_name`).
- Tier 2 rules inject protocol facts as OPA input
  (`input.aws.action`, `input.sql.verb`, `input.redis.command`).
- Both use the existing `candidate`/`resolver` pattern, the locked
  self-protection set, custom-rule quarantine, SIGHUP reload, and
  `with`-based testing — unchanged.
- One custom-rule path: `agentjail policy add ~/my_rule.rego` works for both
  tiers. The rule's target layer is inferred from which input variables it
  references, not declared.
- One config surface: `policy.yaml` drives both tiers through
  `data.agentjail.config.*`.
- One docs path; one authoring UI (when it ships).

## Consequences

+ No second engine to build, ship, document, or keep in sync with OPA
  releases.
+ Rego's power (rule composition, `with`-based testing, rich builtins —
  regex, glob, JSON, crypto — partial sets, fixpoint semantics) is available
  at both tiers.
+ OPA's primary production use case is API authorization (Envoy ext-authz,
  Kubernetes admission control) — Rego over HTTP request properties is not
  novel; it is OPA's bread and butter. Tier 2 uses protocol-specific facts
  instead of generic HTTP facts.
+ The `THIRD_PARTY_LICENSES` set does not grow (OPA already a dependency).
- Body-buffering gating is a Go-side AST walk, not a CEL built-in — slightly
  less elegant, same effect.
- A typo in a fact field (`aws.acount` vs `aws.account`) is not a compile
  error in Rego the way it would be in a typed CEL environment. Mitigated by
  parser-side schema validation and `opa compile` at rule-install time.
- Tier 2 wire rules are not shippable until the microVM gateway (ADR 0016 in
  the research notes) is Accepted and built. This ADR settles the DSL
  question so that when the gateway ships, it uses Rego — no migration.

This decision supersedes any earlier implicit "CEL for Tier 2" assumption.
