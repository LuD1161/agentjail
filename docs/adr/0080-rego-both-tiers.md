# ADR 0080-rego-both-tiers: Rego at both tiers

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
  → **Implemented 2026-07-15; see the addendum below.**
- Tier 2 wire rules are not shippable until the microVM gateway (ADR 0016 in
  the research notes) is Accepted and built. This ADR settles the DSL
  question so that when the gateway ships, it uses Rego — no migration.

This decision supersedes any earlier implicit "CEL for Tier 2" assumption.

## Addendum — 2026-07-15 (AGE-218)

Two updates: the type-checking mitigation above is now built, and the DSL
question was re-litigated against primary sources and re-affirmed.

### The mitigation is implemented

It had not been. Between this ADR being accepted and 2026-07-15,
`NewHookOPAEngineWithData` called `PrepareForEval` with modules + query +
store and nothing else — no schema, no strict mode. OPA does not type-check
`input` references unless given a schema, so the mitigation this ADR banked on
existed only in the prose. `input.aws_accont` compiled clean and the rule
silently never fired.

Now: a JSON schema derived from `HookInput` is wired via `rego.Schemas()`
alongside `rego.Strict(true)` on the single compile path shared by the daemon
and `agentjail policy add`. An unknown `input.*` reference is a compile error
naming the reference, the line, and the valid field set; `policy add` fails
closed on it.

Two constraints kept the schema honest:

- **Optional fields stay legal.** `repo_root` / `aws_account` /
  `command_binaries` are `omitempty` and legitimately undefined for non-git /
  non-AWS / non-Bash calls. Referencing an absent field so the rule simply
  does not match is an intentional Rego pattern. OPA builds its object type
  from `properties` and ignores `required`, which gives exactly this: declared
  fields are referenceable, absent ones are undefined at eval. A schema that
  rejected them would be worse than no schema.
- **`tool_input` stays free-form.** Its key set belongs to the tool, so it is
  declared as an untyped object.

### The schema binds at `SchemaRootRef`, not `InputRootRef`

The first implementation filed the schema under `ast.InputRootRef` — the
obvious reading of the API. It compiled, passed every existing test, and
type-checked nothing; the first all-clear sweep of the rule tree was
meaningless. Only a deliberate typo probe caught it.

A schema at `ast.SchemaRootRef` (the bare `schema` root) is the compiler's
*global* input type — what `opa check --schema` installs, and what types every
module carrying no `# METADATA` annotation. A schema filed under `input` is
only addressable by name from a `# METADATA / schemas:` block, so it applies
to nothing by default.

Recorded because the failure mode is invisible by construction: both spellings
compile, and only one enforces. It is the same silent no-op this addendum
exists to remove, reproduced inside the fix for it. Any future change here must
be proved by a mutation probe (break a ref on purpose, watch the compile fail),
never by a green suite.

**All shipped rules passed on the first run** — the embedded core + library
trees the daemon evaluates had no dead references. Asserted going forward by
`cmd/agentjail/shipped_rules_schema_test.go`. The legacy `agentjail.default`
package (and `lib/exec`, `experimental`) do not share `HookInput`'s shape and
are evaluated by a different engine and query; they are out of scope, not
exceptions.

Consequence #4 above (Tier 2 fact schema) is unchanged and still owed: when
the wire gateway lands, `input.aws.*` / `input.sql.*` get the same treatment.
That is the exact case this ADR's typo example was drawn from.

### The CEL question, re-litigated

Prompted by a public argument for a Turing-incomplete DSL ("Don't mess it up
like Rego/OPA") citing Kubernetes' choice of CEL as precedent. Checked against
the primary sources rather than recollection. **Decision unchanged: do not
migrate.**

The CEL-vs-Rego decision lives in **KEP-2876** (CRD Validation Expression
Language). KEP-3488 (CEL for Admission Control) inherits CEL and contains no
language comparison. KEP-2876's *entire* Rego section, verbatim:

> ### Rego
>
> See Open Policy Agent (https://github.com/open-policy-agent/opa/tree/main/rego).
> The syntax is more extensive than CEL and is designed specifically to work well
> with kubernetes objects. It allows larger, multi-line programs and
> includes a package and module system. It does not offer the same sandbox constraints
> as CEL, nor does it type check code.

Three findings:

1. **Turing-completeness is never raised** — not in the Rego section, not as a
   selection criterion anywhere in the KEP. Rego is in fact already
   Turing-incomplete (recursion is a compile error). The premise of the
   argument is not supported by the source it cites.
2. **The KEP concedes Rego is the more capable and more domain-fit language**
   — "more extensive", "designed specifically to work well with kubernetes
   objects", "package and module system", all stated neutrally. K8s passed on
   Rego *despite* better domain fit.
3. The KEP raises exactly **two** objections to Rego: sandbox constraints and
   type checking.

Of those two, only one transfers:

- **Type checking** — applied to us. This addendum closes it.
- **Sandbox constraints** — does not transfer. K8s runs expressions authored
  by untrusted tenants against shared infrastructure, where an expensive
  expression is a DoS on everyone. Whoever runs `agentjail policy add` already
  owns the machine. Different threat model. (Latency is still governed by
  ADR 0002, but a per-tool-call hook's budget is orders of magnitude looser
  than a per-API-request apiserver path.)

Also note our user-facing DSL is `policy.yaml`, not Rego — the `.rego` tree is
the maintainer-authored pack. The "let users declare intent, the framework
does the heavy lifting" argument already lands on YAML; Rego is the engine
underneath it.

**Net: the one half of the Kubernetes case against Rego that applies to us is
now closed. The other half is inapplicable by threat model.** A greenfield
tool shipping type-checked CEL is not evidence either way — migration cost is
zero before you have rules.
