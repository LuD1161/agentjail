# 0009 — Embedded policy rules drifted from agentpolicy source; widen credential matching, defer install-time policy picker

Status: Accepted

## Context

While building an install-time policy-selection TUI (let users choose which optional
"library" hardening rules to enable during `agentjail install`) and promoting
`no_daemon_kill` to an always-on rule, a Codex plan review plus direct inspection
uncovered a pre-existing architectural split in the policy engine:

There are **two parallel, divergent Rego implementations**:

1. **`agentpolicy/policies/*.rego`** (source, exercised by `opa test`): uses the
   `candidate contains r if {…}` partial-set model, with `resolver.rego` selecting the
   most-restrictive candidate (deny > ask > allow) into `data.agentjail.decision`.

2. **`cmd/agentjail/policies/*.rego`** (embedded via `go:embed`, copied to
   `~/.agentjail/rules/` by `installCoreRules`, and **what the running daemon actually
   evaluates**): uses a self-contained `decision := r if {…} else := …` else-chain.
   `resolver.rego` is **not** embedded and **not** installed.

`diff` confirms all three core files (`command_policy`, `file_policy`, `mcp_policy`)
differ between the two trees, despite header comments asserting they are kept
byte-identical. The library rules (`cmd/agentjail/library/*.rego`) are likewise
complete-`decision` rules (1–8 `decision` definitions each).

Consequences of the split that block the original feature as specced:

- **Wrong promotion path.** Converting `no_daemon_kill` to a `candidate` (the source
  model) would yield *no decision* in the installed else-chain model, which has no
  resolver — it would silently stop enforcing.
- **Conflict risk on batch-enable.** Two complete `decision` rules that both produce a
  value for one input cause OPA `eval_conflict_error`. The proposed install picker
  default ("all optional rules pre-checked → batch-enable") is exactly the scenario that
  can trip this. A conflict crashes policy eval → the hook **fails open** (allows) → a
  hardening step would become a *de facto* enforcement regression.
- **Migration hazard.** `installCoreRules` never overwrites an existing rule file, and a
  promoted-to-core rule would make `policy disable` refuse removal — stranding any
  previously-enabled library copy in `~/.agentjail/rules/`.

## Decision

1. **Document the drift** (this ADR) as tracked tech debt. The embedded
   `cmd/agentjail/policies/*.rego` is the source of truth for *runtime* behavior; the
   `agentpolicy/policies/*.rego` candidate/resolver tree is the source of truth for
   `opa test`. They must eventually be reconciled to a single model.

2. **Ship the low-risk, model-agnostic improvement now:** widen the `file_policy`
   sensitive-path match for credential/secret basenames. Previously only an exact
   basename `credentials`/`secrets` was denied (`(^|/)credentials$`); a file named
   `credentials.json`, `secrets.yaml`, `.secrets`, `credentials_old`, etc. slipped
   through, even though `policy.yaml` advertised `**/credentials*`. Changed to
   `(^|/)\.?credentials($|[._-])` (and the `secrets` equivalent), which catches the
   common extension/separator/dotfile forms while still NOT matching unrelated words
   like `credentialsmith`. Applied to BOTH `agentpolicy/policies/file_policy.rego` and
   the embed copy `cmd/agentjail/policies/file_policy.rego`; new `opa test` cases cover
   the widened forms and the negative case.

   Scope note: the widening is intentionally limited to the file tools (Read/Write/Edit).
   `command_policy`'s Bash sensitive-path matching is NOT widened to credential/secret
   basenames, because matching the bare words "credentials"/"secrets" in arbitrary shell
   commands (commit messages, `echo` strings) would cause frequent false positives.

3. **Surface policy management in help.** `agentjail help` already lists `policy`; added
   a dedicated footer hint (`agentjail policy list · enable|disable <rule>`) and an
   install-summary pointer ("harden further: 'agentjail policy list'") so the
   list/enable/disable workflow is discoverable.

4. **Defer the install-time policy picker and the always-on promotion of
   `no_daemon_kill`** until the embedded Rego model is reconciled into a single,
   conflict-free representation (decision to be captured in a follow-up ADR). The
   prerequisite reconciliation must choose one of:
   - keep the else-chain `decision` model and fold each library rule's deny into the
     core chain (guaranteeing no two complete `decision` rules overlap), or
   - embed `resolver.rego` and convert all installed rules (core + library) to the
     `candidate` contract, ensuring `coreRuleNames()` does not surface `resolver` as a
     user-facing rule.

## Consequences

- Credential/secret files with extensions are now blocked for file tools; closes the
  reported gap. Existing installs need a clean reinstall (or a manual copy of the updated
  `file_policy.rego` into `~/.agentjail/rules/` + `kill -HUP`) because `installCoreRules`
  skips existing files — the same migration limitation noted above.
- The install-time policy TUI is postponed, not cancelled; the user-facing
  `agentjail policy {list,enable,disable}` commands already provide the capability in the
  meantime.
- The drift and the `installCoreRules` no-overwrite behavior are now on record as the two
  things to fix before any feature batch-modifies the installed rule set.
