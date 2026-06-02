# 0011 — Unify installed policy tree with source (fix library-rule fail-open)

Status: Accepted

This implements the reconciliation that [ADR 0009](0009-embedded-policy-rule-drift.md)
identified and explicitly deferred ("they must eventually be reconciled to a
single model"). ADR 0009 documented the drift as tech debt and shipped only the
low-risk credential-basename widening; this ADR removes the drift.

## Context

agentjail kept the policy logic in two places: `agentpolicy/policies/*.rego`
(the source, `opa test`-covered, using `candidate` entries aggregated by
`resolver.rego` into `data.agentjail.decision`) and an embed mirror
`cmd/agentjail/policies/*.rego` that `agentjail install` writes to
`~/.agentjail/rules/` and the daemon actually runs.

The mirror had never been migrated to the candidate+resolver pattern: it used a
self-contained `decision := … else` else-chain and `resolver.rego` was never
shipped in it. Because opt-in library rules (`no_history_read`, `no_shell_eval`,
`no_launchctl`, …) contribute only `candidate` entries — which require
`resolver.rego` to become a `decision` — **every library rule was silently
ignored in a real install**: `agentjail policy enable <x>` appeared to work but
enforced nothing. This is a fail-open security bug. Proven: `git reset --hard`
with `no_destructive_git` loaded returns `deny` against the source tree but
`allow` against the installed mirror.

The credential/publish core rules (ADR 0010) and the other core deny rules were
unaffected — they are self-contained and were duplicated into the mirror's
else-chain.

## Decision

Unify the installed tree with the source so there is one policy architecture:

1. **Mirror = source for the hook-path files.** `cmd/agentjail/policies/`
   `command_policy.rego`, `file_policy.rego`, `mcp_policy.rego` are now
   byte-identical to their `agentpolicy/policies/` counterparts, and
   `resolver.rego` is shipped in the mirror. `default.rego` (package
   `agentjail.default`, the legacy/cred/exec path on
   `data.agentjail.default.decision`) is intentionally NOT mirrored — out of
   scope and a different query path.
2. **Managed-core migration on install.** `installCoreRules` no longer skips
   files that already exist; it atomically (temp file + rename) overwrites the
   agentjail-managed core set (`coreRuleNames()`, now including `resolver`),
   replacing stale versions on upgrade, while leaving non-core files (enabled
   library rules and user-authored rules in `~/.agentjail/rules/`) untouched.
   Without this, an upgrade would leave a user's stale else-chain
   `command_policy.rego` beside the new `resolver.rego` → two `decision`
   definitions → `eval_conflict_error` → broken enforcement (worse than the
   fail-open).
3. **`no_destructive_git`** (the opt-in library rule developed alongside ADR
   0010) ships now that library rules actually enforce.
4. **Guard tests** lock the fix: a behavioral test compiling the mirror alone +
   a library rule and asserting it denies; core-equivalence cases proving no
   weakening; an upgrade-simulation test (seed stale core → install → assert a
   library rule denies); and a byte-parity test for the 4 hook-path files +
   library rules so the trees can never drift apart again.

## Consequences

- **Library rules enforce in real installs.** All 7 pre-existing opt-in rules
  and `no_destructive_git` now take effect when enabled.
- **Single source of truth.** The mirror is a verified copy of the source; the
  parity test fails CI on drift. The previous "manual mirror, keep in sync by
  hand" comments are removed.
- **Core rules are agentjail-managed.** Editing a core file in
  `~/.agentjail/rules/` is no longer a supported customization point — installs
  refresh them. Custom rules belong in their own files, which are preserved.
- **Tie-breaking semantics.** The resolver picks the most restrictive candidate
  (deny > ask > allow), tie-breaking by lexicographic `rule_id` rather than the
  old else-chain order. Verified that representative core cases keep the same
  action (`sudo`/`rm -rf`/sensitive-read → deny, publish → ask, project → allow);
  only `reason`/`rule_id` may differ when multiple denies match.
- **`agentjail policy list`** now shows `resolver` as a core rule (honest; it is
  always installed and cannot be disabled).
