# ADR 0057: env write-deny: secret-form deny-list (invert the over-broad .env* catch-all)

**Status:** Accepted

## Context

The shield write-denied EVERY `.env` variant via a single catch-all regex
(`\.env(\.[a-zA-Z0-9_]+)?$`, `cmd/agentjail-shield/shield_contract.go`,
`Write:true`). This blocks the OS-level file writes `git` performs during
working-tree checkout for any repo that commits non-secret env templates.
Confirmed live:

```
error: unable to create file frontend/.env.example: Operation not permitted
```

The same repo also hit `worker/.env.docker`. The deny is write-only, so
reads were not the problem - the checkout itself failed. Template files
like `.env.example`, `.env.sample`, `.env.docker`, `.env.dist` are
non-secret by convention (that is the entire point of a template): they
exist so a repo can document required variables without committing real
values. Blocking their write protects nothing while breaking routine
clones.

The `.env` sensitivity classification is duplicated across four places
that must stay in sync by convention (AGENTS.md: "drift is a bug"):
`cmd/agentjail-shield/shield_contract.go`,
`agentpolicy/policies/file_policy.rego`,
`agentpolicy/policies/command_policy.rego`, and
`agentpolicy/policies/default.rego` - plus a byte-identical embedded
mirror of the three rego files at `cmd/agentjail/policies/`, guarded by
`cmd/agentjail/embed_parity_test.go`.

## Decision

Invert the over-broad catch-all to a deny-LIST of secret-bearing `.env`
forms, and allow every other `.env.*` write. The deny set is basename-
anchored (`(^|/)`), case-sensitive, and applies to WRITE/EDIT operations
only:

1. `(^|/)\.env$` - bare `.env` (canonical local secrets)
2. `(^|/)\.env\.local$` - local override
3. `(^|/)\.env\..+\.local$` - nested local override (`.env.production.local`,
   `.env.feature-x.local`, ...)
4. `(^|/)\.env\.(production|prod|development|dev|staging|test|qa|uat|secret|secrets|vault|override)$`
   - known environment/secret names

Everything else `.env.*` (`example`, `sample`, `template`, `dist`,
`defaults`, `docker`, `schema`, `ci`, ...) is allowed for write. `.envrc`
(direnv) is a separate, unchanged deny rule.

`.env.override`, `.env.*.local`, `.env.secret(s)`, and `.env.vault` are
additions beyond the user's original base list (production/development/
staging/test/prod/dev/local + bare); they are unambiguously secret names
and shrink the residual "novel name slips through" gap at zero cost to
template clones.

This is WRITE/EDIT-scoped. READ posture is unchanged: `file_policy.rego`
is now op-aware for the env predicate specifically - it uses the new
secret-form list on Write/Edit, and keeps the existing broad
`(^|/)\.env($|\.)` match on Read. So `Read(".env.example")` still asks,
exactly as before; only `Write(".env.example")` moves from ask to allow.

The four layers are kept in sync by hand, not by a shared source of
truth, and are test-guarded: `opa test` (rego), the embed parity test
(`cmd/agentjail/embed_parity_test.go`, requiring the rego mirror to be
copied byte-for-byte into `cmd/agentjail/policies/`), and a shield unit
test asserting the match table (secret forms match, template forms do
not).

## Consequences

- **WRITE/EDIT relaxation only.** `file_policy` READ posture is
  unchanged and stays broad. There is no new read exposure via the
  Read/Edit/Write tools: an agent asking to read `.env.example` still
  hits the same "ask" gate it hit before this change.
- **One bounded, documented exception: `command_policy.rego`.** This
  rule matches raw shell text and cannot split read vs. write the way
  `file_policy` can - a shell command that merely references a file
  cannot be classified as "reading" vs. "writing" it without executing
  it. Narrowing its `.env` match to the same secret-form list means a
  bash command that only references a template-named env file is no
  longer auto-blocked, including a plain read of one (`cat .env.example`,
  `cat .env.docker`). Real secret forms stay blocked in bash
  (`cat .env`, `cat .env.production`, `printf x > .env.local`). This is
  accepted as a small, bounded read-via-bash relaxation for names that
  are non-secret by convention, not a general env-read relaxation.
- **Accepted naming residuals**, enumerated rather than left implicit:
  - Unknown suffixes not on the list (e.g. `.env.foobar`) are writable.
    This is the accepted residual risk of a deny-list inversion; the
    obvious secret-signaling names are covered, novel ones are not.
  - Matching is case-sensitive by design, so `.ENV` or `.env.FEATURE`
    are not covered by the deny list.
  - Non-dotfile `*.env` files (e.g. `config.env`, `secrets.env`) are no
    longer matched, because the new patterns are dotfile-anchored
    `(^|/)\.env...` rather than the old catch-all's bare `\.env` suffix
    match. This is a narrowing versus the prior behavior, tracked here
    rather than silently dropped.
  - Broad branch or mode names beyond the enumerated list are
    deliberately NOT covered. Adding them would recreate the original
    over-broad problem this ADR fixes.
- This is a deliberate, user-approved relaxation of a credential WRITE
  deny (a deny-list inversion), not an oversight. The accepted residual
  risk is stated above.
- **Follow-up (future work, not scoped here):** the secret-env-form list
  is duplicated across four layers (Go shield contract + three rego
  files, plus the embedded rego mirror) and kept in sync by hand,
  test-guarded but not structurally shared. Centralizing it into a
  single cross-tier source of truth, per the shared-contract principle
  in [ADR 0034](./0034-platform-backend-shared-contract.md), is left as
  future work so this security fix stays scoped to the checkout-breaking
  bug it addresses.
