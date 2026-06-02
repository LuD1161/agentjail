# 0010 — Core policy pack: credential-read denies + broadened publish

Status: Accepted

## Context

The shipped default rules (`file_policy`, `command_policy`, `mcp_policy` plus
opt-in `library/` rules) cover the most common dangerous tool calls, but two
gaps affected essentially every developer:

1. **Credential-file reads.** `file_policy` denied `~/.ssh`, `~/.aws`,
   `~/.gnupg`, `.env`, `*.pem/.key`, and `.netrc`, but left a set of pure-token
   stores open: `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`,
   `~/.docker/config.json`, `~/.kube/config`, `~/.cargo/credentials`, and
   `~/Library/Keychains/`. Reading any of these has no legitimate agent use and
   is a one-step exfiltration path.
2. **Accidental publish.** `confirm-publish` (an *ask* rule) only covered
   `npm/cargo publish` and `pip/twine upload`, missing `yarn/pnpm publish`,
   `gem push`, `poetry publish`, `docker push`, and `gh release create`.

This is the in-tree **CORE policy pack** — generic protections every developer
benefits from. Domain-specific bundles (aws, gcp, k8s, terraform, docker,
prod-database) are deliberately out of scope: they will ship later from a
separate, signed, versioned, community-contributable marketplace repo
(`policy-packs`). Core = broadly-useful and in-tree; domain packs = community
and out-of-tree.

## Decision

- **Credential reads → built-in DENY.** New HOME-ANCHORED `is_sensitive_path`
  clauses (`^/Users/[^/]+/\.npmrc$`, …) added to `file_policy.rego`, mirrored in
  `command_policy.rego`'s `contains_sensitive_path` (with `~`, `$HOME`, and
  absolute forms), and to `agentjail-shield`'s sensitive-path lists. Anchoring
  is intentional: project-local `./.npmrc` stays allowed (legitimate per-project
  config); only the home copy is denied. Exact-file regexes are `$`-anchored so
  `.npmrc.bak` is not swept up.
- **Publish → keep ASK, broaden coverage.** `confirm-publish` refactored to a
  single shared `is_publish_cmd(cmd)` predicate (used by both the candidate and
  the `any_dangerous_pattern` twin, eliminating drift) and extended to the verbs
  above. `ask`, not `deny`, because publishing is sometimes the intended action.
  `docker buildx build --push` is a known, accepted gap.

## Consequences

- **Two enforcement surfaces, one policy.** Every credential path now appears in
  the OPA `file_policy`/`command_policy` AND the OS sandbox `agentjail-shield`.
  The shield is the actual filesystem safety net; the Rego command rules are
  UX/intent checks.
- **Regex-over-shell-text is bypassable** (variables, shell expansion,
  base64/eval, sub-scripts, symlinks). The new Bash deny clauses do not — and
  cannot — catch variable indirection like `p=~/.npmrc; cat "$p"`. This is an
  accepted hook-layer limitation; the shield enforces at the syscall boundary
  regardless of how the path is spelled.
- These two changes are **core** rules and enforce correctly in the installed
  (mirror) policy tree — verified by behavioral test
  (`cmd/agentjail/policies_behavior_test.go`): `~/.npmrc` read → deny,
  `docker push` → ask, project-local `.npmrc` → allow.
- The published default-policies reference on the website is updated in lockstep
  so the advertised list matches what ships.

## Discovered but NOT fixed here (follow-up)

While verifying this batch we found a pre-existing **fail-open bug** affecting
all opt-in library rules. The policy tree is implemented twice:
`agentpolicy/policies/*.rego` uses `candidate` + `resolver.rego` (unit-tested),
while the embed `cmd/agentjail/policies/*.rego` — which `agentjail install`
writes to `~/.agentjail/rules/` and the daemon actually runs — is a separate
self-contained `decision := … else` else-chain that never reads
`data.agentjail.candidate`, and `resolver.rego` is never installed. Because of
this, enabling any `candidate`-based library rule (`no_history_read`, …) has no
effect in a real install: the deny is silently dropped (proven — `git reset
--hard` with `no_destructive_git` loaded returns `deny` against the source tree
but `allow` against the installed mirror).

The credential/publish rules in THIS ADR are unaffected (they are core
else-chain rules). The fix — regenerating the mirror from the candidate+resolver
source and installing `resolver.rego`, plus an enforcement test for the
installed tree — is deferred to its own ADR/change because it touches the
enforcement engine for every rule and warrants separate review. The
`no_destructive_git` library rule was implemented during this work and is held
to ship with that fix so it lands actually-enforcing.
