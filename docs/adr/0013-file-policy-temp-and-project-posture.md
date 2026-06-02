# 0013 — File-policy posture: temp allow, in-project sensitive downgrade, boundary-safe membership

Status: Accepted

## Context

`file_policy.rego` produced three classes of false positive that drove users to
disable core protections wholesale — a far worse security outcome than the noise
it was avoiding:

1. **Temp hard-denied.** macOS `$TMPDIR` resolves under `/private/var/folders/…`,
   and the policy marked all of `/var` and `/private/var` sensitive ⇒ writes to
   the system temp directory returned `deny`, not even `ask`. `/tmp` fell through
   to the `ask` default. Agents legitimately need scratch space.
2. **Project folder asked on relative paths.** `project_allow` fired only when
   `startswith(file_path, input.cwd)`. Agents routinely pass *relative* paths
   (`src/foo.go`), which never matched ⇒ constant `ask` on the very directory the
   agent was granted.
3. **Sensitive-basename files inside the granted project denied.** "Sensitive
   beats project," so `.env.example`, `secrets.yaml` (k8s/Helm), `server.key`
   (local TLS) *inside* `cwd` were hard-denied even though the agent was
   explicitly given that directory.

A naive `startswith(p, cwd)` membership test is also unsafe: with
`cwd=/Users/u/proj` it matches the sibling `/Users/u/proj2/…`.

## Decision

Split the single `is_sensitive_path` predicate into two tiers and add a
boundary-safe project-membership check. Path canonicalization and temp-root
injection are provided by the daemon (ADR 0012); this policy assumes inputs are
already canonical absolute paths.

- **Temp ⇒ allow (`file_policy/temp_allow`).** `is_temp_path` covers
  `data.agentjail.config.file.temp_roots` (injected) plus structural fallbacks
  (`/tmp`, `/private/tmp`, `/var/folders/…/T/`, `/private/var/folders/…/T/`).
  Critically, the temp subtree is *excluded* from the `/var` and `/private/var`
  deny predicates, so **no deny candidate is emitted** for a temp path — the
  resolver is order-independent and picks any deny over any allow, so suppression
  (not out-voting) is required.
- **`is_protected_credential` ⇒ always deny.** Home-anchored credential stores
  and system dirs (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, `~/Downloads`,
  `~/Desktop`, `~/.agentjail`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`,
  `~/.docker/config.json`, `~/.kube/config`, `~/.cargo/credentials`,
  `~/Library/Keychains`, `/etc`, non-temp `/var`). Hard-deny regardless of `cwd`
  — these are the protections that justify running the tool, and are never
  downgraded.
- **`is_sensitive_basename` ⇒ deny outside project, ask inside.** Basename /
  extension patterns (`.env*`, `.envrc`, `credentials*`, `secrets*`,
  `*.pem|key|p12|pfx|jks|keystore`, `.netrc`, `id_rsa|id_ed25519|id_ecdsa|id_dsa`)
  downgrade to **`ask`** (`file_policy/sensitive_in_project`) when in-project, and
  stay `deny` (`file_policy/sensitive_credential`) when outside. `ask`, not
  `allow`: a `secrets.yaml` with real secrets still warrants a human beat.
- **Boundary-safe membership.** `in_project(p) := p == cwd OR startswith(p, cwd +
  "/")` replaces raw `startswith` everywhere (`project_allow`,
  `sensitive_in_project`, `file_specific_matched`), closing the sibling-prefix
  escape.

The embedded mirror (`cmd/agentjail/policies/file_policy.rego`, ADR 0011) is
updated in lockstep; the embed-parity test enforces this.

## Consequences

- Day-one friction drops sharply (temp + project just work), removing the main
  reason users reached for disabling core. The hard-deny credential tier is
  unchanged, so the guardrail still means something.
- In-project sensitive files are `ask`, not silent allow — a deliberate
  speed-bump, not a hole.
- Correctness now depends on the daemon delivering canonical absolute paths and
  injected temp roots (ADR 0012). Tests assert candidate-set *absence* of a deny
  for temp (not just the final action), since resolver precedence would otherwise
  hide a stray deny.
- A future broader user-tunable policy surface (per-rule enable/disable, custom
  rules) is tracked separately; this ADR only fixes the shipped defaults.
