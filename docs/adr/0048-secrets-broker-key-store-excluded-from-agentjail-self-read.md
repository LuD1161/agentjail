# 0048 - secrets-broker master key and store are excluded from the ~/.agentjail self-read allow

Status: Accepted

## Context

ADR 0045 allowed the sandboxed agent to Read anywhere under `~/.agentjail/`
for observability, on the premise that "reads leak no secret" because the
session bearer token lives only in netproxy memory, never on disk.

That premise stopped being true once the secrets broker (ADR 0023,
`cmd/agentjail-secrets/`) landed: it persists an AES-256 master key at
`~/.agentjail/secrets.key` and ciphertext for every stored secret under
`~/.agentjail/secrets/`. Both are on disk, both are inside the blanket
`file_policy/agentjail_self_read` allow, and neither the Rego hook layer nor
the Landlock shield carved them out. A prompt-injected agent could simply
`Read ~/.agentjail/secrets.key` followed by `Read ~/.agentjail/secrets/<name>`
and decrypt every secret the broker ever stored, entirely offline, with no
further access needed. This is tracked as issue C2.

Two independent layers needed the same fix, because they enforce
independently and either one alone would have leaked the key:

1. **Hook layer** (`agentpolicy/policies/file_policy.rego`): Rule 0b
   (`file_policy/agentjail_self_read`) resolved a Read of `secrets.key` /
   `secrets/*` to `allow`.
2. **OS sandbox** (`cmd/agentjail-shield`): on Linux, `agentPaths().HomeRO`
   granted `~/.agentjail` as one recursive Landlock `path-beneath` rule,
   which — because Landlock is allow-list only with no punch-through deny —
   necessarily covered `secrets.key` and `secrets/` too. (macOS was already
   safe: `sensitiveReadPaths` in `shield_darwin.go` denies read on the whole
   `~/.agentjail` subtree.)

## Decision

**Hook layer.** Add a dedicated predicate `is_agentjail_secrets(p)` matching
`~/.agentjail/secrets.key` and the `~/.agentjail/secrets/` subtree, and a new
locked candidate `file_policy/agentjail_secrets` that fires `deny` for
Read/Write/Edit. It is added to `resolver.rego`'s `locked_rules` so it can
never be suppressed via `disabled_rules`. Because the resolver picks
`deny > ask > allow` unconditionally (rule_id ordering only breaks ties
within the same action), this deny wins over Rule 0b's blanket read-allow
regardless of declaration order. Rule 0b's allow and its comment are updated
to state the exception explicitly rather than claim "no secret" leaks.

**Shield layer (Linux).** Landlock cannot express "allow this directory
except these two children" as a single rule — an allow rule on a directory
grants access to its entire subtree. So `applyLandlock` no longer grants one
recursive rule on `~/.agentjail`; instead it grants `LANDLOCK_ACCESS_FS_READ_DIR`
on the directory itself (so listing still works) and then enumerates its
current children at launch time, granting each one read-only individually
*except* the names returned by the new shared-contract function
`AgentjailSecretsProtectedNames()` (`"secrets.key"`, `"secrets"`). This keeps
`policy.yaml`, the audit DB, `trusted.yaml`, `bin/`, etc. readable exactly as
before, while structurally excluding the two secrets paths — including any
future files added to the store, since the exclusion is name-based rather
than needing a static allowlist of everything else in the directory.

**Shield layer (macOS).** No code change: `sensitiveReadPaths` in
`shield_darwin.go` already denies read on the entire `~/.agentjail` subtree,
so `secrets.key`/`secrets/` were never reachable there. This ADR documents
that invariant via `AgentjailSecretsProtectedNames()`'s doc comment rather
than adding a redundant carve-out, per ADR 0034's "name your exceptions"
guidance.

## Consequences

- Reads of `~/.agentjail/secrets.key` and `~/.agentjail/secrets/**` resolve to
  `deny` at both the hook layer and (on Linux) the OS sandbox layer —
  defense in depth, matching the two-layer bug this ADR closes.
- Reads of other `~/.agentjail` files (`policy.yaml`, `agentjail.db`,
  `trusted.yaml`) remain `allow`/readable, unchanged from ADR 0045.
- The Linux Landlock grant for `~/.agentjail` changed from one static
  directory-level rule to a launch-time enumeration. This is a small,
  bounded extra `os.ReadDir` + N `landlock_add_rule` calls at shield startup;
  no measurable latency impact (ADR 0002).
- If a future change adds a new secrets-adjacent file that is NOT named
  `secrets.key` or nested under `secrets/`, it will NOT be automatically
  excluded — anyone adding a new sensitive file under `~/.agentjail` must
  extend `AgentjailSecretsProtectedNames()` (and the matching Rego predicate)
  rather than assume the exclusion is content-aware.
