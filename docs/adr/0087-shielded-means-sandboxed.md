# ADR 0087: AGENTJAIL_SHIELDED means a sandbox is applied

**Status:** Accepted

**Amends:** [ADR 0064-statusline-always-attests](./0064-statusline-always-attests.md),
[ADR 0085-statusline-attests-daemon](./0085-statusline-attests-daemon.md)

## Context

[ADR 0064](./0064-statusline-always-attests.md) keyed the status-line badge on
`AGENTJAIL_SHIELDED`, and stated the premise plainly:

> the badge attests kernel-level enforcement, which is what `AGENTJAIL_SHIELDED` records

The premise was false. The variable recorded that the **shield wrapper ran**, not that a
sandbox was **applied**.

On Linux, `applyLandlock` failing left three outcomes, and `AGENTJAIL_SHIELDED=1` was set
unconditionally after all of them:

- `errLandlockUnsupported` — printed "Landlock unavailable — sandbox enforcement disabled",
  emitted `ShieldFailed`, and **fell through**. No sandbox.
- Any other error — failed closed and exited, **unless**
  `AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1`, which fell through. No sandbox.
- Success — emitted `ShieldActivated`. Sandboxed.

A line commented `// Landlock applied` sat above the env-var append, false on two of the
three paths. On macOS, `execAgent` — whose own doc says *"execs the agent directly (no
sandbox) — used when sandbox-exec is absent (fail-open path)"* — set it too.

So on a kernel without Landlock the agent ran unsandboxed under `🔒 secured by agentjail`.
The shield told the audit log `ShieldFailed` and the user `SHIELDED=1`, from the same
function, in the same launch.

This was **not** staleness. `landlock_restrict_self` is irreversible for the process
lifetime ([ADR 0001](./0001-os-sandbox-enforcement-layer.md): "inherited and irreversible"),
and macOS applies its sbpl profile at `sandbox-exec` time. Whether a session is sandboxed
is decided at exec and cannot change. The value was **false at birth**, which no amount of
re-checking or re-sourcing repairs.

## Decision

**`AGENTJAIL_SHIELDED=1` is set if and only if a sandbox was applied.**

The rule lives in the tag-free contract as `AppendShieldedEnv(env, SandboxState)`
(`shield_contract.go`), which is now the **only** site in the tree that writes the variable.
Backends resolve a `SandboxState` and pass it; they do not re-implement the rule. Per
[ADR 0034](./0034-platform-backend-shared-contract.md) this is deliberate: the drift
cautionary tale in `AGENTS.md` is about *this exact variable* — macOS once omitted it
entirely — so a shared contract is the only shape that cannot drift again.

`NotSandboxed` is the zero value: a state nobody resolved cannot claim a sandbox.

**The env var stays; it is not replaced by a daemon query.** Sandbox state is an
immutable-at-exec fact, and a constant in the environment is the right mechanism for it —
in contrast to the daemon, which is mutable runtime state and is therefore probed on every
render ([ADR 0085](./0085-statusline-attests-daemon.md)). Routing the shield's own report
through the daemon was considered and rejected: `restrict_self` happens inside the agent's
process, so the daemon never witnesses it and cannot be an independent source. It could
only relay what the shield tells it — and it cannot even do that today, since
`ShieldActivated` is emitted without its `SessionID`, no control op exists to ask, and the
status line does not parse the session from stdin. Three new moving parts and a hard
dependency on daemon liveness, to carry the same claim no closer to the truth.

**Forgery is explicitly out of scope.** [ADR 0064](./0064-statusline-always-attests.md)
already establishes the badge as a notification, not an attestation: `statusLine` lives in
agent-writable `~/.claude/settings.json`, so anything that can forge the variable can
rewrite the status-line command outright. This ADR makes the variable honest about
**accidental** failure. That is its whole value, and it should be judged on that axis only.

## Consequences

A session on a kernel without Landlock, or launched through the
`AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` override, or via macOS's `execAgent` fallback, now
renders `⚠ UNSECURED` instead of a padlock. That is the point, and it is a **user-visible
change**: users on Landlock-less kernels who saw a padlock will now see the truth. Their
protection did not change; the report did.

The env var now agrees with the audit log by construction — `ShieldActivated` and
`SHIELDED=1` come from the same resolved state, and `ShieldFailed` and an absent variable
likewise. That divergence was the bug.

`AGENTJAIL_SHIELD_ALLOW_UNSANDBOXED=1` no longer produces a padlock, closing the H7 row in
[`docs/failure-scenarios.md`](../failure-scenarios.md).

**Not closed:** macOS sets `Sandboxed` *before* `syscall.Exec` hands off to `sandbox-exec`,
which is what actually validates the sbpl profile. If the profile is rejected the process is
already replaced and cannot correct the claim. That is a narrower window than the paths this
ADR closes — it needs profile pre-validation, tracked as C7 in the failure-scenario matrix —
but the variable is not yet *provably* true on darwin, only no longer knowingly false.

Tests assert the premise (state → env) rather than only the mapping (env → badge). Testing
the mapping alone is why this survived: the badge tests were green throughout.
