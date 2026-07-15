# ADR 0074: degraded is the default daemon-unreachable posture

**Status:** Accepted (supersedes [ADR 0050](./0050-daemon-unreachable-policy.md)'s
`allow` default; the tiered mechanism ADR 0050 defines is unchanged)

## Context

ADR 0050 built the tiered `daemon_unreachable` policy — `allow` / `degraded` /
`deny`, with the daemon compiling the resolved level and an offline
critical-denylist into `~/.agentjail/hook-fallback.json` for the stdlib-only
hook to match. It shipped with `allow` as the default and this rationale:

> Default is `allow` so this change is **behavior-preserving** on upgrade.

That reasoning conflates two different things. `allow` preserves behavior in the
sense that *no configuration changed*. It does not follow that changing the
default would change behavior in any way a user would notice — and it does not.

`degraded` denies exactly three rules, compiled by `compileOfflineRules` from
`resolver.rego`'s `locked_rules`:

| Offline rule | Online counterpart |
|---|---|
| `file_policy/agentjail_self` | locked — writes under `~/.agentjail` |
| `file_policy/agentjail_secrets` | locked — reads of `secrets.key` / `secrets/` |
| `command_policy/no-policy-mutation` | locked — `agentjail policy`/`mcp`/`grant`/`trust`/`--persist`/`update` |

`locked_rules` is a constant in Rego, deliberately not in `policy.yaml`, so no
configuration can suppress these. **Every call `degraded` denies offline is
already denied online, unconditionally.** The command patterns are byte-identical
to `_is_policy_mutation`'s, behind the same `_mentions_agentjail` binary gate,
and the offline set *omits* the shell-redirect pattern — so it under-matches
rather than over-matches.

Therefore `degraded` cannot refuse a call that would have succeeded against a
healthy daemon. The set of newly-denied calls is empty. What it changes is the
opposite direction: under `allow`, a daemon that crashes takes agentjail's own
self-protection down with it, and the agent may then write `~/.agentjail`, read
the secrets store, or run `agentjail policy disable` — the exact operations the
policy layer exists to make impossible, available precisely when nothing is
watching.

This is not hypothetical. AGE-212 was a daemon dying and enforcement silently
lapsing, and the whole class of concern behind ADR 0066 and ADR 0069 reduces to
*if you can keep the daemon busy, the next tool call is unpoliced*. Gating the
control sockets (ADR 0067–0069) raised the cost of reaching that lever. This
addresses the lever.

## Decision

`daemon_unreachable` defaults to `degraded`.

An unset level resolves in three places, all of which move together — the
default is not one constant:

1. `config.Default()` — a fresh install's config.
2. `config.Merge()`'s three-way fallback — neither base nor overlay sets it.
3. `daemonapp.writeHookFallback()` — coerces an empty level before writing the
   sidecar. **This is the one that reaches existing installs**: a `policy.yaml`
   written before this ADR has no `daemon_unreachable` key, so this coercion,
   not `Default()`, is what their daemon applies.

`allow` remains available and is now an explicit opt-in. The choice did not
disappear; it stopped being silent.

## Consequences

Upgrading changes behavior — deliberately, for the first time on this knob. The
change is bounded by the argument above: only calls that a live daemon already
refuses are refused when it dies. A user who wants the old posture sets
`daemon_unreachable: allow`.

`deny` is untouched and remains the right answer for regulated environments. It
is not the default because a crashed daemon would then brick every agent on the
box, and in non-interactive contexts (CI) that is a hard stop with no human to
read the restart instructions. `degraded` never fully blocks.

**A missing sidecar still resolves to `allow`, and this default does not fix
that.** `degraded` enforcement is driven entirely by the sidecar's compiled
rules; with no sidecar there are no rules and `degraded` is vacuously `allow`.
The daemon writes the sidecar on startup, so the gap is the daemon that *never
started*, not the one that died. Naming it here rather than leaving it implicit:
this default protects against crash/OOM/kill, not against a fresh install whose
daemon has never run. Closing that would mean teaching the hook a hardcoded rule
set, which contradicts ADR 0050's "the daemon owns the rule definitions; the hook
is a dumb, fast matcher" split — worth doing only with a reason to reopen it.

Drift risk, inherited from ADR 0050 and now load-bearing for the default rather
than an opt-in: `compileOfflineRules` is kept in sync **by hand** with
`resolver.rego`'s `locked_rules`, `file_policy.rego`, and `command_policy.rego`.
If a locked rule changes online and not offline, `degraded` quietly stops
mirroring it. The subset argument this ADR rests on holds only while that sync
holds. A test asserting the two sets agree would make it structural; that does
not exist today.

Related: ADR 0050 (the mechanism and the tiers), ADR 0073 (the fail-open notice
now rides `systemMessage`, so the user actually sees the level), ADR 0066 /
0069 (reload as a fail-open DoS lever — the concern this default blunts),
ADR 0032 / 0048 (the secrets-store protection mirrored offline).
