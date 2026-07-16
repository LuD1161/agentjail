# ADR 0085: the status line attests policy enforcement, not just shield activation

**Status:** Accepted

**Amends:** [ADR 0064-statusline-always-attests](./0064-statusline-always-attests.md)

## Context

[ADR 0064-statusline-always-attests](./0064-statusline-always-attests.md) fixed a real
bug and its reasoning holds: an unprotected session used to render nothing, silence reads
as "fine", and the status line is the only surface that survives Claude Code's terminal
takeover. Its rule — *never render silence* — stands and is not revisited here.

0064 keyed the badge on `AGENTJAIL_SHIELDED=1` alone, and defended that explicitly:

> The badge keys on shield activation rather than daemon reachability because it attests
> kernel-level enforcement, which is what `AGENTJAIL_SHIELDED` records. A shielded session
> with a dead daemon is still shielded.

Every clause of that is true. Landlock/sbpl really was on; the env var really does record
it; the session really was still shielded. The error is not in the facts, it is in what the
badge *says* about them. `🔒 secured by agentjail` is not read as "the kernel sandbox is
active". It is read as "agentjail is protecting me" — which spans both enforcement layers,
because agentjail sells both.

AGE-212 is what that gap costs. The policy daemon was down for three days (Jul 10–12).
The shield kept activating, so `AGENTJAIL_SHIELDED=1` stayed set, so the status line
rendered a green padlock for the entire window while policy enforcement was dead and
`agentjail-hook` was failing open to `levelAllow`. `decisions` recorded 0 rows on two of
those days; `shield.activated` logged 464. The one channel built to survive was up, was
visible, and was reassuring the user through a three-day enforcement outage.

The irony is exact. 0064's own Context says the badge exists because "an unprotected
session was therefore indistinguishable from a protected one". 0064 closed that hole for
the shield and left the identical hole open for the daemon: a policy-unprotected session
was indistinguishable from a policy-protected one. `shield only` is a half-truth that
renders as a whole one, and a half-truth on the security surface is the failure mode 0064
was written to kill.

0064 also anticipated this and traded it away deliberately:

> Two states were chosen over naming the cause (`no shield` vs `daemon down`) to keep the
> badge to one glanceable fact.

That trade priced `daemon down` as a *cause* of `UNSECURED` — a detail to defer to
`doctor`. AGE-212 shows it is not a cause of an already-visible state; it is a *distinct
state that renders as its own opposite*. The glanceability argument survives; the
two-states-only conclusion does not.

## Decision

The badge attests both enforcement layers. `protection` is a three-constant enum in
`cmd_statusline.go` — one named state per real configuration, so illegal states are
unrepresentable and the switch has nothing to render but a real state:

| state | condition | badge |
|---|---|---|
| `fullySecured` | shield on, daemon answers | `🔒 [secured by agentjail (<version>)]` |
| `shieldedPolicyDown` | shield on, daemon unreachable | `⚠ [POLICY OFF · shield only · agentjail]` |
| `unshielded` | `AGENTJAIL_SHIELDED != "1"` | `⚠ [UNSECURED · agentjail]` |

`unshielded` is the zero value: a `protection` that was never computed reads as
unprotected, never as secured. The `badge()` switch defaults to `UNSECURED` for any
unrecognised state, for the same reason.

`shieldedPolicyDown` names the state rather than collapsing into `UNSECURED`, because the
two demand different actions: `UNSECURED` means "you are not running under agentjail",
`POLICY OFF` means "you are, and half of it is dead — restart the daemon". Amber, not red:
the shield genuinely is holding, and 0064 is right that overstating that would be its own
inaccuracy. This is the one addition to 0064's glanceable-fact rule, and it is confined to
the state that reads as its own opposite.

**Liveness is a 50ms `wire.ControlOpPing` to `wire.DefaultSocketPath()`**, sharing doctor's
`probeDaemon` (ADR 0086-doctor-repairs-diagnosed) with a tighter budget. Only when the
shield is on — an unshielded session renders `UNSECURED` regardless, so the probe would buy
nothing but latency.

**A bare `connect()` is not liveness.** An earlier revision of this ADR dialed and closed,
and argued that a wedged daemon would time out into `POLICY OFF`. That was wrong, and
measured to be wrong: against a listener that never calls `accept()`, `net.DialTimeout`
returns **success in 55µs**, because the kernel completes the `AF_UNIX` handshake into the
accept backlog with no involvement from the process. A dial therefore badges a daemon that
evaluates nothing as `secured` — reintroducing, one layer down, the exact lie this ADR
exists to remove. Requiring a ping reply is what makes the claim true.

50ms, against doctor's 500ms, because doctor is a one-shot command and this runs on **every
prompt render**. The probe is kernel-local; `AF_UNIX` never touches a network. Benchmarked
on this host: a live accept resolves in ~9.6µs, a missing socket fails `ENOENT` in ~6.6µs,
a stale socket file fails `ECONNREFUSED` in ~7.0µs. The timeout is therefore ~5000x the
healthy cost and is not a latency budget — it is a hang guard. It bites in exactly one
case: a daemon holding the socket but not answering. That state cannot enforce policy, so
`POLICY OFF` is the correct reading, not a false negative.

The badge remains a **notification**, not an attestation, exactly as 0064 established:
`statusLine` lives in agent-writable `~/.claude/settings.json`, so anything that can forge
the env var can rewrite the command outright. Probing the daemon does not change that and
is not claimed to.

## Consequences

The AGE-212 window would now have rendered amber `POLICY OFF · shield only` for three
days instead of a green padlock. That is the whole point of the change.

Every prompt render now pings the daemon. At ~10µs against a render already costing
milliseconds this is unmeasurable, but it is new work on a hot path, and a wedged daemon
costs the full 50ms per render — visible if it persists, which is the intended signal.

The badge is no longer a pure function of the environment: it depends on live daemon state,
so it can now flap. A daemon restart flips the badge to `POLICY OFF` and back within a
render or two. That is truthful — the hook really is failing open during that gap — but it
is new visual noise where 0064 had none, and users who restart the daemon routinely will
see it.

`POLICY OFF` is a third badge users have never seen, and it will fire for anyone running
the shield without the daemon. If that turns out to be a deliberate supported configuration
rather than an outage, this will read as a false alarm and needs a follow-up — a suppression
env var, or a state that distinguishes "daemon not installed" from "daemon dead". Deferred:
no evidence anyone runs that on purpose, and inventing the escape hatch now would re-open
the hole this ADR closes.

Three probe timeouts now coexist in `cmd/agentjail`: 50ms here, 200ms in `install.go`,
500ms in `cmd_doctor.go`. The budgets genuinely differ (per-render vs one-shot), so this is
divergence and not drift — but it is three call sites re-implementing one dial, and it
belongs behind a shared `wire` helper taking a timeout. Left alone deliberately; out of
scope for this change.
