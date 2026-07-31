# 0050 - Configurable behavior when the daemon is unreachable (fail-open → tiered)

Status: Accepted (Phases 1 and 2 implemented; updates the prior fail-open
stance). Phase 3 (auto-recovery) is a separate follow-up — see
[plans/011-daemon-unreachable-policy.md](../../plans/011-daemon-unreachable-policy.md).

> **The `allow` default below is superseded by
> [ADR 0074](./0074-degraded-is-the-default-posture.md).** The tiered mechanism
> this ADR defines is unchanged; only the default moved, to `degraded`. The
> "behavior-preserving on upgrade" rationale for `allow` does not survive
> scrutiny: degraded's offline denials are a strict subset of the locked rules
> OPA already enforces online, so it cannot refuse a call a healthy daemon would
> have allowed.
>
> **Amended by [ADR 0073](./0073-fail-open-notice-uses-systemmessage.md).** The
> per-occurrence banner below is printed to stderr, which Claude Code discards
> on an exit-0 allow — so on the fail-open allow path it never reached the user
> and the silent-drift problem this ADR set out to fix survived. The notice now
> rides the response's `systemMessage` field.

## Context

When `agentjail-hook` cannot reach the daemon within its dial/round-trip
budget (~30 ms dial / 45 ms legacy round-trip), it currently **fails open**:
the tool call is allowed, a `fail_open` telemetry event fires, and a one-time
stderr warning is printed (gated by the `~/.agentjail/fail-open-warned`
sentinel, which the daemon now re-arms on startup — see the U2 fix). This
matches the prior "never block the agent" stance. Bridge-capable Codex requests
use a 250 ms healthy-response ceiling; see ADR 0118-codex-approval-broker.

Two problems with a single hard-coded policy:

1. **Silent false sense of security.** A user who installed agentjail to be
   protected keeps running, unprotected, after the daemon dies (crash, OOM,
   `brew upgrade` that doesn't reload launchd, or a deliberate DoS —
   P9). The OS shield still enforces files+network, but *all*
   command/MCP/web policy is silently off. The one-shot warning is too quiet.
2. **One size does not fit all.** A hobbyist wants work to continue (blocking on
   a dead daemon is infuriating). A fintech/regulated shop wants the opposite:
   if the guardrail is down, stop. Neither should be forced onto the other.

The hook is deliberately **stdlib-only** (no external deps, <50 ms budget) and
does **not** read `policy.yaml` — it cannot, without pulling in a YAML parser
and the OPA engine. So the config knob cannot simply be "read by the hook."

## Decision

### 1. A tiered `daemon_unreachable` policy (config knob)

Add a top-level `daemon_unreachable` setting to `PolicyConfig` with three levels:

| Level | Hook behavior when daemon is unreachable |
|---|---|
| `allow` (**default**) | Fail open — allow the call. Current behavior, preserved so nothing changes for existing users. |
| `degraded` (**recommended**) | Enforce a small **offline critical denylist** (the locked rules) via stdlib pattern-matching; allow everything else; print a loud per-call banner. Reduced-but-nonzero protection, work continues. |
| `deny` | Fail closed — deny the call with a clear reason + restart instructions. For regulated/critical environments. |

Default is `allow` so this change is **behavior-preserving** on upgrade; users
opt into `degraded`/`deny`. (We recommend `degraded` in docs and the default
`policy.yaml` comments.)

### 2. A daemon-written JSON sidecar (how the hook learns the level)

Because the hook can't read `policy.yaml`, the **daemon** serializes the
relevant slice of config into a small JSON file the hook reads with stdlib
`encoding/json` when — and only when — the daemon is unreachable:

- Path: `~/.agentjail/hook-fallback.json` (owned by `internal/wire`, alongside
  `DefaultSocketPath` / `FailOpenWarnedSentinelPath`).
- Written **atomically** (temp + rename, 0600) by the daemon on startup and on
  every SIGHUP config reload.
- Shape:
  ```json
  {
    "version": 1,
    "level": "allow|degraded|deny",
    "offline_rules": [ /* compiled critical-denylist matchers, see §3 */ ]
  }
  ```
- **Missing/unparseable sidecar → `allow`** (backward-compatible safe fallback:
  a fresh install or an old daemon that never wrote one behaves exactly as
  today). The hook never blocks because a sidecar is absent.

The sidecar is written by the daemon (the process that *has* the config and the
OPA bundle), so the hook stays stdlib-only. When the daemon is *reachable*, the
sidecar is irrelevant — normal full-policy evaluation happens over the socket.

### 3. Offline critical denylist (`degraded` mode enforcement)

The hook cannot run OPA offline, so `degraded` enforces only rules expressible
as **simple pattern checks** — precisely the locked-rule set from
`resolver.rego`, which is already the "can never be suppressed" crown-jewel set:

- `file_policy/agentjail_self` → deny Write/Edit whose path is under home
  `~/.agentjail`.
- `file_policy/agentjail_secrets` → deny Read of `~/.agentjail/secrets.key` or
  `~/.agentjail/secrets/**`.
- `command_policy/no-policy-mutation` → deny Bash whose parsed binaries (via the
  stdlib-only `internal/shellparse`, now hardened per P6) include an `agentjail`
  policy-mutation invocation.

The daemon compiles these into the sidecar's `offline_rules` as typed matchers
(kind = `path_prefix_write` | `path_read` | `command_mutation`, plus operands),
so the *daemon* owns the rule definitions and the hook is a dumb, fast matcher.
Everything not matched by an offline rule is **allowed** in `degraded` (reduced
protection, not full). This is the honest middle: the guardrails that matter
most for self-protection still hold even with the daemon down.

### 4. Loud, non-silent notice (all levels)

Regardless of level, replace the one-shot stderr warning with a **per-occurrence**
banner while the daemon is unreachable, naming the current protection level and
the exact restart command, e.g.:

```
⚠ agentjail: daemon unreachable — running at REDUCED protection (degraded).
  Critical self-protection rules still enforced; other policy is OFF.
  Restart: agentjail daemon restart    (diagnose: agentjail doctor)
```

`deny` mode's denial message carries the same restart instructions. The
`fail_open` telemetry event continues to fire on every occurrence.

### 5. Auto-recovery (separate, complementary — see Phase 3)

The best mitigation is for the daemon to rarely stay down: OS-level supervision
(launchd `KeepAlive`, systemd `Restart=always`) plus an optional hook-triggered
restart-and-retry on connect failure. This shrinks the window in which any of
the above matters. Scoped as a follow-up phase (ties into daemon restart on
upgrade) so it doesn't
block the policy knob.

## Consequences

- **Backward-compatible by default** (`allow`) — no behavior change on upgrade.
- Fixes the silent-drift problem for anyone on `degraded`/`deny`, and improves
  the notice even on `allow`.
- Serves both audiences (availability-first and containment-first) from one
  mechanism.
- Keeps the hook stdlib-only; the daemon owns all config knowledge.
- `degraded` gives reduced-but-real offline protection using the already-locked
  rule set — no new trust surface (the same rules OPA locks).
- New failure mode to watch: a **stale sidecar** (daemon died before writing an
  updated level). Mitigation: daemon rewrites on every reload; the hook treats
  an unparseable/old-version sidecar as `allow`. Documented, low-risk.
- Caveat: `deny` in a **non-interactive** context (CI, codex exit-2) is a hard
  stop by design; `degraded` is the right default there because it never fully
  blocks. (`ask` was considered as a fourth level but collapses to `deny` in
  non-interactive harnesses, so it is deliberately omitted for now.)

## Supersedes / relates to

- Updates the prior "never block the agent" stance — that remains the
  `allow` default, but is no longer the only option.
- Complements **U2** (sentinel re-arm), **P9** (DoS hardening), and daemon
  restart on upgrade.
