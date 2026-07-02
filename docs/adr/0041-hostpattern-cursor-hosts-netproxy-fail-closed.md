# ADR 0041: Typed host classification, Cursor CLI hosts, and netproxy-failure fail-closed default

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** agentjail-core
- **Related:** [ADR 0038](0038-essential-vs-extended-allowed-hosts.md) (essential vs. extended allowed_hosts), [ADR 0039](0039-complete-shared-sandbox-contract.md) (shared sandbox contract), [ADR 0040](0040-mcp-derived-hosts-and-fail-loud-config.md) (MCP-derived hosts, fail-loud config load)

## Context

Three smaller gaps remained after ADR 0040:

1. **Wildcard-DNS "theater."** `resolveAllowedHosts` in `shield_darwin.go`
   calls `net.LookupHost` on every entry of `cfg.EffectiveAllowedHosts()`,
   including wildcard entries such as `*.claude.ai` or `*.posthog.com`.
   `net.LookupHost("*.claude.ai")` can never resolve as a literal DNS name --
   the call always fails, and the failure path logs an `INFO: could not
   resolve ... - skipping` line on every single shield launch. This is pure
   noise: sbpl cannot enforce a wildcard host by IP either way (this whole
   function is a best-effort, informational layer -- the real hostname-based
   enforcement point is netproxy), so nothing is gained by attempting the
   doomed lookup, and something is lost (signal-to-noise in shield startup
   logs).

2. **Cursor CLI login/update hosts were missing.** The Cursor block in
   `ExtendedDefaultAllowedHosts()` only listed the `*.cursor.sh` API
   subdomains (`api2.cursor.sh`, `agent.api5.cursor.sh`, the
   `authenticate*.cursor.sh` family). The `cursor.com` / `www.cursor.com`
   hosts used by Cursor CLI's login and self-update flows were absent, which
   breaks `cursor-agent login` / update checks under the shield even though
   the API hosts are reachable.

3. **A netproxy start failure silently downgraded network enforcement.**
   `shield_darwin.go` and `shield_linux.go` both handled "netproxy binary not
   found" and "netproxy failed to start" the same way: print a `WARNING` to
   stderr and continue with port-only egress filtering (TCP 80/443 allowed
   to any host, no per-host allowlist). The agent launches either way -- the
   only difference is a log line the operator may not see. This means a
   transient failure (e.g. a stale `$AGENTJAIL_NETPROXY` path, a port already
   in an unexpected state) silently drops the user's `network.allowed_hosts`
   / MCP-derived host enforcement without ever refusing to launch, the same
   class of problem ADR 0040 fixed for a malformed `policy.yaml`.

4. **`chat.openai.com` was missing from the essential tier.** Codex CLI still
   normalizes some auth/session requests against the legacy
   `chat.openai.com` backend URL, even though `api.openai.com` is the primary
   API host and `chatgpt.com` is the current web host (both already
   essential). Without `chat.openai.com`, Codex CLI auth can break under the
   shield.

5. **The two enforcement-path callers called `config.LoadOrDefault` directly**,
   the same function every CLI/UI command uses for convenience reads. There
   was no separately named entry point that made the "this call site must be
   fail-loud" contract explicit at the call site itself -- a future CLI-side
   change to loosen `LoadOrDefault`'s error handling (e.g. for a friendlier
   `agentjail policy show` UX) could silently weaken the shield/netproxy
   launch-time guarantee too, since they shared the same function.

## Decision

### `HostPattern` / `ClassifyHost`: typed host classification

Add `agentpolicy/config/hostpattern.go`:

```go
type HostPattern struct {
    Pattern  string
    Wildcard bool // true iff Pattern has a "*." prefix
}

func ClassifyHost(h string) HostPattern
```

`resolveAllowedHosts` (macOS shield) classifies each host via `ClassifyHost`
and skips `net.LookupHost` entirely for `Wildcard` entries -- no behavior
change for exact hosts, no more "skipping" log noise for wildcards. Linux's
shield does not resolve hosts at all (Landlock has no IP-based network
primitive), so there is no equivalent call site there.

This type is deliberately scoped narrowly: `EffectiveAllowedHosts()` still
returns `[]string` at the serialization boundary (netproxy's `matchHost` and
`ToOPAData` both consume plain strings, per ADR 0038's original design) --
`HostPattern` is not threaded through every consumer, only the DNS-resolution
decision that actually needs to distinguish the two cases.

### Cursor CLI: add `cursor.com` / `www.cursor.com`

Added to the Cursor block in `ExtendedDefaultAllowedHosts()` alongside the
existing `*.cursor.sh` API subdomains, for login/update flows. Deliberately
NOT a broad `*.cursor.sh` wildcard -- the existing exact-subdomain list stays
exact, this only adds the two additional exact hosts Cursor CLI needs.

### netproxy-failure fail-closed default

Added a shared, OS-agnostic `abortOnNetproxyFailure` helper
(`cmd/agentjail-shield/netproxy_failure.go`) that both `shield_darwin.go` and
`shield_linux.go` call when netproxy was requested (`!noNetproxy`) but its
binary could not be located, or it failed to start. The new default: emit an
`audit.ShieldFailed` event, print a clear stderr error naming the failure,
and `os.Exit(1)` -- the shield refuses to launch the agent rather than
downgrading to port-only egress.

`--no-netproxy` is unchanged: it remains the explicit, intentional opt-out
for port-only mode (no per-host enforcement), and `abortOnNetproxyFailure` is
never invoked on that path -- the whole netproxy-start block is skipped when
`noNetproxy` is true, exactly as before.

### `chat.openai.com` added to `EssentialAllowedHosts()`

Added as an exact hostname (no wildcard), matching the existing essential-tier
convention, alongside `api.openai.com`, `auth.openai.com`, and `chatgpt.com`.

### `LoadPolicyForEnforcement`: a canonical, separately named enforcement load path

Added `config.LoadPolicyForEnforcement(path string) (*PolicyConfig, error)`,
used by `agentjail-shield`'s `main.go` and `agentjail-netproxy`'s `loadPolicy`
in place of the shared `config.LoadOrDefault`. It has the same observable
behavior as `LoadOrDefault` today (distinguishing "file absent" from "file
present but malformed" via `os.Stat`, rather than unwrapping `Load`'s error),
but exists as its own function so the fail-loud contract for enforcement
call sites is explicit and does not depend on `LoadOrDefault` -- used by
every CLI/UI command for convenience reads -- never being loosened for a
CLI-side UX reason.

## Consequences

- **A netproxy start failure now stops the agent from launching**, instead
  of silently running it with a strictly weaker network posture than the
  user configured. This is intentionally more disruptive than before,
  mirroring ADR 0040's "malformed policy.yaml" decision: a degraded
  enforcement posture is a hard failure, not a silent downgrade.
- **Operators who want the old best-effort behavior use `--no-netproxy`
  explicitly** -- the shield no longer decides that trade-off for them after
  the fact.
- **Shield startup logs are quieter** for deployments whose `allowed_hosts`
  include wildcard entries (the default extended list has several: `*.claude.ai`,
  `*.sentry.io`, `*.googleapis.com`, `*.huggingface.co`, `*.posthog.com`) --
  no behavior change, only noise removal.
- **Codex CLI auth works under the shield** without a manual `allowed_hosts`
  addition for `chat.openai.com`.
- **The fail-loud enforcement-load contract is now decoupled from
  `LoadOrDefault`'s general-purpose CLI/UI usage.** `LoadPolicyForEnforcement`
  behaves the same as `LoadOrDefault` today, but a future change to
  `LoadOrDefault` for CLI convenience cannot silently change what the shield
  or netproxy do on a malformed policy file.
- **No `.rego` changes.** All changes are Go-side: host-list membership,
  DNS-resolution control flow, shield process-exit control flow, and the
  enforcement config-load entry point. `mcp_policy.rego` / `web_policy.rego`
  / netproxy's own `matchHost` are unaffected.
