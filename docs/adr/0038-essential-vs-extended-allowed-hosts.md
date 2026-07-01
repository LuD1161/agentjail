# ADR 0038: Essential vs. extended `network.allowed_hosts`

- **Status:** Accepted
- **Date:** 2026-07-01
- **Deciders:** agentjail-core
- **Related:** [ADR 0003](0003-mcp-reverse-proxy.md) (MCP reverse proxy), [ADR 0022](0022-netproxy-linux.md) (netproxy on Linux)

## Context

`network.allowed_hosts` had two independent, drifted representations:

1. `config.Default()` in `agentpolicy/config/config.go` -- the list `agentjail
   install` actually seeds into a fresh `~/.agentjail/policy.yaml`.
2. `agentpolicy/default_policy.yaml` / `cmd/agentjail/default_policy.yaml` --
   install/docs material. Only a self-comparison test read these against each
   other; neither was checked against `Default()`, so the two representations
   had diverged (the YAML files listed a small, stale subset while
   `Default()` carried the real, larger list).

Separately, `config.Merge` treated `Network.AllowedHosts` like every other
slice field: `len(overlay.Network.AllowedHosts) > 0` decided whether the
overlay replaced the base. Because a user's `policy.yaml` **fully replaces**
rather than extends the default list, a policy.yaml that customizes
`allowed_hosts` for one purpose (e.g. adding an internal registry) but omits
`api.anthropic.com` silently starves the agent of its own provider -- a
footgun with no warning at load time.

Both problems point at the same root cause: `allowed_hosts` had no concept of
"hosts the agent cannot function without" versus "hosts a user might
reasonably add, remove, or replace."

## Decision

Split `network.allowed_hosts` into three layers:

1. **Essential (`config.EssentialAllowedHosts()`)** -- a small, hardcoded,
   EXACT-hostname-only (no wildcards) list of the hosts an agent needs to
   authenticate and run inference against its own provider: Anthropic/Claude
   (`api.anthropic.com`, `claude.ai`, `platform.claude.com`), OpenAI/Codex
   (`api.openai.com`, `auth.openai.com`, `chatgpt.com`), and Google OAuth
   (`accounts.google.com`, `oauth2.googleapis.com`, needed for claude.ai's
   Gmail/Calendar/Drive connectors). This list is **not editable** via
   `policy.yaml` and is never itself serialized into a seed policy file --
   it lives in code only.

2. **Extended (`config.ExtendedDefaultAllowedHosts()`)** -- the broader
   removable/editable default set: wildcard hosts (`*.claude.ai`,
   `*.googleapis.com`, `*.sentry.io`), Cursor CLI subdomains, telemetry,
   hosted MCP endpoints, package registries, git hosting, and documentation
   sites. `config.Default().Network.AllowedHosts` now equals this list
   exactly (extended only -- essentials are deliberately excluded from the
   seed). Meta-proxy MCP hosts (`mcp.composio.dev`, `mcp.zapier.com`) and the
   Stripe payment MCP host (`mcp.stripe.com`) are deliberately excluded from
   both essential and extended, enforced by a test -- host allowlisting also
   governs shell/network egress, not just the MCP gate.

3. **Effective (`(*PolicyConfig).EffectiveAllowedHosts()`)** -- essentials
   deduplicated ahead of the (possibly user-overridden) extended list,
   essentials-first, order-stable. This is the **enforced** set.

### Additive merge semantics

`config.Merge`'s `Network.AllowedHosts` branch changed from
`len(overlay.Network.AllowedHosts) > 0` to `overlay.Network.AllowedHosts !=
nil`. yaml.v3 decodes an omitted `allowed_hosts` key to `nil` and an explicit
`allowed_hosts: []` to a non-nil empty slice, so this lets us distinguish "the
user didn't mention this field, keep the default extended list" from "the
user explicitly wants zero extended hosts." Either way, essentials still
apply via `EffectiveAllowedHosts` -- even `allowed_hosts: []` keeps the agent
able to reach its own provider. This nil-vs-empty change is scoped to
`Network.AllowedHosts` only; other slice fields keep their existing
`len() > 0` semantics.

### Enforcement point: netproxy

`cmd/agentjail-netproxy/main.go`'s `loadPolicy` -- the actual per-request
hostname gate on both macOS and Linux -- now loads presence-aware via
`config.LoadOrDefault` and returns `cfg.EffectiveAllowedHosts()` rather than
the raw `cfg.Network.AllowedHosts`. Without this change, essentials would be
"non-removable" on paper but not in practice: netproxy is what actually
decides whether a CONNECT is allowed. A **missing** policy file is not
treated as an error here either -- `LoadOrDefault` falls back to `Default()`,
so a fresh install with no `policy.yaml` yet still gets essentials.

`cmd/agentjail-shield/shield_darwin.go`'s `resolveAllowedHosts` (used for
sbpl IP allow-rules and the startup INFO log) was switched to the same
`EffectiveAllowedHosts()` call, so the shield's resolved/logged set stays
consistent with what netproxy actually enforces. (Linux's shield has no
per-host resolution step of its own -- Landlock has no network ABI, so
netproxy is the sole enforcement point on Linux.)

### OPA serialization

`ToOPAData()` now serializes `c.EffectiveAllowedHosts()` under the
`network.allowed_hosts` key, not the raw editable field. `data.agentjail.
config.network.allowed_hosts` therefore always means the EFFECTIVE egress
set (essentials + user list) to any Rego rule that reads it -- not the
removable subset a user's `policy.yaml` shows. This is called out in a code
comment in `config.go` so future policy authors are not confused about which
list they're seeing.

### YAML templates stay extended-only

`agentpolicy/default_policy.yaml` and `cmd/agentjail/default_policy.yaml`
list only the extended set (byte-identical to each other, and equal to
`ExtendedDefaultAllowedHosts()`, enforced by a drift test), with a comment
explaining that the essential provider hosts are always allowed from code and
are intentionally absent from the file.

## Consequences

- **Anti-footgun:** a user cannot accidentally break their own agent's
  provider connectivity by trimming or replacing `allowed_hosts` in
  `policy.yaml`.
- **Anti-tamper:** a compromised or malicious policy edit cannot silently
  reroute the agent's provider traffic by omitting or rewriting the essential
  hosts -- they are baked into the binary, not read from a file an attacker
  with file-write access could modify.
- **Minimized non-removable surface:** essentials are exact hostnames only
  (no wildcards) -- 8 hosts total. Anything broader (wildcards, Cursor,
  telemetry, hosted MCP, registries) stays in the removable extended set, so
  the "can never be turned off" footprint is as small as it can be while
  still being useful.
- **Drift eliminated:** `Default()` and the two `default_policy.yaml` files
  are now bound by a test that fails the build if they diverge, instead of
  silently drifting like they had been.
- **New user-facing behavior to document:** `allowed_hosts: []` in
  `policy.yaml` no longer means "block everything" -- it means "no extended
  hosts, essentials still apply." Documented in `docs/SANDBOX.md`,
  `docs/ARCHITECTURE.md`, and `cmd/agentjail-shield/README.md`.
- **Scope note:** this is domain control, not exfil-proofing (Tier 1.5, per
  `docs/SANDBOX.md`) -- a determined agent that can reach an essential
  provider host can still exfiltrate data through it in-band (e.g. as part of
  a prompt). Essential-host non-removability defends against accidental
  self-lockout and policy tampering, not against a fully compromised model
  abusing an allowed channel.
