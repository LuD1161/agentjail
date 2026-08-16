# ADR 0110: network flag consolidation and canonical precedence

Status: Accepted; tunnel IPv6 default superseded by ADR 0138-dual-stack-default

## Context

The shield accumulated three independent network knobs, each wired up ad hoc
as ADR 0077 (MITM), ADR 0109 (capture gateway), and AGE-262 (tunnel IPv6) each
added its own carve-out:

- MITM: `--mitm`/`--no-mitm` (CLI) over `network.tunnel_mitm` (config,
  tri-state `*bool`), resolved by `resolveMITM` in `internal/shieldapp/main.go`.
- Capture gateway: `--no-provider-gateway` (CLI) over `network.capture_gateway`
  (config, tri-state), resolved inline in `main.go`.
- Tunnel IPv6 (AGE-262): the bare env var `AGENTJAIL_TUNNEL_IPV6=1`, read
  straight out of `os.Getenv` inside `tunnel_shield_darwin.go`. No config
  field, no CLI flag, no documented precedence, and the decision was made
  inside a darwin-only file instead of at the shared entrypoint the other two
  knobs use.

Three knobs, three different shapes, one of them entirely undocumented and
sourced from inside a platform-specific file rather than `main.go`. A user (or
`doctor`) had no single place to answer "what actually decided this?".

## Decision

One canonical precedence for every network knob, highest wins:

**CLI flag > env var (where one exists) > `policy.yaml` (`network.*`) > built-in default.**

Canonical knob list:

| Knob | CLI | Config (`network.*`) | Env | Default |
|---|---|---|---|---|
| TLS interception (tunnel) | `--mitm` / `--no-mitm` | `tunnel_mitm` (tri-state) | none | on |
| Capture gateway | `--no-provider-gateway` | `capture_gateway` (tri-state) | none | on |
| Tunnel IPv6 (AGE-262) | `--tunnel-ipv6` / `--no-tunnel-ipv6` | `tunnel_ipv6` (tri-state) | `AGENTJAIL_TUNNEL_IPV6=1` (transitional) | on (ADR 0138-dual-stack-default) |

Changes:

- `network.tunnel_ipv6 *bool` added to `NetworkConfig`, mirroring
  `TunnelMITM`/`CaptureGateway` exactly (tri-state pointer, same `Merge()`
  contract, same merge-test shape).
- `--tunnel-ipv6`/`--no-tunnel-ipv6` added to `agentjail-shield`, mirroring
  `--mitm`/`--no-mitm`. A new `resolveTunnelIPv6(ipv6Flag, noIPv6Flag,
  envSet, cfgTunnelIPv6) bool` in `main.go` implements the precedence table
  above for this knob and is the single place the on/off decision is made.
  The resolved value flows into `runShield` -> `startTunnelDarwin` as a plain
  `bool` parameter; the darwin tunnel file no longer reads the environment
  itself. This does not touch the v6 datapath (AGE-262) — only how the
  on/off decision is sourced.
- `AGENTJAIL_TUNNEL_IPV6` is kept working as a **transitional** override for
  one release (read once, in `resolveTunnelIPv6`'s caller, not scattered
  across files), then removed. Scripts should migrate to `--tunnel-ipv6` or
  `network.tunnel_ipv6`.
- `--netproxy`/`--no-netproxy` are **deprecated, not removed**: `--netproxy`
  already prints a one-line deprecation warning at launch and continues to
  function for one release. The transparent tunnel (`--tunnel`) is the
  supported replacement (ADR 0104).
- `agentjail doctor` prints, for each of the three knobs, the effective value
  it can currently see (from `policy.yaml` and, for tunnel IPv6, the env var)
  and which layer decided it — env/config/default — plus a note that a CLI
  flag on the next launch still takes precedence over all of it (doctor does
  not launch anything, so it cannot observe a CLI flag directly).
- Internal re-exec plumbing env vars (`AGENTJAIL_LANDLOCK_*`,
  `AGENTJAIL_SHAPE_DISAGREEMENT`, `AGENTJAIL_FORCE_USERNS_FAIL`) are explicitly
  OUT of this consolidation — they are not user-facing knobs, just re-exec
  plumbing, and keeping them out of the precedence table keeps the table
  meaningful.

## Consequences

- One precedence rule to document, test, and reason about, instead of three
  bespoke ones (one of which was undocumented).
- `network.tunnel_ipv6` is a real, mergeable policy field: overlays and
  `agentjail policy` tooling can set it like `tunnel_mitm`/`capture_gateway`
  instead of requiring an env var nobody could discover from `policy.yaml`.
- `AGENTJAIL_TUNNEL_IPV6` still works for one release, so existing scripts and
  the AGE-262 rollout are not broken by this change; it is scheduled for
  removal once `--tunnel-ipv6`/`network.tunnel_ipv6` have had a release to
  land.
- `doctor` cannot show a live CLI-flag override (it never launches the
  agent), so its "source" column tops out at env/config/default; this is
  called out explicitly in its own output rather than silently overstating
  what doctor can see.
- ADR 0138-dual-stack-default later enabled the existing IPv6 datapath by
  default without changing this ADR's precedence.
- No change to the IPv6 datapath itself, the MITM datapath, or the capture
  gateway's fail-closed contract (ADR 0109) — this ADR is scoped to how the
  on/off decisions are sourced and documented, not to what they do once
  decided.
