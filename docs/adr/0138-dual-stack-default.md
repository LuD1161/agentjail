# ADR 0138 — dual-stack default

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** agentjail-core
- **Supersedes:** the tunnel IPv6 default in [ADR 0110-network-flag-consolidation](0110-network-flag-consolidation.md)
- **Related:** [ADR 0136-tunnel-golden-image](0136-tunnel-golden-image.md)

## Context

ADR 0110-network-flag-consolidation made the transparent tunnel IPv4-only by
default and exposed IPv6 as an opt-in. The Tart testbed's IPv4-first resolver
made that posture look functional. On an IPv6-first macOS 26.2 host, the
Network Extension delivered resolved IPv6 destinations while the tunnel had no
IPv6 route. Extension lifecycle events were successful, but requests failed
before the gateway and produced no `network_requests` row.

Apple's `NETransparentProxyProvider` documentation says matched connect-by-name
flows continue to use the system's DNS behavior. That makes the address family
chosen by the host resolver part of the normal transparent-proxy input, not an
optional test condition. The contract was rechecked on 2026-08-15:

- <https://developer.apple.com/documentation/networkextension/netransparentproxyprovider>

A live A/B check with the same approved extension confirmed the boundary:
IPv4-only returned `no route to host` for IPv6 destinations with no request-row
delta; dual-stack reached the gateway, enforced named allow/deny policy, and
wrote durable request rows.

## Decision

The transparent tunnel is dual-stack by default. The canonical default is the
typed `config.DefaultTunnelIPv6` value shared by launch resolution and doctor.
The precedence from ADR 0110-network-flag-consolidation remains unchanged:
explicit CLI flag, transitional environment override, policy configuration,
then built-in default.

Users may still select an IPv4-only diagnostic posture with
`--no-tunnel-ipv6` or `network.tunnel_ipv6: false`. Tests that claim tunnel
coverage run without an opt-in override and require both an executed scenario
and a post-watermark request-row delta.

## Consequences

- IPv6-first hosts no longer bypass or fail before the tunnel gateway under the
  ordinary default configuration.
- The default matches the address families the approved extension and tunnel
  datapath already support; it does not loosen host, port, protocol, path, MITM,
  audit, or evidence policy.
- An explicit IPv4-only configuration remains available for diagnosis and is
  visible through the same configuration precedence and doctor output.
- Lifecycle success alone remains insufficient release evidence because it
  cannot prove that a selected flow reached the gateway.
