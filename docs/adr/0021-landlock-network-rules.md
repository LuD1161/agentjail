# ADR 0021 — Landlock network rules (kernel 6.7+)

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** agentjail-core
- **Related:** [ADR 0001](0001-os-sandbox-enforcement-layer.md) (OS sandbox), [ADR 0004](0004-credential-broker-tier1.md) (credential broker)

## Context

The Linux shield (`agentjail-shield`) uses Landlock to restrict filesystem
access. Until now, network egress was not restricted on Linux — the
`shield_linux.go` comment stated "Landlock has no network ABI." That comment
was **stale**: Landlock gained `LANDLOCK_ACCESS_NET_CONNECT_TCP` and
`LANDLOCK_ACCESS_NET_BIND_TCP` in **ABI v4 (Linux 6.7, January 2024)**.

Without network restriction, a sandboxed agent on Linux can:
- Connect directly to IMDS (`169.254.169.254`) and read the instance role creds
- Bypass `agentjail-netproxy` by opening raw TCP sockets to any host
- Exfiltrate data to non-allowlisted hosts on any port

The macOS shield solves this with Seatbelt (localhost-only TCP) + netproxy
(per-host allowlist). Linux needs the same two-layer approach: Landlock
restricts TCP connect to the netproxy port only; netproxy enforces
`network.allowed_hosts`.

### golang.org/x/sys/unix coverage

`golang.org/x/sys/unix` v0.45.0 exposes:
- `LANDLOCK_ACCESS_NET_CONNECT_TCP` (0x2)
- `LANDLOCK_ACCESS_NET_BIND_TCP` (0x1)
- `LandlockRulesetAttr.Access_net` field

It does **not** expose:
- `LANDLOCK_RULE_NET_PORT` constant (value 2)
- `landlock_net_port_attr` struct

These are defined locally in `shield_linux.go` from the kernel UAPI
(`include/uapi/linux/landlock.h`). No dependency update is needed.

## Decision

Extend `applyLandlock()` in `cmd/agentjail-shield/shield_linux.go` with
network rules:

1. **ABI probing**: the existing `landlock_create_ruleset(VERSION)` probe
   returns the maximum ABI version. If `abi >= 4` (kernel 6.7+), the network
   access set is included in the ruleset's `Access_net` handled mask.

2. **Handled network access**: when netproxy is enabled (`netproxyPort > 0`)
   and ABI >= 4:
   - `LANDLOCK_ACCESS_NET_CONNECT_TCP` is handled → all TCP connect denied
     unless explicitly allowed.
   - `LANDLOCK_ACCESS_NET_BIND_TCP` is handled → all TCP bind denied (the
     agent never needs to bind; no rule is added).

3. **Allow rule**: a single `LANDLOCK_RULE_NET_PORT` rule grants
   `LANDLOCK_ACCESS_NET_CONNECT_TCP` for port `9100` (the netproxy port).
   The agent can only TCP-connect to port 9100, where `agentjail-netproxy`
   enforces `network.allowed_hosts`.

4. **Fallback** (kernel < 6.7): if `abi < 4`, network access is not handled
   by Landlock. A warning is printed to stderr and FS-only Landlock is
   applied (the pre-P2.1 behavior). This is fail-open for network — the agent
   can connect anywhere — but filesystem containment is still active.

5. **`--no-netproxy` mode**: when `--no-netproxy` is passed, `netproxyPort`
   is 0 and no network rules are added. The agent can connect freely (same
   as the macOS `--no-netproxy` port-based mode, but without port filtering
   since Landlock network is port-based and we don't enumerate allowlisted
   ports).

### Port-based, not IP-based

Landlock network rules restrict by **port**, not by destination IP. We
allow connect to port 9100, not to `127.0.0.1:9100` specifically. In
practice this is equivalent because:
- The netproxy listens on `127.0.0.1:9100`
- No other service on the host should listen on port 9100
- The agent's `HTTPS_PROXY` is set to `http://127.0.0.1:9100`

If a hostile service were running on port 9100 on another interface, the
agent could connect to it — but the agent is cooperative (foot-gun model),
not adversarial. The netproxy + Landlock combination is defense-in-depth,
not a hard boundary against a determined attacker.

## Consequences

**Positive:**
- On kernel 6.7+: agent is restricted to TCP connect only on the netproxy
  port. Direct egress to IMDS, attacker hosts, and non-allowlisted services
  is denied at the kernel level (`EACCES`).
- Closes the network bypass gap on Linux, bringing it to parity with macOS
  (Seatbelt localhost-only + netproxy).
- No new dependencies — `golang.org/x/sys/unix` v0.45.0 has the needed
  constants and struct field; only two local definitions are added.

**Negative:**
- Requires kernel 6.7+ for network restriction. On older kernels (the
  majority of current Linux deployments, including Debian 6.1), network is
  unrestricted by Landlock. The warning makes this visible.
- Landlock network is port-based, not IP-based. The restriction is "connect
  to port 9100 only," not "connect to 127.0.0.1:9100 only." Sufficient for
  the foot-gun model but not for adversarial defense.
- The `landlock_net_port_attr` struct and `LANDLOCK_RULE_NET_PORT` constant
  are defined locally. When `golang.org/x/sys/unix` adds them, the local
  definitions should be removed to avoid duplication.

**Implementation notes:**
- `applyLandlock()` signature changed: `applyLandlock(cfg, netproxyPort)`.
  `netproxyPort = 0` skips network rules (FS-only); `netproxyPort > 0` adds
  network rules when ABI >= 4.
- The stale comment "Landlock has no network ABI" is removed.
- Tests: `TestLandlockNetworkEnforcement` re-execs a child that applies
  Landlock with `netproxyPort=9100` and probes connect to a denied port
  (expects EACCES) and to port 9100 (expects ok or ECONNREFUSED, not EACCES).
  The test skips on kernels < 6.7.
