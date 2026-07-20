# 0107 - Back NewGateway with the promiscuous serverNetstack

Status: Accepted

## Context

The macOS Network Extension transparent-proxy path runs WireGuard over the
extension's loopback. On this path the agent connects to the real destination
IP - the mac system resolver runs out-of-band, so the DNS-VIP scheme (ADR
0038-essential-vs-extended-allowed-hosts and friends) never applies.

`tunnel.NewGateway` used `netstack.CreateNetTUN`, whose gVisor stack adds only
the gateway's own address to the interface and drops SYNs addressed to any
other destination. The WireGuard handshake completed - the tunnel came up -
but the gateway never answered the tunneled TCP SYN
(`DialContextTCP: context deadline exceeded`), and nothing reached the MITM or
got captured.

## Decision

Back the WireGuard device with the `serverNetstack` primitive
(`internal/tunnel/servernetstack.go`, built in an earlier phase but never
wired in). `serverNetstack` enables `SetPromiscuousMode` and `SetSpoofing` on
the gVisor NIC and serves TCP via `tcp.NewForwarder`, so it accepts
connections addressed to any destination rather than only its own address.
`ListenAndServe` gains a push-based `serveServerNS` branch that drives
accepted connections into the existing MITM/passthrough handling.

## Consequences

- The macOS tunnel now captures traffic instead of timing out on every
  connection.
- `NewGateway`'s only caller is the darwin tunnel
  (`internal/shieldapp/tunnel_shield_darwin.go`); the Linux forward path
  (`NewForwardGateway`) is untouched by this change.
- Tests assert against `serverNS` instead of the removed `tnet` field.
