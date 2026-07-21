# ADR 0108 - serverNetstack: SACK parity and backpressure, not a stall fix

Status: Accepted

## Context

The macOS tunnel (`internal/tunnel.NewGateway`) fronts wireguard-go with a
promiscuous gVisor stack, `serverNetstack` (`internal/tunnel/servernetstack.go`).
While chasing the AGE-259 streaming hang (macOS `/v1/messages` h2 SSE never
captured), two properties of `serverNetstack` stood out against the upstream
wireguard-go `tun/netstack` reference and against Tailscale/sing-box/tun2socks:

1. It set **no** TCP options. gVisor disables SACK by default; every peer that
   runs gVisor over a userspace tunnel enables it.
2. Its outbound link-endpoint drain (`WriteNotify`) **dropped** packets when the
   queue was full instead of applying backpressure -- silent loss on a carrier
   the inner TCP treats as lossless. The upstream reference blocks; so does
   Tailscale's link endpoint.

These looked like the streaming-hang cause. They are **not**. A host-only
reproduction (two real wireguard-go peers over loopback + a lossy/latency UDP
shim + the real `serveH2`) established:

- Raw transport carries 100 MB byte-perfect; the full h2 SSE path carries
  multi-MB streams byte-perfect at loopback.
- At **200 ms RTT with 0% loss**, a 4 MB SSE stream completes in ~8 s -- the
  default gVisor windows are adequate; this is not a window/BDP problem.
- Under injected loss the transport slows (loss recovery), but enabling SACK +
  raising buffer ranges did **not** resolve the stall and did not clearly help,
  and the real macOS loopback WG path carries ~no loss anyway.

So buffer-size tuning was dropped as unvalidated, and the real AGE-259 hang is
being localized with live `serveH2` instrumentation (`AGENTJAIL_MITM_TRACE`) on
the actual macOS transport, not the pure-Go stack.

## Decision

Keep two small, defensible changes; drop the speculative one.

- **Enable TCP SACK** (`tcpip.TCPSACKEnabled(true)`) in `tuneServerNetstackTCP`,
  matching the upstream `tun/netstack` reference. Strict improvement for loss
  recovery; no downside.
- **`WriteNotify` blocks instead of dropping** when the outbound queue is full
  (guarded by a `done` channel so `Close` unwedges a parked producer). The
  counter `serverNSBackpressure` records how often the blocking fallback
  engages. Never silently drop segments the inner TCP expects delivered.
- **Do NOT** raise the send/receive buffer ranges or set moderate-receive-buffer:
  the on-host reproduction showed no benefit and a mild slowdown under loss.

## Consequences

- SACK parity with the reference; backpressure replaces silent drops. Both are
  correctness/robustness improvements, independent of AGE-259.
- The AGE-259 streaming hang remains open, now correctly scoped OUT of the Go
  transport layer and INTO the live macOS path (Swift `NETransparentProxy` pump
  in `macos/AgentjailExtension/Provider.swift`, real NE timing/MTU, or the real
  upstream h2 SSE) -- to be diagnosed with the shipped `serveH2` trace.
- Changes are OS-agnostic (pure gVisor); the Linux forward path is unaffected.
