# 0106 - Widen the darwin session-socket wait to 30s

Status: Accepted

## Context

After `AgentjailTunnel start`, the shield polls `/tmp/agentjail.sock` (bound
by the Network Extension provider's `startProxy`) before launching the agent.
When a provider from a prior session is still resident, the NE stack reloads
it - stop, wait for `.disconnected` (roughly 10s), then start - to pick up the
new run's fresh WireGuard keys and port. The socket is unbound for the entire
reload window plus the provider's own app-start latency. The old 15s wait
raced that window and lost, falling back to a non-tunnel launch with no
capture.

## Decision

Widen the socket wait to 30s.

## Consequences

- The tunnel comes up reliably across provider reloads between sessions.
- A genuinely dead tunnel now takes 30s, not 15s, to degrade to the bounded
  non-tunnel fallback.
