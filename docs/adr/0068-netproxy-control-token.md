# ADR 0068: the netproxy control plane authenticates every verb but fingerprint

**Status:** Accepted

## Context

[ADR 0067](./0067-control-plane-token-auth.md) establishes the control-plane token and applies
it to `secrets.sock`. `netproxy-ctl.sock` is the second of the three control sockets and had
no authentication at all — any process that could `connect()` it could call `register`.

`register` binds a session Token to an **egress allowlist**. netproxy keys the effective
allowlist per Token with no global fallback, so registration is the sole authority over where a
session may reach on the network. A caller who can register can re-register an existing Token
with an allowlist of its choosing, or mint a fresh one, and the data plane will honour it.

The isolation claim in `proxyctl` was the same one ADR 0067 refuted, stated more specifically:

> AF_UNIX connect() requires WRITE access to the socket inode, which the read-only grant does
> not confer ... (This is the exact inverse of the daemon.sock write grant, and is **proven by
> a Landlock enforcement test**.)

The cited test proves the opposite — it records `ctl_connect=ok`. Landlock does not mediate
`AF_UNIX connect()` at all, so no arrangement of filesystem grants makes this socket
unreachable on Linux. The claim's specificity is what made it convincing; it was never tested.

`fingerprint` is the one verb with a reason not to gate. It is the version-negotiation channel:
a shield calls it to decide whether to reuse a running proxy or fail closed on an incompatible
protocol. Gating it would break the mechanism that exists to resolve build mismatches — the
negotiation would fail before it could report *why*. It returns version data only and mutates
nothing.

## Decision

Gate every `netproxy-ctl.sock` verb on `ctlauth` except `fingerprint`.

- `proxyctl.Request` carries `CtlToken`, distinct from the per-session data-plane `Token`. The
  agent holds `Token` by design and must never hold `CtlToken`.
- The check sits **before the dispatch switch**, so a verb added later is gated by default
  rather than by remembering to gate it.
- netproxy mints the token in `run()` before binding and fails closed if it cannot. The token is
  injected into `newControlServer` rather than read there, so the caller owns the fail-closed
  decision and tests do not touch the real `~/.agentjail`. An empty token is refused at startup:
  `ctlauth.Valid` would reject every caller, presenting as an unregisterable proxy rather than
  as the misconfiguration it is.
- The shield reads the token inside `ensureSessionProxy`, which runs before `applyLandlock` by
  construction. A missing token fails the session rather than proceeding unregistered — an
  unregistered session has no egress, so there is nothing to gain by continuing.
- Rejections reply `unauthorized` uniformly, so the error does not disclose which verbs exist.

`fingerprint` stays unauthenticated. This is a named exception, not an omission.

## Consequences

The sandboxed agent can still reach the socket on Linux and always will — the token, not the
path, is the boundary. An agent that cannot read `~/.agentjail/control.token` cannot set its own
egress allowlist.

A mixed-binary pairing (new netproxy, old shield) fails closed: the old shield sends no
`CtlToken`, `register` is refused, and the session does not launch. Both binaries ship together,
so this is a development-tree state rather than a user-facing one.

The `/tmp` fallback for an unresolvable `$HOME` is no longer a special case worth its own
caveat. It was previously called out because the agent has a read-write grant on `/tmp` and the
socket therefore lost its (imagined) filesystem protection; since the path was never the
boundary, the fallback is no weaker than the normal path. The token file follows the same
fallback and carries the same 0600 protection.

`daemon-ctl.sock` is the last of the three; see [ADR 0069](./0069-daemon-control-token.md).
