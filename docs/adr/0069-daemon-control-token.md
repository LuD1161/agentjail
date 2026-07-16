# ADR 0069: the daemon control socket authenticates every verb

**Status:** Accepted

## Context

[ADR 0067](./0067-control-plane-token-auth.md) establishes the control-plane token;
[ADR 0068](./0068-netproxy-control-token.md) applies it to `netproxy-ctl.sock`. `daemon-ctl.sock`
is the last of the three, and the one whose existing guard was most convincing.

It checks `SO_PEERCRED` for `peerUID == daemonUID`, which reads as authentication and is not.
The sandboxed agent runs as the daemon's own UID, so the check passes for it. `SO_PEERCRED`
answers "which Unix user is on the other end", a question whose answer is the same for the
daemon, the CLI, and the agent. It cannot answer "is this peer inside the sandbox", which is
the only question that matters here.

Combined with the fact that Landlock does not mediate `AF_UNIX connect()` (ADR 0067), the socket
had no boundary on Linux. Its verbs are:

| verb | what an unauthenticated caller gets |
|---|---|
| `grant_approve` | self-approve its own pending host grant, and persist it to `policy.yaml` |
| `grant_deny` | discard a request before a human sees it |
| `grant_list` | read every session's pending requests, cwd, and reason |
| `daemon_reload` | force a full Rego recompile, on demand, at no cost to itself |

`daemon_reload` is the sharpest. [ADR 0066](./0066-reload-off-the-agent-socket.md) moved it here
*from* the agent-facing `daemon.sock` precisely because it is cheap to ask for and expensive to
serve, which makes it a fail-open DoS lever: the hook's budget is ~30ms and `DaemonUnreachable`
defaults to `Allow`, so a caller that can keep the daemon busy can make its own next tool call
bypass policy. That move was necessary and not sufficient — it relocated the verb to a socket
the agent can also reach. The reasoning was sound; only the reachability premise was wrong.

## Decision

Gate every verb on `daemon-ctl.sock` with `ctlauth`. There is no exception: unlike
`netproxy-ctl.sock`, this socket has no version-negotiation verb, so nothing needs to answer an
unauthenticated caller.

- `grantctl.Request` carries `CtlToken`. `ReqGrantRequest` is exempt because it is the agent's
  own verb and is served on `daemon.sock`, not here.
- The check sits **before the dispatch switch**, so a verb added later is gated by default. The
  test asserts the reload side effect does not fire, not merely that the reply says no.
- `SO_PEERCRED` stays, re-documented as what it is: defence-in-depth against a different-UID
  peer, which is all it can honestly do.
- The daemon mints the token in `startGrantServer` before binding. On failure the control socket
  is not served at all — the fail-closed outcome is no approvals and no reload, not an open
  socket.
- The CLI loads the token and explains that these commands must run outside a shielded session.
  A read failure inside the sandbox is the boundary working, not a misconfiguration.

## Consequences

All three control sockets now authenticate. The token, not the path and not the peer UID, is the
boundary on Linux; macOS keeps its sbpl profile as a second layer.

On macOS that second layer is now verified by execution rather than by reading the generator
(AGE-216; `test/sbpl-probe/`). It holds — a shielded agent reaches none of the three sockets —
but the enforcing rule is the trailing `(deny network*)` catch-all, **not** the explicit
per-path denies, which are redundant today. See ADR 0067 for the corrected mechanism.

The `daemon_reload` DoS lever is closed *on this socket*. **SIGHUP is not**, and reload remains
reachable by a same-UID agent through it: Landlock does not mediate signals. It is serialized by
the signal loop, so it offers no amplification over what any process on the box can already do,
and it is the documented admin interface. Unchanged from ADR 0067, and still worth revisiting.

`DaemonUnreachable: Allow` — the fail-open default that makes a reload storm worth attempting in
the first place — is also unchanged, and remains the more fundamental of the two. It deserves its
own ADR rather than an inherited default.

A same-UID process outside the sandbox (the user's own shell) can still read the token and use
these verbs. That is intended: it is the human's interface, and a process outside the sandbox
running as the user has already lost nothing left to protect.
