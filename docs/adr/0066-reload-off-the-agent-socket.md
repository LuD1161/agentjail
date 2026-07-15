# ADR 0066: policy reload moves off the agent-reachable socket

**Status:** Accepted

## Context

`wire.ControlOpReload` and `wire.ControlOpPing` were dispatched in `daemonapp.handleConn` — on
`daemon.sock`, the socket every `agentjail-hook` connects to **from inside the sandbox**. That
is not incidental: `shield_agentpaths.go` grants the agent a single-file *write* on
`.agentjail/daemon.sock`, because `AF_UNIX connect()` requires write on the socket inode. The
agent must reach this socket for Tier-1 to work at all.

The prior reasoning (recorded in the code) was that reload "is not a privileged mutation — it
re-reads policy.yaml/rules that are already on disk, exactly like SIGHUP", protected by a 0600
socket plus a `SO_PEERCRED` peer-UID check, which was claimed to stop "a same-UID sandboxed peer
that can merely connect()".

That claim was false. The check is `peerUID == daemonUID` (`grantserver.go:177`), and the agent
runs as **the same UID as the daemon**. It passes. `SO_PEERCRED` proves "same Unix user", not
"outside the sandbox" — it is identity, not authorization. Any prompt-injected agent could shell
out and send:

```json
{"type":"control","op":"reload"}
```

Reload is not harmless, even though the agent cannot write `policy.yaml` (`~/.agentjail` is
granted read-only). It is **cheap to ask for and expensive to serve**: `reloadPolicy` does
`loadModules` + a full Rego recompile via `evaluator.Reload`. Meanwhile the hook runs on a ~30ms
budget and `config.DaemonUnreachable` defaults to `Allow` — fail open. So an agent could spend
CPU it does not own to push the daemon past the hook's deadline and have its *next* tool call
waved through unchecked. A DoS that degrades into a Tier-1 policy bypass.

Two details bound the severity, both verified rather than assumed:

- `evaluator.Reload` compiles **before** taking `engineMu.Lock()`, so eval does not block for the
  duration of a compile. The lock is held only for the pointer swap.
- SIGHUP delivery is already serialized: the signal loop handles it on one goroutine.

But the socket path had neither property: it is one goroutine per connection, with `connSem`
allowing up to `maxAgentConns` (256) concurrent connections — i.e. up to 256 concurrent Rego
compiles. That amplification is the vector.

A `ControlOpShutdown` (wanted so `agentjail uninstall` could stop a daemon the service manager
does not own, per ADR 0065) was considered and rejected for the same reason, more sharply: on
this socket it is an agent-reachable kill switch for the entire policy layer, since a dead daemon
means every hook fails open.

## Decision

**Reload moves to the privileged control socket.** It is now `grantctl.ReqDaemonReload`, served by
`grantServer.handleCtlConn` on `daemon-ctl.sock` — which the shield denies to the sandbox on both
platforms (outside the Landlock allowlist on Linux; explicit sbpl deny on macOS). Path/capability
separation is the actual boundary; the peer-UID check remains only as defence-in-depth against a
different-UID peer, which is all it can honestly do.

**Ping stays on `daemon.sock`.** It is side-effect-free, and the single-instance guard
(`singleton.go`) probes exactly that socket to tell a live daemon from a squatter (ADR 0060).
Moving it would break that guard.

**The agent socket refuses reload explicitly** — an error naming the reason, rather than
"unknown control op", so an operator on an older client learns where the verb went.

**Reloads are serialized** by `server.reloadMu`, making "at most one Rego compile in flight" a
property of the daemon rather than an accident of the delivery path. It does not deduplicate:
every caller still gets a real reload and an honest compile verdict.

**Refusal is distinguishable from unreachability.** `grantctl.RefusedError` marks "the round trip
completed and the daemon said no". The CLI must not conflate the two: a rejected policy has to be
surfaced, while an unreachable daemon must fall back to SIGHUP. Collapsing them is how a rejected
policy gets silently reported as applied.

## Consequences

The only agent-triggerable expensive operation is gone from the one socket the agent is required
to reach. What remains there is eval, grant requests, and a ping — all of which the agent is
supposed to use.

`agentjail policy` now needs `daemon-ctl.sock`. That socket is best-effort: if `newGrantServer`
fails to bind, the daemon logs "grants unavailable" and runs on. The existing pgrep+SIGHUP
fallback covers this — reload still happens, just without a compile verdict — so the degradation
is a lost error message, not a lost reload.

SIGHUP remains reachable by a same-UID agent, and Landlock does not mediate signals. It is not
closed here: it is serialized by the signal loop and coalesced by the signal channel, so it offers
no amplification, and it is the documented admin interface. Removing it would break the
`systemctl reload` idiom for a marginal gain over an attacker who can already spend their own CPU.
The honest statement is that this ADR removes the amplification, not every path to a reload.

Fail-open on daemon-unreachable (`DaemonUnreachable: Allow`) is unchanged and remains the load-bearing
assumption behind the whole class: it is what turns "daemon is slow" into "policy is bypassed".
Revisiting that default is out of scope here and worth its own ADR.

## Verification

Exercised against a live daemon, not only unit tests:

- Reload over `daemon.sock` → `{"ok":false,"error":"reload is not served on the agent socket..."}`,
  daemon logs the refusal with `peer_uid`.
- Ping over `daemon.sock` → `{"ok":true}` (singleton guard intact).
- Reload over `daemon-ctl.sock` → `{"ok":true}`, daemon logs "policy reloaded via grant control socket".
- Real CLI (`agentjail policy add`) → reload served over the control socket.
- Editing `policy.yaml` on disk then reloading moved the daemon's reported `mcp_blocked_count`
  5 → 6, proving the reload re-read and applied on-disk config rather than merely logging.
- `rm -rf /` still denied afterwards; zero ERROR/panic entries in the daemon log.
