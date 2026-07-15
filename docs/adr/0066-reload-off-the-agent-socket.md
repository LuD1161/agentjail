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
`grantServer.handleCtlConn` on `daemon-ctl.sock`.

**Correction — what this buys, per platform.** This ADR originally claimed the control socket is
denied to the sandbox "on both platforms". That is false on Linux, and the repo already knew:

> `// Landlock cannot prevent AF_UNIX connect() - FS-only LSM. Issue #10.`
> — `shield_linux_enforce_test.go`, which observes `ctl_connect=ok` and logs it as
> "Landlock limitation; grant-socket isolation needs Tier 2+".

Landlock is a filesystem LSM; it does not mediate `AF_UNIX connect()`. Leaving the socket outside
the allowlist withholds nothing. The claim came from the doc comment on
`grantctl.ControlSocketPath`, which asserted the sandbox could not reach it — that comment was
wrong and has been corrected. Verified on kernel 6.1: `ctl_connect=ok`.

So, honestly:

- **macOS**: a real boundary. The shield denies network-outbound to the path, so the agent cannot
  connect.
- **Linux**: **structural only, not a security boundary.** A prompt-injected agent can still reach
  `daemon_reload` — and, pre-existing and independent of this ADR, `grant_list` / `grant_approve` /
  `grant_deny` (Issue #10).

What *does* hold on both platforms is `reloadMu`: it removes the amplification, which was the
actual severity multiplier (one goroutine per connection × `maxAgentConns` = up to 256 concurrent
Rego compiles). A serialized single compile is what SIGHUP already offered.

The peer-UID check remains, and is only defence-in-depth against a different-UID peer — all it can
honestly do, since the agent shares the daemon's UID.

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

The only agent-triggerable expensive operation is gone from the one socket the agent is *required*
to reach. What remains there is eval, grant requests, and a ping — all of which the agent is
supposed to use. On macOS that closes the hole. On Linux it relocates a verb the agent can still
reach, and the real mitigation is `reloadMu` removing the 256× amplification.

**Follow-up (the actual Linux fix): a control-socket token.** Landlock *does* mediate file reads —
`AgentjailSecretsProtectedNames` already withholds `secrets.key`/`secrets/` from the agent, and
`TestLandlockAgentjailSecretsExcluded` proves it works. So a random token written 0600 under a
read-denied child of `~/.agentjail`, required on every `daemon-ctl.sock` verb and compared in
constant time, is unforgeable by a sandboxed agent that can connect but cannot read. That closes
`daemon_reload` **and** Issue #10 (`grant_approve` self-approval) on Linux, using a mechanism the
codebase already has and tests. Deferred to its own change: it touches the grant plane, which is
fail-closed and audited, and deserves a focused review rather than a tail-end addition here.

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
- Landlock enforcement test on kernel 6.1 → `ctl_connect=ok`: the sandboxed agent CAN reach
  `daemon-ctl.sock` on Linux. This is the finding that corrected the Decision above.
- Real CLI (`agentjail policy add`) → reload served over the control socket.
- Editing `policy.yaml` on disk then reloading moved the daemon's reported `mcp_blocked_count`
  5 → 6, proving the reload re-read and applied on-disk config rather than merely logging.
- `rm -rf /` still denied afterwards; zero ERROR/panic entries in the daemon log.
