# 0042 - Session-aware netproxy control plane (one proxy, per-session allowlists)

Status: Accepted

## Context

`agentjail-netproxy` enforces `network.allowed_hosts` for shielded agents. Until
now it held ONE global allowlist loaded from `policy.yaml`, and the shield reused
"whatever is listening on `127.0.0.1:9100`" via a blind TCP dial. Two problems:

1. **Stale reuse.** The shield reused any listener on the fixed port without
   verifying it, and (on macOS) `syscall.Exec` means the shield's cleanup
   `defer` never runs, so the proxy outlives the session. A NEW session could
   silently inherit an OLD session's proxy and allowlist. The only workaround
   was a manual `pkill` / `kill -HUP`.
2. **No per-session / per-folder scoping.** A single global allowlist cannot
   give repo A and repo B different egress, and there was no in-session way to
   grant a host. Running one netproxy per session (8 sessions -> 8 proxies) was
   rejected as wasteful.

We want ONE netproxy serving every session, each with its own allowlist, plus a
foundation for per-folder overlays (see the project-overlay ADR) and runtime
grants (AGE-93) -- without letting the sandboxed agent widen its own egress.

This is a Tier-1 (hook + OS sandbox) mechanism. The eventual protocol-aware
WireGuard gateway (AGE-81) will replace the *transport* (HTTP CONNECT ->
transparent tunnel) and therefore the token-in-Proxy-Authorization binding, but
the control/policy layer here -- per-session identity, resolved allowlists,
registration, leases, grants -- is transport-agnostic and carries forward.

## Decision

One netproxy, session-aware, with a control plane the agent cannot reach.

- **Typed protocol (`internal/proxyctl`).** `Token`, `Fingerprint`,
  `SessionPolicy`, `Request`/`Response`; JSON only at the socket boundary. Both
  the netproxy (server) and shield (client) depend on these types; the client
  helpers are `QueryFingerprint` / `Register`.
- **Per-session tokens, no global fallback.** Each shielded session gets an
  unguessable 32-byte base64url `Token`. The shield registers the session's
  resolved `EffectiveAllowedHosts` under that token and injects
  `http://<token>:@127.0.0.1:9100` so the agent's HTTPS traffic carries the token
  as the Basic-auth username. netproxy keys the allowlist by token; a CONNECT
  with a missing/unknown/expired token is denied (407) -- there is no global
  allowlist left to be stale or to leak between sessions.
- **Control socket unreachable by the agent.** The control plane
  (fingerprint / register / future grant) lives on a Unix socket at
  `~/.agentjail/run/netproxy-ctl.sock`. The token in the agent env is a
  DATA-PLANE bearer only; it carries no control power because the socket is
  unreachable:
  - **Linux:** `~/.agentjail` is granted read-only to the agent
    (see [ADR 0034]/`shield_agentpaths.go`); AF_UNIX `connect()` requires the
    WRITE access right on the socket inode, which the read-only grant withholds
    (the exact inverse of the single-file write grant that keeps `daemon.sock`
    reachable). A Landlock enforcement test proves the agent cannot `connect()`
    the control socket while it still can `connect()` the daemon socket.
  - **macOS:** the sbpl profile emits `(deny network-outbound (literal <path>))`.
    Seatbelt models AF_UNIX `connect()` as a network op under `(allow default)`,
    so an explicit deny is required.

  This location refines the original plan's `$XDG_RUNTIME_DIR` choice: on Linux
  `$XDG_RUNTIME_DIR` (`/run/user/<uid>`) is itself only a read-only grant, so it
  would rely on the same "read-only withholds connect-write" property anyway,
  while being frequently unset on macOS. `~/.agentjail/run` is one path on both
  OSes, reuses the grant we already reason about, and is proven by the same
  enforcement test.
- **Safe singleton ownership + fingerprint.** netproxy owns the control socket
  under an `flock`'d lockfile (stdlib `syscall.Flock`); it clears a stale socket
  only after confirming nothing live answers it, and never binds over a live
  owner. A launching shield calls `QueryFingerprint`:
  - compatible `ProtocolVersion` -> register + reuse (binary drift tolerated;
    we do not restart a proxy serving other live sessions for a version bump);
  - incompatible -> FAIL CLOSED (refuse to launch; ask the user to restart the
    proxy) -- never silently kill another session's proxy;
  - no control socket but `:9100` occupied by an unverifiable listener -> FAIL
    CLOSED (refuse; do not kill by port).
- **Leases, not deregistration.** macOS cannot deregister post-`exec`, so a
  registration is a LEASE with a hard absolute cap (`MaxLeaseTTLMs` = 24h),
  reaped by netproxy regardless of traffic. An agent-spawned background process
  cannot keep a token alive by generating traffic.
- **Additive/fail-closed posture.** `session_registered` / `session_expired`
  audit events are defined (`internal/audit`). The token and proxy URL are never
  logged.

## Consequences

- Stale reuse is impossible: config is per token, registered fresh each launch;
  there is no global allowlist to go stale. No manual `pkill`.
- Two sessions (sequential or concurrent) with different allowlists do not bleed;
  an unknown token is denied outright.
- An unverifiable or protocol-incompatible proxy makes a launch fail closed with
  a clear message rather than silently weakening or hijacking enforcement.
- The agent cannot reach the control plane on either OS (enforcement-tested on
  Linux; sbpl deny asserted on macOS), so the injected token cannot be used to
  self-grant.

Known limitations / follow-ups:

- **Proxy process lifecycle.** netproxy is still a shield-spawned child, not a
  persistent daemon. On Linux the shield reaps the proxy it started on exit; if
  session A started the proxy and session B reused it, A's exit stops the proxy B
  depends on. On macOS the proxy persists after `exec` (by design for the
  singleton) and is not reaped until the machine restarts. A persistent
  netproxy service (or refcount) is a follow-up.
- **24h lease cap.** A single session running longer than 24h would lose its
  registration; re-registration/heartbeat is a follow-up.
- **Audit sink.** `session_registered`/`session_expired` currently fire to a
  `NopEmitter`; wiring netproxy to the store-backed `audit.Emitter` (or routing
  via the daemon) per the store-singleton rule is a follow-up.
- **Non-HTTP protocols.** This is HTTP CONNECT only; Postgres/Redis/SSH remain
  blocked by the OS sandbox (port-9100-only). Enabling them is AGE-81 (SOCKS5,
  then the WireGuard tunnel), which will replace the token-in-Proxy-Authorization
  binding with tunnel/peer identity while reusing this control/policy layer.

See also: [ADR 0034] (platform shared contract), [ADR 0040]/[ADR 0041]
(allowed-hosts model, fail-loud/fail-closed), AGE-81 (WireGuard gateway),
AGE-77 (per-folder policy), AGE-93 (runtime `/agentjail allow`).

[ADR 0034]: ./0034-platform-backend-shared-contract.md
[ADR 0040]: ./0040-mcp-derived-hosts-and-fail-loud-config.md
[ADR 0041]: ./0041-hostpattern-cursor-hosts-netproxy-fail-closed.md
