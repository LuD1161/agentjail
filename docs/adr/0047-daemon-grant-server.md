# 0047 - Daemon-hosted grant server with peer-PID binding

Status: Accepted

## Context

Runtime host grants ([ADR 0044], `agentjail allow host <h>`) allow an agent to
request a new egress host mid-session. The request/approve flow is designed to
work without the agent holding approval authority - the agent files a request via
its own session token, and a human approves from outside the sandbox.

Until now, approval and grant enforcement have lived entirely in netproxy
([ADR 0044]). This creates a dependency: grants only work when netproxy is
running. With [ADR 0046], netproxy became opt-in (`--netproxy` flag, off by
default); that made MCPs work on macOS but left runtime grants dormant in the
default (netproxy-off) case. An agent can still call `agentjail allow`, the
request is recorded, but approval has nowhere to live and the session cannot
benefit.

The daemon runs always - it evaluates every hook call and maintains the audit
log. Moving the grant server to the daemon decouples grant availability from the
netproxy opt-in flag: agents can request and users can approve grants at any
time, whether netproxy is on or off.

The hard problem remains unchanged: grants must not be approvable from the
sandboxed agent itself. Netproxy achieved this via socket-level access control
([ADR 0042]): `netproxy-ctl.sock` is agent-unreachable by design. The daemon's
`daemon.sock` is agent-reachable (it must be, for hook eval), so we need a
complementary control socket (`daemon-ctl.sock`) that carries the same
unreachability guarantee, bound the same way.

Additionally, approval must be transactional: a failed persist (writing the next
session's overlay) must fail the approval atomically, not silently leave the
approval granted without persistence. And the daemon must have a way to
authorize approval requests for a specific session - not via a token (tokens are
memory-only and not on disk), but via the requesting process's own peer identity
(PID, user, cwd) so it can authorize via its socket as well.

## Decision

**Two-socket daemon grant server, with peer-PID session binding and transactional
approval.**

### Socket architecture

- **`daemon.sock`** (agent-reachable): Hook evaluation, policy queries, and
  grant *requests*. The agent can call `agentjail allow host <h>` and the
  request lands here.
- **`daemon-ctl.sock`** (agent-unreachable): Grant *listing* and *approval*
  (approve/deny). The human runs `agentjail grants` / `agentjail grant approve
  <id>` / `agentjail grant deny <id>` from an unsandboxed terminal. Mirrors the
  netproxy control plane ([ADR 0042]) with the same filesystem sandbox
  protection: read-only `~/.agentjail` on Linux (AF_UNIX connect/write denied),
  sbpl deny on macOS.

### Peer-PID binding and session discovery

Grant requests on `daemon.sock` include a per-hook `session_id` (opaque handle,
not authoritative), but the daemon does NOT use it to authorize the request;
instead:

- **Peer-PID extraction**: On Linux, `SO_PEERCRED` yields the requestor's PID,
  UID, GID. On macOS, `LOCAL_PEERPID` yields the PID.
- **Parent chain walk**: The daemon maintains a registry of active sessions,
  keyed by the PID of the active hook process (the agent's session). When a
  grant request arrives with a peer PID, the daemon walks the process tree
  backwards - from the requesting process's parent PID, then parent's parent,
  etc. - looking for an active session registration. The session is discovered
  from the kernel, not from the request itself. An agent cannot claim to be
  "session 42"; the daemon verifies it actually is.
- **CWD and persist path**: The active session registration includes the daemon's
  own cached observation of the session's CWD at registration time (from shield's
  `session.register` call over `netproxy-ctl.sock`, [ADR 0042]). When approval
  happens, the persist step uses that daemon-observed CWD (not a path from the
  approval CLI) to load and update `.agentjail/policy.yaml`. This prevents a
  TOCTOU attack where an agent requests, then changes directory before the human
  approves.

### Grant modes and persistence

The daemon supports two grant modes, selected at approval time (not request time):

- **Default mode (persist-only)**: The approval writes the host to the session's
  `.agentjail/policy.yaml` in `network.allowed_hosts`, so the next time that
  repo is opened in a session, the host is allowed. The live grant (permission
  to reach the host in the current session) is NOT applied in the default mode.
  This is the path that works with netproxy off.
- **`--netproxy` mode (live + optional persist)**: If netproxy is running when
  approval happens, the human can add `--live` to apply the grant immediately
  to the current session. This mirrors [ADR 0044]'s live grant path. Persist can
  also be added (`--live --persist`) to write the overlay and apply live
  simultaneously. Persist can be added without live (`--persist` alone) to write
  the overlay for next session without granting live authority. Live mode requires
  netproxy to be running at approval time.

Both modes are transactional with respect to persistence (see below).

### Transactional approval and atomicity

- **Claim**: The approval call invokes `ClaimGrant(grant_id)`, which atomically
  marks the pending request as claimed and retrieves its details (host, reason,
  ttl, created_at). Only one approver can claim a given grant_id; the second
  fails with "already claimed". This is the same guard as [ADR 0044].
- **Persist step** (if mode includes persist): Load `.agentjail/policy.yaml`
  from the daemon-observed CWD, merge the host into `network.allowed_hosts`,
  write atomically (temp + rename), hash the result, and update the trust file
  ([ADR 0043]).
- **Live step** (if mode is `--live` and netproxy is reachable): Call
  `netproxy-ctl.sock` to add the host to the session's live allowlist
  (mirroring [ADR 0044]'s live grant path).
- **Atomicity and rollback**: Both persist and live steps are called before
  `CommitGrant(grant_id)` is called in the audit log. If persist fails
  (file I/O error, trust check failure), the approval fails with an error
  message. If live fails (netproxy unreachable when `--live` was requested),
  the approval also fails. Only if both steps succeed (if present) does
  `CommitGrant` record the decision in the audit log and mark the grant as
  approved. A transient error during persist (e.g., the disk fills up mid-write)
  does not leave the grant half-approved; the calling CLI retries the approval
  and reuses the same grant_id.

### Audit and durability

- **`policy.change_requested`** (fail-closed): Emitted before persist. If audit
  fails, the whole approval fails (`503`). This is the same fail-closed behavior
  as [ADR 0044].
- **`policy.changed`** (best-effort): Emitted after `CommitGrant` succeeds. If
  audit fails (e.g., the audit DB is locked), the approval succeeds, the grant
  is live and persisted, and the audit event is logged asynchronously or
  dropped. The approval decision is durable; the audit record is best-effort.
- **Grant request events** (`policy.grant_requested`) remain best-effort,
  unchanged from [ADR 0044].

### Display and session_id

The `session_id` in grant request/approval flows is display-only and not
authoritative:

- Request-time: The hook supplies `session_id` (Claude Code session ID or
  opaque handle) for UI display in `agentjail grants` output.
- Approval-time: The CLI shows `session_id` but does not transmit it to the
  daemon. The daemon looks up the grant by `grant_id` (the claim), resolves the
  session via peer-PID binding (not `session_id`), and retrieves the persistent
  session details (cwd, registered_at) from its own registry.

## Consequences

- **Grants work in the default (netproxy-off) case.** An agent can request a
  host, a human can approve it, and the next session in that repo inherits the
  allowed host. No netproxy required.
- **Live mid-session grants still work with `--netproxy`.** If netproxy is
  enabled, approval can use `--live` to grant the host to the current session
  immediately, identical to [ADR 0044]'s behavior. This unifies the grant
  interface: the same `agentjail allow` request works whether netproxy is on or
  off; the approval surface (`agentjail grants`, `agentjail grant approve`)
  remains unchanged.
- **Peer-PID binding prevents session spoofing.** The daemon does not trust a
  `session_id` from the request; it derives the session from the process tree.
  An agent cannot request on behalf of another session or forge a session ID -
  the daemon verifies the requesting PID is descended from an active session
  registration.
- **Transactional approval prevents partial state.** If persist fails, the grant
  is not approved; no half-approved state leaks. This is a stronger guarantee
  than the pre-transactional versions of the persist step (which could succeed
  live but fail to write the overlay).
- **CWD stability prevents TOCTOU attacks.** The persist path is derived from
  the daemon's registered CWD, not from the approval command's CWD, so an agent
  cannot change directories mid-approval to persist to a different path.
- **Test surface**: Unit tests for peer-PID binding (process tree walk,
  mismatched PID rejection), ClaimGrant atomicity (duplicate claims), transactional
  approval (persist + rollback, netproxy failures), and audit ordering (fail-closed
  on policy.change_requested).

### Known limitations / follow-ups

- **Grant approval requires netproxy socket to be running even for `--persist`
  in live mode.** If the human approves with `--live --persist` and netproxy is
  not reachable, the approval fails. In the default case (`--persist` alone),
  netproxy is not required. This is by design: `--live` is a mode that requires
  netproxy to be available.
- **Persist writes the session's `.agentjail/policy.yaml`, not a global
  allowlist.** This is inherited from [ADR 0044] and [ADR 0043]; grants only
  affect the folder where they are persisted.
- **macOS menubar Approve/Deny UI is a follow-up,** same as [ADR 0044]. CLI
  approve ships first; a point-and-click surface can be layered on top.
- **Non-HTTP protocols remain blocked** until the transparent tunnel lands (on
  Linux, and on macOS). HTTP CONNECT via netproxy is the current transport
  for grants.

This is phase 1: move grant server to daemon.

See also: [ADR 0042] (session-aware netproxy control plane), [ADR 0043]
(per-folder policy overlay trust gate), [ADR 0044] (runtime host grants),
[ADR 0046] (netproxy egress enforcement opt-in), and the transparent tunnel
follow-ups for Linux and macOS.

[ADR 0042]: ./0042-session-aware-netproxy-control-plane.md
[ADR 0043]: ./0043-per-folder-policy-overlay-trust-gate.md
[ADR 0044]: ./0044-runtime-host-grants.md
[ADR 0046]: ./0046-netproxy-egress-enforcement-opt-in.md
