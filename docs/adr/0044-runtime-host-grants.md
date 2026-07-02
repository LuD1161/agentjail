# 0044 - Runtime host grants (`agentjail allow`), AGE-93

Status: Accepted

## Context

The session-aware netproxy ([ADR 0042]) and per-folder trust gate ([ADR 0043])
cover the two cases where a session's allowlist is known ahead of time: the
global policy and a trusted repo overlay. Neither covers the case that shows up
mid-session: the agent needs one more host right now (a staging API, an
internal package mirror) and the fix should not require killing the session,
editing `policy.yaml` by hand, and relaunching.

The obvious shape - let the agent ask for a host and a human approve it - has a
trust-boundary problem the moment you look for where "approve" would live:

- **`daemon.sock` is agent-reachable by design** (it is how the hook talks to
  the daemon on every tool call). Anything that grants network authority must
  NOT be servable there, or a sandboxed agent could eventually drive it itself
  (directly, or by tricking a hook round-trip).
- **`netproxy-ctl.sock` is the only socket proven agent-unreachable** on both
  OSes ([ADR 0042]: read-only `~/.agentjail` withholds the Linux AF_UNIX
  connect-write; sbpl denies it outright on macOS). It already holds the
  in-memory per-session `{token, allowlist}` state.
- **The per-session token is a real bearer secret.** It legitimately exists in
  the agent's own proxy env and in every request's `Proxy-Authorization`
  header - that is the intended data-plane binding. What must never happen is
  the token leaking anywhere else: not persisted to disk, not present in a
  pending request, a list response, or an audit `Detail`, and never accepted
  as an input to an approval call. The sandboxed agent can read
  `~/.agentjail/agentjail.db` (the directory is granted read-only), so the
  token must never land in that database either.

So the design question is not "how do we let the agent widen its own egress" -
it must not be able to - but "how do we let a human widen ONE session's egress,
from outside the sandbox, without adding a second place that holds grant
authority."

## Decision

**Request/approve split, with netproxy as the sole grant authority.** No new
daemon endpoint, no `grant_requests` DB table. Pending requests and the token
live only in netproxy's existing in-memory session registry; the daemon is not
in the grant path at all.

- **Request (agent, data plane, token-bound).** `agentjail allow host <h>
  [--ttl] [--reason]` issues a `GET
  http://grant.agentjail.local/allow?host=H&ttl=..&reason=..` through the
  agent's own `HTTPS_PROXY`. netproxy recognizes this reserved sentinel
  authority in its request handler - matched AFTER the token/auth lookup (an
  unknown or expired token still gets `407`) but BEFORE the generic
  `method != CONNECT` `405` path - and never forwards sentinel traffic
  upstream. It reads the session token from `Proxy-Authorization`, so the
  request is intrinsically bound to the caller's own session: the agent
  supplies no session ID and cannot request on behalf of another session. A
  `CONNECT grant.agentjail.local:443` is not a grant request; only `GET
  .../allow` is. Hitting the sentinel files intent only - it grants nothing.
  netproxy records an in-memory `pending{grant_id, host, ttl, reason, created,
  expires}`, emits `netproxy.grant_requested` (best-effort), and returns `202`.
- **Sentinel is hard-bounded.** Per-session and global pending caps,
  `MaxReasonLen`, `MaxGrantTTL`, per-request expiry, and duplicate coalescing
  (a repeat request for the same session+host updates the existing pending
  entry instead of piling up). Over a cap returns `429`; a malformed host or
  TTL returns `400`. This stops an agent from exhausting memory or audit
  volume by spamming requests - filing a request costs it nothing but it is
  still not unbounded.
- **Approve/deny (human, `netproxy-ctl.sock`, never sandboxed).**
  `agentjail grants` lists pending entries (`grant_id`, host, ttl, cwd, reason
  - all non-secret) over the control socket. `agentjail grant approve
  <grant_id> [--persist]` / `agentjail grant deny <grant_id>` run from a
  regular, unsandboxed terminal. On approve, netproxy atomically claims the
  pending entry (a race between two approvers has one winner, the other
  no-ops), verifies the session's lease is still live (refuses otherwise),
  and resolves session -> token entirely from its own in-memory registration -
  never from the approval call's input. Only then does it add
  `granted{host, grant_id, expiry=now+ttl}` to that session's allowlist. Deny
  emits `netproxy.grant_denied` and drops the pending entry.
- **Approval is genuinely fail-closed on audit.** `grant_approved` is the
  event that actually grants authority, so it must never go through a
  `NopEmitter`. A session without a real, writable audit emitter can still
  serve best-effort `grant_requested` / `grant_expired`, but `grant.approve`
  itself is refused (`503`, "audit unavailable") rather than applying a live
  grant with no durable record. This is the opposite durability class from
  `grant_requested`: a lost request just means the human re-requests; a lost
  approval record would mean an unaudited widening of egress, which is not
  acceptable.
- **Expiry.** The existing per-session lease reaper also prunes expired
  `granted` entries and stale `pending` entries, emitting
  `netproxy.grant_expired` with `ref_id=grant_id` (best-effort, in-memory,
  same durability class as `grant_requested`).
- **`--persist` (approve-time only, human CLI writes the FS).** Because the
  approve CLI runs outside the sandbox, it can safely touch the filesystem.
  With `--persist`, it loads the session's `./.agentjail/policy.yaml` (the
  `cwd` shown in the listing) through the strict loader, merges the host into
  `network.allowed_hosts` if not already present, writes it atomically
  (temp file + rename), hashes the final bytes, and updates
  `~/.agentjail/trusted.yaml` atomically - reusing the [ADR 0043] trust gate
  rather than inventing a second one. The live grant is applied by netproxy
  regardless of persist outcome; if the persist step fails, the CLI reports
  "granted live, persist failed" rather than failing silently. `--persist` is
  never offered at request time - only at approval, by the human doing the
  approving.
- **`command_policy.rego` denies `agentjail grant approve|deny`, any
  `--persist` flag, and `agentjail trust|untrust` to agent-initiated calls;
  `agentjail allow host` is allowed.** This is explicitly defense-in-depth,
  not the hard boundary - the hard boundary is that the approval path only
  exists on `netproxy-ctl.sock`, which the agent cannot reach regardless of
  what the policy engine decides.
- **Registration carries `session_id` + `cwd`.** The shield's existing
  `session.register` call over `netproxy-ctl.sock` (pre-sandbox, per
  [ADR 0042]) is extended with a non-secret `session_id` (the Claude Code hook
  session ID, or a fresh opaque handle) and the session's `cwd`, so
  `agentjail grants` can display which repo a pending request came from and
  `--persist` knows which overlay file to write.

## Consequences

- A human can widen one session's egress in seconds from a second terminal,
  without killing the session or hand-editing `policy.yaml` mid-run.
- The sandboxed agent can file a request for its own session and nothing more
  - it cannot list other sessions' pending requests, approve its own request,
    or read the token that would let it forge control-plane calls, because the
    only socket that grants authority is proven unreachable from inside the
    sandbox on both OSes ([ADR 0042]).
- No new persistent secret state: the token was already in-memory-only before
  this ADR, and stays that way. The only new persistent state is the optional
  `--persist` write into the existing per-folder overlay + trust file
  ([ADR 0043]), gated the same way any other overlay edit is.
- `grant_approved` fail-closed on audit means a broken/locked audit DB
  degrades to "approve refused" rather than "approve succeeds unaudited" -
  consistent with the project's general fail-closed posture for anything that
  grants authority.

Known limitations / follow-ups:

- **Pending requests are in-memory.** A netproxy restart drops all pending
  requests; the agent must re-request. `grant_requested` is best-effort audit
  for the same reason - the durable, fail-closed record of authority is
  `grant_approved`, not the request.
- **macOS menubar Approve/Deny UI is a follow-up.** CLI approve
  (`agentjail grants` / `agentjail grant approve|deny`) ships first; a
  point-and-click approval surface can be layered on top of the same control
  verbs later.
- **Non-HTTP protocols are unaffected and still blocked.** This grant layer is
  HTTP CONNECT only, same as the rest of netproxy today. Postgres/Redis/SSH
  remain blocked by the OS sandbox until AGE-81 (SOCKS5, then the WireGuard
  gateway), which is transport-agnostic to this control/policy layer and will
  carry the request/approve model forward unchanged.

This is AGE-93.

See also: [ADR 0042] (session-aware netproxy control plane), [ADR 0043]
(per-folder policy overlay trust gate), AGE-81 (WireGuard gateway), AGE-93
(this feature).

[ADR 0042]: ./0042-session-aware-netproxy-control-plane.md
[ADR 0043]: ./0043-per-folder-policy-overlay-trust-gate.md
