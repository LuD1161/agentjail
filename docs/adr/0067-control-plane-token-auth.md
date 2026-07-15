# ADR 0067: control-plane sockets authenticate with a read-denied token

**Status:** Accepted

## Context

agentjail binds four Unix sockets. One is agent-facing by design; three are control plane:

| socket | binary | purpose |
|---|---|---|
| `daemon.sock` | daemon | policy eval + agent-originated grant requests — **agent-reachable by design** |
| `daemon-ctl.sock` | daemon | `grant_list` / `grant_approve` / `grant_deny`, `daemon_reload` |
| `netproxy-ctl.sock` | netproxy | per-session network allowlist registration |
| `secrets.sock` | secrets broker | `set` / `list` / `delete` / `grant` / `revoke` |

The three control sockets relied on **path separation** for isolation: they sit outside the
agent's Landlock allowlist, so the agent was assumed unable to reach them. `daemon-ctl.sock`
additionally checked `SO_PEERCRED` for `peerUID == daemonUID`.

Neither property does what was assumed:

- **Landlock is a filesystem LSM and does not mediate `AF_UNIX connect()`.** Withholding a
  write grant on a socket inode withholds nothing. The shield's own enforcement test has
  recorded this as a known limitation for some time — it observes `ctl_connect=ok` and notes
  "grant-socket isolation needs Tier 2+". Confirmed on kernel 6.1.
- **`SO_PEERCRED` is identity, not authorization.** The agent runs as the same UID as the
  daemon, so a UID-equality check passes. It proves "same Unix user", never "outside the
  sandbox".

macOS is unaffected in principle: the sbpl profile denies `network-outbound` to the control
socket paths, and Seatbelt does model `AF_UNIX connect()` as network-outbound. That asymmetry
is exactly why a Linux-only assumption survived — the property held on one platform and the
comments generalised it to both.

The consequence on Linux is that path separation alone is not a boundary for any control
verb, including the broker's `grant`, which returns credential material. `policy.yaml` decides
which grants a session receives and the shield requests them from outside the sandbox, but the
broker itself never checked who was asking.

Landlock **does** mediate file reads — `AgentjailSecretsProtectedNames` already withholds
`secrets.key` and `secrets/` from the agent, and `TestLandlockAgentjailSecretsExcluded` proves
it. That asymmetry (connect: unmediated; read: mediated) is the lever.

## Decision

Control-plane callers authenticate with a shared token that the sandbox cannot read.

- `internal/ctlauth` owns the token: 32 random bytes, hex, at `~/.agentjail/control.token`,
  mode 0600. Created with `O_EXCL` so concurrent starters converge on one value rather than
  clobbering each other and invalidating live clients. Comparison is constant-time.
- The token file is listed in `shieldapp.AgentjailReadDeniedNames`, so `shield_linux.go` skips
  it when enumerating read grants for `~/.agentjail`. **That exclusion is the entire
  boundary** — a token the agent can read is not a token. macOS already denies reads across
  the subtree.
- Every control verb requires it. Servers `Ensure()` at startup; clients `Load()`.
- **The secrets broker fails closed**: it refuses to serve if it cannot establish a token,
  since serving credentials to an unauthenticated caller is the thing this prevents.
- `AgentjailReadDeniedNames` is deliberately separate from `AgentjailSecretsProtectedNames`:
  the latter is mirrored by uninstall's `--keep-secrets` preserve list (ADR 0048), and the
  token must *not* be preserved — it is disposable, regenerated on next start.

**The shield must capture the token before `applyLandlock`.** On Linux, Landlock restricts the
shield process itself, so once the sandbox is up the shield can no longer read the token it
needs to request the session's grants. It loads the value early and holds it in memory, passing
it to `requestSecretGrants` / `revokeSecretGrants`. On macOS the profile applies at
`syscall.Exec`, so the shield is still unsandboxed at that point; the parameter is threaded the
same way for a single code path.

The token authenticates "I am a process outside the sandbox" — precisely the property the
control plane needs, and the only one available given the two facts above.

## Consequences

Reaching a control socket is no longer sufficient to use it. An agent that can `connect()` but
cannot `read()` cannot produce the token, so `grant`, `grant_approve`, `register`, and
`daemon_reload` are closed to it on Linux by the same mechanism that already protects the
master key. This also closes the long-standing grant-socket isolation gap that was previously
scoped to "needs Tier 2+".

`SO_PEERCRED` stays on `daemon-ctl.sock` as defence-in-depth against a different-UID peer —
all it can honestly do.

Rollout is per socket: `secrets.sock` here, `netproxy-ctl.sock` in
[ADR 0068](./0068-netproxy-control-token.md) (which names `fingerprint` as the one deliberate
exception), `daemon-ctl.sock` in [ADR 0069](./0069-daemon-control-token.md).

Costs and residuals:

- A stale `control.token` from a previous install is adopted rather than replaced (`O_EXCL`),
  by design — remaking it would break live clients. Uninstall removes it with `~/.agentjail`.
- The token is a bearer credential in memory for the life of a shielded session. Anything that
  can read the shield's memory has already lost.
- **SIGHUP still triggers a reload** and Landlock does not mediate signals, so reload remains
  reachable by a same-UID agent. It is serialized by the signal loop, so it offers no
  amplification, and it is the documented admin interface. Not addressed here.
- Fail-open on daemon-unreachable (`DaemonUnreachable: Allow`) is unchanged.
- macOS gets the token too, on top of the sbpl deny. Redundant there today, but it means the
  boundary no longer depends on which platform you are on — the drift that made this necessary.

Related: ADR 0004 (credential broker), ADR 0048 (secrets-store read denial — the mechanism
reused here), ADR 0058 (on-demand broker), ADR 0066 (`daemon_reload` off the agent socket —
which this makes a real boundary on Linux rather than a structural one).
