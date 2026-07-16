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

macOS is unaffected in principle, and this is now **verified by execution** rather than by
reading the generator (AGE-216; probe and evidence in `test/sbpl-probe/`). Measured on a clean
macOS 15.7.7 box against the real `agentjail-shield` binary:

- Seatbelt **does** model `AF_UNIX connect()` as `network-outbound` — confirmed, not assumed.
- A shielded agent **cannot** reach any of the three control sockets. The conclusion above
  stands.

Two corrections to what this ADR originally asserted, both found only by running it:

1. **The explicit `(deny network-outbound (literal <ctl sock>))` rules are not the boundary.**
   Deleting them entirely (with the profile still compiling) leaves the sockets denied. The
   trailing `(deny network*)` catch-all is what actually enforces, for all three. The denies
   are defence-in-depth; they become load-bearing only if some allow grows to cover a
   control-socket path.
2. **`secrets.sock` had no explicit deny at all** — the claim "the profile denies the control
   socket paths" was literally false for it; it survived on the catch-all alone. It also lives
   at `~/.agentjail/secrets.sock`, *not* under `~/.agentjail/run/` with the other two. Fixed.

The Linux/macOS asymmetry is exactly why a Linux-only assumption survived — the property held
on one platform and the comments generalised it to both. Worth noting the same failure shape
recurred *here*: the conclusion was right, the stated reason was wrong, and only execution
separated them.

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
- macOS gets the token too, on top of the sbpl profile. **Verified redundant there today**
  (AGE-216, `test/sbpl-probe/`) rather than believed redundant — but it means the boundary no
  longer depends on which platform you are on, which is the drift that made this necessary.
  Redundancy is the point: the macOS gate turned out to rest on the catch-all, and a token
  that does not care which rule enforces is the cheaper thing to reason about.

- **The code comments contradicted this ADR for as long as it has existed** (found in the
  AGE-216 review; corrected on main in `644b384`). `shield_agentpaths.go`, `shield_linux.go`
  and `shield_linux_enforce_test.go` all described `daemon-ctl.sock` as "agent-unreachable"
  because "Landlock denies `connect()` without write" — the precise claim the Context above
  refutes, sitting a few hundred lines from an assertion that logs `ctl_connect=ok` as the
  expected result and a denial as a "bonus". The ADR was right and unread. Anything that
  describes Linux as path-isolating the control plane is wrong by construction; the token is
  the boundary. `ControlSocketPaths` (`shield_contract.go`) is the shared list, and it is
  darwin-enforceable only — named there, not silently.
- **Measured; the grant stays, pending a human call.** The `~/.agentjail/daemon.sock`
  single-file write grant (`AgentPaths.HomeFilesRW`) was added believing `AF_UNIX connect()`
  needs write on the socket inode. It does not — the grant has since been A/B-measured as a
  `connect()` no-op on Landlock ABI 2 (see the addendum below), so it could be dropped. It is
  left in place deliberately: a false rationale is not by itself proof the grant is
  unnecessary, and dropping a grant is a human decision. The comments no longer assert the
  mechanism.

Related: ADR 0004 (credential broker), ADR 0048 (secrets-store read denial — the mechanism
reused here), ADR 0058 (on-demand broker), ADR 0066 (`daemon_reload` off the agent socket —
which this makes a real boundary on Linux rather than a structural one).

Review record for the macOS verification and the comment corrections above:
[`docs/reviews/age-216-item3-sbpl-control-sockets.md`](../reviews/age-216-item3-sbpl-control-sockets.md).

## Addendum: the `daemon.sock` write grant measured (AGE-216)

The "Landlock does not mediate `AF_UNIX connect()`" premise above was previously supported
only by the incidental `ctl_connect=ok` observation. It has now been measured directly, by
A/B-ing the single-file write grant on `~/.agentjail/daemon.sock` in
`AgentPaths.HomeFilesRW` (`internal/shieldapp/shield_agentpaths.go`) against
`TestLandlockAgentjailStateEnforcement`.

Host: kernel `6.1.0-44-amd64`, **Landlock ABI 2** (the ABI the "confirmed on 6.1" claim
refers to; ABI 3 lands in 6.2, the network ABI 4 in 6.7).

| arm | `sock_connect` |
|---|---|
| grant present (as-is) | `ok` |
| grant removed | `ok` |

**The grant is a no-op for `connect()`.** The premise holds on this kernel: withholding write
on the socket inode withholds nothing, so granting it grants nothing.

The result is not vacuous — three controls back it:

- **The removal is observable.** `.claude.json` is granted through the *same* `HomeFilesRW`
  loop (`shield_linux.go`, `allowPath(p, rwFileAccess)`). Removing it flips its write probe
  `ok` → `EACCES`, so removing an entry from that list demonstrably changes enforcement.
  In the decisive arm `.claude.json` stayed granted (`claudejson_write=ok`) while
  `daemon.sock` was removed — the list was live and `connect()` still succeeded.
- **The sandbox is live and denying on this exact subtree.** `policy_write=EACCES` and
  `trust_write=EACCES` in every arm.
- **The probe can report failure.** Pointed at a socket path with no listener it returns
  `ERR:...no such file or directory`, not `ok`.

Incidental finding, recorded but **not acted on**: a `HomeFilesRW` grant on a path that does
not exist at launch is silently skipped by `allowPath`. This is why the socket grant is
"skipped harmlessly if the daemon is not running" — but it also means such a grant binds only
when the inode already exists.

Consequently the grant's justifying comments in `shield_agentpaths.go` (the `HomeRO`
`.agentjail` note and the `HomeFilesRW` `daemon.sock` note) state the opposite of this ADR:
they claim "Landlock mediates AF_UNIX connect() through the filesystem hook (needs write on
the socket inode)". That is measurably false here. The same stale premise is what
`daemon-ctl.sock`'s "Linux Landlock denies connect() without write" comment asserts — and
`ctl_connect=ok` contradicts it, which is precisely the gap this ADR's token exists to close.

The grant is **left in place**; dropping it and correcting the comments is a human decision.
Note the grant is not load-bearing on macOS either (sbpl permits the connect via
allow-default network), so removal would be a Linux-and-macOS no-op — but that is untested.
