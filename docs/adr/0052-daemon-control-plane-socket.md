# ADR 0052 — Daemon control-plane socket for policy reload

- **Status:** Accepted
- **Related:** [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) §"Config overlay
  (ADR 0012)", [ADR 0047](0047-daemon-grant-server.md) (grant control socket)

## Context

Policy mutations (`agentjail mcp allow/block`, `agentjail policy
disable/enable`) write the change to `~/.agentjail/policy.yaml` via
`internal/policyctl`, then call `sighupDaemonFn()` to make the running
daemon pick it up without a restart. Until now that meant:

1. `findDaemonPID()` shells out to `pgrep -f agentjail-daemon` to find a PID.
2. `sighupDaemon()` sends `SIGHUP` to that PID.
3. The daemon's signal handler reloads `policy.yaml` and the Rego rule
   bundle, rebuilding the OPA engine.

This has three problems:

- **`pgrep -f` is a substring match.** Any process whose command line
  happens to contain the string `agentjail-daemon` — a shell history
  search, an editor with the file open, a completely unrelated script that
  mentions the name — can be matched instead of (or in addition to) the real
  daemon.
- **PID reuse is a TOCTOU window.** Between `pgrep` returning a PID and
  `proc.Signal` being called, the daemon could have exited and the OS
  reused that PID for an unrelated process. `SIGHUP`'s default disposition
  for a process that doesn't install a handler is *terminate* — so in the
  worst case this signals an innocent process to death instead of reloading
  policy.
- **No acknowledgement.** `SIGHUP` is fire-and-forget. If the daemon's
  reload fails (a corrupted `policy.yaml`, a broken custom `.rego` file),
  the daemon correctly keeps serving the *old* policy — but the CLI has no
  way to know that happened. The user sees "allowed: X" from the CLI while
  the daemon silently continues enforcing the pre-change policy. The gap is
  invisible until the next `agentjail policy list` or an unexpected
  deny/allow surprises them.

## Decision

Add a control-plane message on the daemon's existing agent-reachable Unix
socket (`~/.agentjail/daemon.sock`), and make policy-mutation commands use
it instead of `SIGHUP` as the primary reload path.

- **Wire shape** (`internal/wire`): `ControlRequest{Type: "control", Op:
  "reload"}` / `ControlResponse{OK bool, Error string}`. `handleConn`
  probes the `Type` field before decoding the rest of the request (same
  pattern already used for `grant_request`) and dispatches
  `wire.ControlOpReload` to a new `(*server).reloadPolicy(ctx) error`
  method.
- **`reloadPolicy` is the single implementation** shared by both delivery
  paths. The `SIGHUP` handler in `main.go`'s signal loop and the control
  dispatch in `handleConn` both call it; the inline reload body that used to
  live in the `SIGHUP` case was extracted verbatim into this method so
  behavior does not change, only how it's triggered.
- **Never-fail-open contract preserved exactly.** `reloadPolicy` returns a
  non-nil error on any failure (Rego module load, `policy.yaml` load, OPA
  compile) *before* mutating any daemon state; `policyeval.Evaluator.Reload`
  already keeps serving the old engine on a compile error. Both `SIGHUP` and
  the control path log the failure and leave the old policy in effect —
  this ADR only changes how the *caller* learns about that outcome.
- **The CLI (`cmd/agentjail/policy.go`, `sighupDaemon`) tries the control
  socket first.** It dials `wire.DefaultSocketPath()` with a short timeout
  (200 ms), sends the reload request, and reads back the response. If
  `OK == false`, it prints the daemon's error to stderr — this is the
  concrete fix for the silent-failure gap above. If the dial fails (daemon
  not running, or an older daemon binary that doesn't understand the
  control op), it falls back to the existing `pgrep -f agentjail-daemon` +
  `SIGHUP` path unchanged, under the renamed `sighupDaemonViaSignal`.
- **`SIGHUP` is retained as the fallback, not removed.** It's the only
  reload mechanism available when the daemon socket can't be reached (e.g.
  a stale/missing socket file after a crash, before the daemon is fully
  back up), and it costs nothing to keep now that it's no longer the
  primary path exercising `pgrep`'s substring-match risk on every mutation.
  `pgrep` is deliberately **not** hardened (e.g. matching on an exact
  binary path or a PID file) in this change — it's being retired from the
  hot path, not invested in further. A future ADR can revisit or remove it
  if the fallback is ever exercised in practice and needs to be more
  precise.
- **Trust boundary: same as `SIGHUP`.** `daemon.sock` is created with `0600`
  permissions in a `0700` directory (`~/.agentjail/`), so only the owning
  user's processes can connect to it at all — the same "same UID" trust
  `SIGHUP` already relied on (`os.FindProcess` + `Signal` only works within
  the same user's process tree without additional privilege). No new
  attack surface is introduced by adding this message type to a socket that
  already accepts policy-eval and grant-request traffic from any
  same-UID process. As defense-in-depth, `handleConn` additionally verifies
  the connecting peer's real UID via `SO_PEERCRED` (Linux) /
  `LOCAL_PEERCRED` (macOS) — reusing the `extractPeerUID`/`peerUIDAllowed`
  helpers already used to gate the privileged grant-control socket
  (`daemon-ctl.sock`, ADR 0047) — before honoring a `reload` op, and rejects
  with `{"ok":false,"error":"unauthorized"}` otherwise. This matters
  specifically for the Linux Landlock shield configuration
  (`docs/ARCHITECTURE.md` §"OS-native Sandbox"), where a sandboxed agent is
  granted a single-file write to `daemon.sock` so its hook can `connect()`
  it, but must not be able to trigger a policy reload through that grant.

## Consequences

**Positive:**

- Policy-mutation commands (`mcp allow/block`, `policy enable/disable`) now
  report the true outcome of the reload, not just "the file was saved."
- Eliminates `pgrep -f`'s substring-match misidentification and the
  PID-reuse TOCTOU window as the *primary* reload path; both risks remain
  possible only in the increasingly rare fallback case (daemon socket
  unreachable).
- No new dependency, no new socket, no new trust boundary — reuses
  `daemon.sock` and the peer-cred helpers already built for the grant
  server.

**Negative / accepted trade-offs:**

- Two reload code paths (`SIGHUP` signal, control message) both remain live
  indefinitely; `reloadPolicy` being the single shared implementation is
  the mitigation, but signal-handling test coverage and control-socket test
  coverage both need to keep passing.
- `pgrep`-based process discovery is retained, unhardened, purely as a
  fallback — it is a known-weaker mechanism kept for availability, not
  correctness. Anyone relying on the fallback path in an adversarial
  environment should be aware `SIGHUP` delivery is still same-UID-based
  process signaling, not cryptographically authenticated.
- The 200 ms dial/round-trip timeout on the CLI side is a judgment call: long
  enough for a warm daemon to answer, short enough that a genuinely-down
  daemon doesn't make every policy-mutation command feel slow before
  falling back to `SIGHUP`.
