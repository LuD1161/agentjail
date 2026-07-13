# ADR 0058 — Auto-start the secrets broker (on-demand, client-triggered)

- **Status:** Accepted (implemented 2026-07-11)
- **Date:** 2026-07-11
- **Deciders:** agentjail-core
- **Related:** [ADR 0023](0023-secret-server.md) (secret server), [ADR 0048](0048-secrets-broker-key-store-excluded-from-agentjail-self-read.md) (key store excluded from self-read), [ADR 0052](0052-daemon-control-plane-socket.md) (daemon control-plane socket)
- **Review:** an independent code review (Codex, against `server.go`/`secretsgrant.go`/`env.go`/
  `store.go`) raised three findings — grant-lifecycle vs idle-exit (P1), socket-unlink vs
  activation (P1), and activating status probes (P2). All three are incorporated below and
  marked `(P1/P2, review)` at the relevant points.

## Context

ADR 0023 shipped `agentjail-secrets`, the credential-vault broker: `agentjail-secrets serve`
listens on `~/.agentjail/secrets.sock` (0600), holds the AES-256-GCM master key
(`~/.agentjail/secrets.key`, 0600) in process memory, and mints scoped short-lived
credentials for `agentjail-shield` before it execs a sandboxed agent.

The binary now ships in the release tarball and installer, but **nothing starts it**.
`agentjail install` never copies `agentjail-secrets` into `~/.agentjail/bin/`, writes no
service definition for it, and starts no process. The operational result (tracked as
DEFECT-2):

- `agentjail secret set` fails fast — the CLI client `rpcClient`
  (`cmd/agentjail-secrets/server.go:289-294`) errors with
  *"Is agentjail-secrets running? Start it with: agentjail-secrets serve"*.
- `agentjail-shield`'s grant step (`requestSecretGrants`,
  `cmd/agentjail-shield/secretsgrant.go:75-79`) probes
  `sandbox.SecretsBrokerRunning()` (`internal/sandbox/env.go:249`), finds no broker,
  prints a WARNING, and starts the agent session **without** the scoped credentials —
  a silent degradation.

`agentjail-daemon` solved this exact "come up automatically" problem via launchd/systemd
auto-start (`installAndStartDaemonService`, `cmd/agentjail/install.go:1092`). The obvious
move is to mirror that for the broker. This ADR records **why we do not mirror it exactly**
— the broker's trust profile differs from the daemon's — and specifies the auto-start
model we adopt instead.

## Decision

### On-demand (socket-activated), not always-running

The daemon is a policy-enforcement process holding **no persistent secret material**, so
its plist uses `RunAtLoad=true` + `KeepAlive=true` (`plistTemplate`,
`cmd/agentjail/install.go:1378-1400`) and it is safe resident 100% of uptime.

The broker is different in kind: it holds the **decrypted** master key in process memory
(`Store.key`, `cmd/agentjail-secrets/store.go`) for as long as it runs. Every minute it is
resident is a minute a local process — or a sandbox-escape bug — has a live target to attack
over the Unix socket, versus a key file at rest that requires its own compromise to decrypt.
The actual usage pattern is bursty (a grant/set/revoke around each session start/end), not
continuous, so an always-on broker buys negligible availability for a real increase in
blast radius.

**Build constraint that rules out native socket activation.** The obvious design —
launchd/systemd *socket activation* (the service manager owns the socket, spawns the broker on
first connect, hands it the fd) — is **not implementable on macOS under this project's build**.
Retrieving a launchd-passed socket requires `launch_activate_socket()`, a C libSystem call, i.e.
**cgo**. But `agentjail-secrets` ships in the release tarball built **`CGO_ENABLED=0`**
(`Makefile:111`, `.github/workflows/release.yml:48`) — the static-binary property ADR 0023's
no-deps design deliberately bought. launchd has no `LISTEN_FDS`-style env fallback, so on macOS
the fd handoff is the C call or nothing. (Linux systemd *could* do it cgo-free via `LISTEN_FDS`,
but a split design — activation on Linux, something else on macOS — is not worth the divergence.)

**Decision: on-demand via *client-triggered start* (not socket activation), self-exiting after
an idle timeout.** The broker owns its own socket (`net.Listen`, as today); the service manager
holds only a loaded-but-not-running *definition*; and the client starts the broker on demand:

- **macOS (launchd)** — `~/Library/LaunchAgents/com.agentjail.secrets.plist`:
  - `Label` = `com.agentjail.secrets`; `RunAtLoad` = `false`; `KeepAlive` omitted; **no `Sockets`
    key**. The job is loaded (registered) but idle until kickstarted.
  - `ProgramArguments`: `[<secrets-bin>, serve, --store=…, --key=…, --idle-timeout=…]`.
  - `StandardErrorPath` = `~/.agentjail/secrets-crash.log`; broker's structured log →
    `~/.agentjail/secrets.log` (separate from the daemon's `crash.log`/`daemon.log`).
  - On-demand start: the client runs `launchctl kickstart gui/<uid>/com.agentjail.secrets`, then
    waits for the socket to appear before connecting. launchd guarantees single-instance, owns
    lifecycle + log redirection.

- **Linux (systemd --user)** — single service unit (no `.socket`):
  - `agentjail-secrets.service`: `ExecStart=<secrets-bin> serve --store=… --key=… --idle-timeout=…`,
    `Type=simple`; installed + enabled but not started at boot.
  - On-demand start: the client runs `systemctl --user start agentjail-secrets.service`, then
    waits for the socket.
  - Fallback for no-user-session hosts (mirrors the daemon's `defaultSystemdUserAvailable`
    guard, `install.go:1498`): if neither launchd nor systemd --user is reachable, the client
    directly `exec`s `agentjail-secrets serve` **detached** (`setsid`, own session) and waits for
    the socket. Single-instance is then protected by the broker's own `net.Listen` on a fixed
    path failing `EADDRINUSE` if a second one races — the loser exits.

Because the broker owns its socket again, the **P1 socket-unlink finding no longer applies**:
`os.Remove` before `net.Listen` (`server.go:109`) and on shutdown (`server.go:139`) is correct
and stays — there is no service-manager-owned socket to preserve. (Recorded here so the finding
isn't re-raised against the revised design.)

- **Idle self-exit — gated on grant state (P1, review):** the broker tracks last-activity and
  self-exits after an idle window (new `--idle-timeout` flag) so the service manager
  re-activates it on the next connection, bounding how long the decrypted master key sits in a
  live process. **But idle exit must NOT fire while any grant is active**, because ADR 0023's
  grant state is in-memory only: `GrantManager` (with each grant's `revokeFn`) lives solely in
  the server process, and revocation happens later — either on shutdown via `gm.RevokeAll()`
  (`server.go:135-139`) or when the shield calls back (`secretsgrant.go:120-136`). An idle exit
  in the middle of a longer-than-idle-window agent session has two failure modes, both of which
  weaken ADR 0023:
  - if it calls `RevokeAll()` on the way out, it tears down live PG/Redis credentials out from
    under a still-running session;
  - if it exits *without* revoking, the `revokeFn` closures are lost — the re-activated broker
    has no way to revoke those grants (PG `DROP ROLE` / Redis `ACL DELUSER` never happen), so
    scoped credentials outlive their session, silently.

  Therefore the idle-exit predicate is **"idle AND `GrantManager` has zero active grants"**, not
  a bare timer. Any design that wants to reclaim the key while grants are outstanding must first
  make grant state **durable and reconstructable across a restart** (persist grant id + backend +
  revoke parameters, reload on activation) — a larger change than a timer, and out of scope for
  the minimal v1 unless we accept "no idle exit while grants are active." Default idle strawman
  10-15 min — see Open question 2.

### Broker + client code changes (all pure-Go, no cgo)

1. **Broker (`runServer`):** add `--idle-timeout` (duration, default 0 = never, opt-in). When
   non-zero, an idle watchdog fires only when **both** the last-activity age exceeds the window
   **and** `GrantManager` reports zero active grants (§ idle-exit gate above); it then shuts down
   the same way as a SIGTERM (`gm.RevokeAll()` is a no-op with zero grants, `ln.Close`,
   `os.Remove` the broker-owned socket). `net.Listen` and both `os.Remove`s stay exactly as
   today — the broker owns its socket in this design.
2. **Client (`rpcClient`, `server.go:289`):** on connect-refused (`ECONNREFUSED` / no socket),
   instead of failing fast, call a new `ensureBrokerRunning()` that: (a) tries
   `launchctl kickstart gui/<uid>/com.agentjail.secrets` (macOS) / `systemctl --user start
   agentjail-secrets.service` (Linux); (b) if the service manager is unreachable, `exec`s the
   broker detached (`setsid`); (c) polls for the socket with a short bounded deadline; then
   retries the connect once. Preserves the existing clear error if start fails.
3. **Shield grant path (`secretsgrant.go`):** `requestSecretGrants` already probes
   `SecretsBrokerRunning()` and soft-warns; route its "not running" branch through the same
   `ensureBrokerRunning()` so a session start reliably brings the broker up (Open question 3
   decides warn-vs-hard-fail on failure).

Why client-triggered start rather than the service manager restarting the broker: without
socket activation (ruled out by the cgo constraint), nothing in launchd/systemd re-spawns a
self-exited broker on the next *connection* — a plain non-`KeepAlive` job stays dead until
something explicitly starts it. The client is that something. This is not the rejected "punch a
hole" shortcut; it's the cgo-free equivalent of on-demand, with the broker (not the service
manager) owning the socket.

### Installer / status wiring (`cmd/agentjail/install.go`)

Mirroring the daemon's install/uninstall/status paths, kept independently fail-soft so a
broker failure never blocks daemon install:

- Copy `agentjail-secrets` into `~/.agentjail/bin/` (new `installSecretsPreamble`, sibling to
  `installDaemonPreamble`, `install.go:1015`).
- `installSecretsPlist` / `installSecretsSystemdUnit` parallel to `installPlist`
  (`install.go:1404`) / `installSystemdUnit` (`install.go:1482`), emitting the
  **loaded-but-not-running** shape above (launchd `RunAtLoad=false`/no `KeepAlive`/no `Sockets`;
  systemd plain `Type=simple` service, enabled not started). Loading registers the definition so
  the client can later `kickstart`/`start` it.
- `performFullUninstall` (`install.go:570`, step 2) also tears down the broker service
  definition — `launchctl unload` + remove plist / `systemctl --user disable --now` +
  remove unit — parallel to `uninstallLaunchdDaemon` (`install.go:755`) /
  `uninstallSystemdDaemon` (`install.go:785`).
- `printStatusOutput` (`install.go:885`) gains a "secrets broker" row reporting
  **service-definition presence + socket registration**, *not* forcing a start. With socket
  activation gone the P2 hazard is *reduced* — a dial can no longer auto-spawn the broker (there
  is no activation) — but status should still be **non-activating**: report the plist/unit
  presence and `stat` the socket path (listening = broker currently up; absent = dormant, which
  is normal), and **not** call `launchctl kickstart` / `systemctl start` / the client's
  `ensureBrokerRunning()`. A read-only `SecretsBrokerRunning()` dial (`env.go:249-255`) is now
  safe (it can't start anything) but a bare `stat` is cheaper and conveys the same "up vs
  dormant" without a connect.

## Consequences

**Positive:**

- DEFECT-2 closed: `agentjail secret set` and shield's grant step both find a broker after a
  normal `agentjail install`, with no manual `serve`.
- **Smaller decrypted-key residency window than an always-on daemon would create** — the key
  is in memory only during request bursts and is evicted on idle self-exit.
- Note: the small socket-permission TOCTOU in the manual path (`serve` creates the socket, then
  chmods 0600 a few lines later, `server.go:111-118`) is **not** closed by this design — the
  broker still owns and creates its own socket. It is unchanged from today (the socket lives in
  `~/.agentjail`, dir 0700, so the window is low-risk) and could be tightened separately by
  binding under a 0700 dir + rename, independent of auto-start. Flagged so the earlier
  socket-activation draft's "closes TOCTOU" claim isn't assumed to still hold.

**Security review against ADR 0023 + 0048 — no constraint weakened:**

- *ADR 0023, socket 0600 / user-only connect:* enforced by the OS before the process exists
  (tighter than today, per the TOCTOU note above).
- *ADR 0023, master key file perms:* a storage-at-rest property, unchanged — auto-start does
  not change who can read `secrets.key`.
- *ADR 0023, "decrypted key lives in a running process":* this is the exposure auto-start
  affects; on-demand + idle-exit keeps that window *smaller* than an always-on service, which
  is the core reason on-demand is chosen over `KeepAlive`. **This claim only holds with the two
  review-driven guards above:** idle-exit gated on zero active grants (else it corrupts ADR
  0023's grant lifecycle, §3 P1) and a non-activating `agentjail status` probe (else a status
  check re-spawns the broker and reloads the key, §3 P2). Without both, auto-start would
  *weaken* ADR 0023, not preserve it.
- *ADR 0048, hook + Landlock deny Read on `secrets.key`/`secrets/**`:* orthogonal — those
  govern the sandboxed agent's filesystem reads, not broker startup. **The new service files
  (`com.agentjail.secrets.plist`, `agentjail-secrets.socket`/`.service`) must NOT live under
  `~/.agentjail/secrets/` nor be named `secrets.key`** — they are service definitions, not
  secret material.
- *ADR 0048, `AgentjailSecretsProtectedNames()`:* the only new file under `~/.agentjail/` is
  `secrets.log`; it must log **names / grant-ids only, never values** (as `server.go`'s
  `slog` sites already do), so it is safe to leave outside the protected-names set. Any
  future secrets-adjacent file that is not `secrets.key`/`secrets/*` must be explicitly added
  to that set — the exclusion is name-based, not content-aware.

**Negative / new surface:**

- The broker can now be started by any client on the machine (kickstart / detached exec), not
  only by a human typing `serve` — but this is the same trust boundary as today (any local
  process as the user could already run `serve`), and the key is resident only from first
  client use until idle-exit, so the residency envelope is unchanged from the manual path.
- A tamperable service-definition file (plist/unit) whose `ProgramArguments`/`ExecStart`
  could be repointed at an attacker binary — the same risk the daemon plist already carries,
  mitigated the same way: it lives under the user's own `~/Library/LaunchAgents` /
  `~/.config/systemd/user` (not root-writable) and is fully owned/rewritten by
  `agentjail install`/`uninstall`.
- Cold-start latency on the first `agentjail secret set` after an idle eviction — the
  idle-timeout value trades this against key-residency (Open question 2).

## Open questions (resolve before / during implementation)

1. **~~fd-handoff scope~~ (resolved → client-triggered).** Superseded: native socket activation
   is ruled out on macOS by `CGO_ENABLED=0` (`launch_activate_socket` is cgo). v1 uses
   client-triggered start (`launchctl kickstart` / `systemctl --user start` / detached-exec
   fallback); the broker keeps `net.Listen` and both `os.Remove`s (it owns its socket), so the
   P1 unlink concern does not arise. See Decision.
2. **Idle-timeout value & grant-gating** — 10-15 min is a strawman; product call balancing
   cold-start UX against decrypted-key residency. Confirm the v1 stance: **"no idle exit while
   `GrantManager` has active grants"** (simple, correct) vs. investing in durable/reconstructable
   grant state so the key can be reclaimed mid-session (§3 P1). The former is recommended for v1.
3. **Shield fallback semantics** — once auto-start is installed, should
   `secretsgrant.go`'s missing-broker WARNING become a hard error, or keep the soft-fail for
   machines where the service definition failed to install?
4. **Uninstall + stored secrets** — `agentjail uninstall` already deletes the whole
   `~/.agentjail` tree (`os.RemoveAll(installDir)`, `install.go:613`), silently removing all
   stored secrets. Now that the broker is first-class, add an explicit warning line to
   `printUninstallSummary` (`install.go:809`) and/or a `--keep-secrets` flag?
5. **Migration** — users running `agentjail-secrets serve` manually (or via a personal
   launchd/cron entry) need an upgrade note so two listeners don't race for the same socket.
6. **Windows / other platforms** — out of scope (daemon auto-start is macOS/Linux only);
   confirm no install path silently no-ops the broker in a surprising new way.

## Implementation checklist (mechanical once this ADR is Accepted)

1. `cmd/agentjail-secrets/server.go` — add `--idle-timeout` (default 0 = never). When >0, an
   idle watchdog shuts the broker down **only when idle AND `GrantManager` has zero active
   grants** (§3 P1) — not a bare timer. `net.Listen` + both `os.Remove`s stay as-is (broker owns
   its socket).
2. `cmd/agentjail-secrets/server.go` — add `ensureBrokerRunning()` + wire it into `rpcClient`
   (`:289`) on connect-refused: `launchctl kickstart` (darwin) / `systemctl --user start`
   (linux) / detached `setsid` exec fallback, then poll for the socket and retry connect once.
3. `cmd/agentjail-shield/secretsgrant.go` — route the "broker not running" branch through
   `ensureBrokerRunning()` (Open question 3 = warn vs hard-fail on failure).
4. `cmd/agentjail-secrets/server.go` — route logging to `~/.agentjail/secrets.log`; audit all
   `slog` sites for names/grant-ids only, never values.
5. `cmd/agentjail/install.go` — add `secretsBinaryName`, `secretsPlistLabel`/filename,
   `secretsSystemdServiceFilename` constants (near `install.go:69-83`).
6. `cmd/agentjail/install.go` — `secretsPlistTemplate` (`RunAtLoad=false`, no `KeepAlive`, no
   `Sockets`) + `installSecretsPlist`; `secretsSystemdServiceTemplate` (plain `Type=simple`,
   enabled-not-started) + `installSecretsSystemdUnit`.
7. `cmd/agentjail/install.go` — `installSecretsPreamble` (copy binary + install/load the
   loaded-but-not-running service), called after `installDaemonPreamble`, independently fail-soft.
8. `cmd/agentjail/install.go` — extend `performFullUninstall` step 2 to tear down the broker
   service; warn about stored-secret deletion in `printUninstallSummary`.
9. `cmd/agentjail/install.go` — add "secrets broker" row to `printStatusOutput` using
   service-definition presence + `stat` of the socket (up vs dormant); **must not** start the
   broker (§3 P2).
10. `cmd/agentjail/install_test.go` / `install_linux_test.go` + `cmd/agentjail-secrets/*_test.go`
    — coverage mirroring the daemon install/uninstall tests, stubbing `launchctl`/`systemctl`;
    plus a broker idle-exit-gate unit test and an `ensureBrokerRunning` fake-launcher test.
11. Mark this ADR **Accepted** and record the outcome.

## Implementation outcome (2026-07-11)

Landed on `e2e-vm`:
- `internal/sandbox/env.go` — `EnsureSecretsBroker` (client-triggered start:
  `launchctl kickstart` / `systemctl --user start` / detached-`setsid` fallback,
  bounded socket poll) + shared `SecretsBrokerLaunchdLabel` / `SecretsBrokerSystemdUnit`
  constants; `SecretsBrokerRunning` refactored onto `brokerReachable`.
- `cmd/agentjail-secrets/server.go` — `--idle-timeout` flag + `idleClock` +
  `idleWatchdog` gated on **idle AND `gm.Active()==0`**; broker keeps its own
  `net.Listen`/`os.Remove` (owns its socket); `rpcClient` auto-starts on
  connect-refused.
- `cmd/agentjail-shield/secretsgrant.go` — grant path routes the not-running
  branch through `EnsureSecretsBroker` (warn only if start genuinely fails).
- `cmd/agentjail/install.go` — loaded-but-not-running launchd plist
  (`RunAtLoad=false`, no `KeepAlive`/`Sockets`) + systemd `Type=simple` unit
  (no `Restart=`); `installSecretsBrokerService` (fail-soft, after the daemon),
  `uninstallSecretsBroker` teardown, non-activating `status` row (stat socket,
  never start).
- Tests: idle-exit gate (3, incl. the P1 held-off-while-grants-active guard) +
  `EnsureSecretsBroker` fast-path. `go build ./...` + `go vet` clean.

**Follow-ups landed (2026-07-11, same branch):**
- Structured `secrets.log` sink (checklist #4) — broker `--log` flag routes slog
  JSON to `~/.agentjail/secrets.log` (default); stderr still → `secrets-crash.log`
  for panics. slog sites audited: names/grant-ids only, never values. Plist/unit
  pass `--log` explicitly.
- `--keep-secrets` (OQ4) — `agentjail uninstall --keep-secrets` preserves the
  encrypted store + master key via `removeInstallDir` (removes every other
  `~/.agentjail` entry); the uninstall summary now always states the stored
  secrets' fate (deleted vs kept) so a destructive delete is never silent.
- Migration note (OQ5) — install warns if a broker socket already exists (a
  hand-started `serve`) so two listeners don't race for the socket.
- Install-side stub tests (checklist #10) — plist/unit content, def-presence,
  systemd teardown, and keep-secrets preservation (`install_secrets_test.go`).
- Papercut fix (adjacent): `agentjail install` now also refreshes the shield +
  netproxy binaries (`refreshAuxiliaryBinaries`, temp+rename so replacing the
  live shield is safe) — previously install refreshed only hook+daemon, leaving
  a stale shield until a manual `cp`.

Functional end-to-end (real broker init) verifies on the `make e2e-release`
clean-VM gate (GATE GREEN, 15/15) — it cannot run inside the shield (denies
`~/.agentjail` writes + `*.key` reads).
