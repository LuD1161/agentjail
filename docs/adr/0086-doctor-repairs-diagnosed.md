# ADR 0086-doctor-repairs-diagnosed: `doctor --fix` repairs only what it diagnosed

Status: Accepted

## Context

On Jul 10 the policy daemon exited cleanly and launchd never restarted it,
despite `KeepAlive=<true/>`. For three days the agent ran with no policy
enforcement. `agentjail doctor` would have said so — the socket was dead and
`checkDaemon` reports a dead socket — but doctor cannot do anything about it.
Every remedy it knows is a sentence: `checkLaunchIntegration` literally prints
`Repair: agentjail install --with-path-shim` for a human to copy-paste.

Diagnose-only is a real cost here. The window is unbounded by anything except
how long it takes a human to notice, run doctor, read the advice, and act.
ADR 0082-doctor-attests-enforcement bought detection; nothing shortened the
recovery.

The tension is that doctor's value **is** its honesty. It is the command you run
to find out whether you are protected, and the status line and CI gate on its
exit code. A `--fix` that mutates state and then reports on its own optimism
turns "you are unprotected" into "all good" — which is strictly worse than no
repair at all, because the user stops looking. Two failures the project cannot
have are a silent unprotected window and a false attestation, and a careless
repair trades the first for the second.

Two further facts shaped the design:

- **`checkDaemon` did a dial-and-close.** A bare successful `connect()` is not
  liveness: a wedged daemon still holds its socket, and so does a foreign
  process squatting on the path. `internal/daemonapp/singleton.go` already
  learned this and probes with `wire.ControlOpPing`. Gating a *restart* on a
  verdict that weak is how you either restart a healthy daemon or, worse,
  declare a wedged one healthy and never restart it.
- **Not every finding is a repair.** "The shield binary is missing" is fixed by
  fetching and verifying a binary; "the shell profile opts into a PATH shim that
  is not there" is fixed by writing a file whose content we already have.

## Decision

Add `agentjail doctor --fix`. Default behaviour is unchanged and diagnose-only.

**D1 — Repair is opt-in, and gated on a diagnosis.** `repairMode` defaults to
`diagnoseOnly`. A `doctorCheck` carries a `repairID`, and a repair runs only
when the check carrying its id returned `statusFail` in this run. There is no
path from `--fix` to a mutation that does not pass through a failed check.

**D2 — The registry is the definition of "safely repairable".** `repairRegistry`
maps `repairID` to a `repairAction{apply, recheck}`. A finding absent from the
map stays advice-only. Two entries:

| finding | repairable? | why |
|---|---|---|
| **Daemon socket** dead / wedged / absent | **yes** — ask the supervisor to restart | The AGE-212 incident. The action is idempotent, addresses exactly what the check observed, and the daemon is designed to be restarted (ADR 0070's exit-0 handoff). |
| **PATH shim** dangling (rc opts in, shim gone) | **yes** — re-run `installPathShim` | The rc block is a *recorded consent* (ADR 0062). Restoring the shim re-asserts a choice already on record; it grants nothing new. `reassertPathShim` already does exactly this on every install. |
| PATH shim never opted into | no | Installing a shim the user never consented to is not a repair; it is a decision made on their behalf. The `skip` carries no `repairID`, and `restorePathShim` re-checks consent before writing. |
| Shield binary missing | no | Repair means fetch, verify signature, place — a supply-chain action with its own trust decisions. That is `agentjail install`, and doctor must not become a second, weaker installer. |
| Hook binary / Claude Code hook absent | no | Editing another tool's `settings.json` mutates config we do not own, and its absence can be deliberate. Advice. |
| VS Code / Cursor wrapper | no | Same, and neither is a `fail`. |
| ssh-agent | no | User environment state, never a `fail` (see `sshAgentCheck`). Repair means loading a key, possibly prompting for a passphrase. Not ours to do. |
| **Protection** (enforcement gap, fail-open history, dropped decisions) | **never** | These attest what already happened. There is no state to repair — a "repair" could only edit the record. Pinned by a test. |

**D3 — The restart goes through the supervisor, never around it.** `--fix` calls
`selfupdate.RestartDaemon` (launchd `bootout` + `bootstrap` / `systemctl --user
restart`). Re-registering the launchd job also refreshes its lightweight code
requirement after an executable replacement. Doctor never spawns a daemon itself: launchd/systemd owns the
process, and a hand-spawned daemon would be unsupervised, invisible to the
supervisor, and gone at the next restart. Doctor also never unlinks a socket
something is holding — that judgement lives in `bindAgentSocket`.

**D4 — The gate is a ping, not a connect.** `probeDaemon` requires a
well-formed `ControlResponse{OK:true}` within 500 ms and classifies the socket
as `daemonHealthy` / `daemonUnresponsive` / `daemonNoListener` /
`daemonSocketAbsent`. `daemonLivenessCheck` maps that verdict to a check and is
pure, so the repair gate is tested without a daemon. This also fixes a
pre-existing diagnosis bug: a wedged daemon used to read as `ok`.

**D5 — Report the observed post-repair state, never the repair's return
value.** Every `repairAction` carries a `recheck` that re-observes real state
(for the daemon, polling the ping for up to 5 s). A repair that returns `nil`
but leaves its check failing is reported as a failure and exits 1. A repair
that errors names the error and exits 1. `--fix` exits 0 only when every
attempted repair verified **and** no unrepairable failure remains.

## Consequences

- The AGE-212 recovery is one command instead of a diagnosis followed by a
  human deciding what to type. The daemon is restarted by its own supervisor
  and doctor then proves the daemon answers a ping before saying so.
- **`--fix` cannot clear the Protection section, and must not.** After a
  successful restart, the enforcement gap is still real history, so
  `doctor --fix` will still exit 1 until enforcement demonstrably resumes and a
  decision newer than the last shield activation is recorded — which the next
  tool call does. Repair fixes state; it does not rewrite the attestation. This
  reads as "the fix worked but doctor still exits 1", and that is the correct,
  honest report of a machine that spent three days unprotected.
- Exit semantics for plain `doctor` are unchanged: the same sections gate the
  exit code as before, so nothing that reads doctor's exit code moves. Plain
  `doctor` gains one line naming how many failures `--fix` could take.
  Under `--fix`, a failed repair exits 1 even for a finding whose section does
  not normally gate the exit (the PATH shim) — you asked for a repair and did
  not get one.
- The dial-and-close → ping change makes `Daemon / Socket` stricter. A wedged
  daemon that used to report `ok` now reports `fail`. That is a correction, but
  it can surface as a new failure on a machine that looked healthy.
- `--fix` on a machine where the socket is held by an unresponsive foreign
  process will attempt a supervisor restart, the daemon will refuse to unlink
  the squatted socket (ADR 0060), and the re-check will report the still-dead
  socket and exit 1. Loud and correct; doctor resolves nothing it should not.
- Adding a repair now requires an entry in `repairRegistry`, a row in D2's
  table, and a test edit — `TestOnlyDiagnosedRepairsAreRegistered` fails on any
  registry entry that was not a deliberate decision.

Related: ADR 0082-doctor-attests-enforcement (doctor attests), ADR 0070
(supervisor restarts the daemon), ADR 0062 (PATH shim consent), ADR 0060
(single-instance guard), ADR 0050 (daemon unreachable).
