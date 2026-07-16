# ADR 0088-deployed-supervisor-verified: verify the deployed supervisor definition, not the template

Status: Accepted

## Context

`agentjail update` swaps the binaries and then calls `osExitFn(0)`
(`internal/daemonapp/updatechecker.go:276`), handing the daemon back to its
supervisor to restart — the exit-0 handoff of ADR 0070.

Installs before commit `6a41303` have `Restart=on-failure` in the deployed
systemd unit. systemd does not restart a clean `exit(0)` under that policy, so
the daemon dies permanently and the machine runs unprotected until a human
notices. `6a41303` corrected `systemdUnitTemplate`, but the template is only
read by `installSystemdUnit`, whose sole non-test caller is
`cmd/agentjail/install.go:1551` inside install. **`agentjail update` never
rewrote the unit.** The fix therefore reached new installs only; every existing
Linux install still self-destructs on its next auto-update. That is the live
bug (AGE-233).

Nothing read the deployed file back. `TestInstallSystemdUnitContent`
(`install_linux_test.go:69`) asserts what the installer *would* write — it
passed throughout, on machines whose unit on disk said `on-failure`. A test of
the template cannot fail for a stale deployment, which is precisely why this
survived a fix.

The same blindness is why AGE-212 could not be diagnosed: launchd
`KeepAlive=<true/>` should restart unconditionally, so either the deployed plist
did not say that or launchd was not honouring it — and nobody could tell,
because the deployed plist was never read.

Three design tensions shaped the decision:

- **Content equality would clobber documented customization.** The comment above
  `plistTemplate` (`install.go:1793-1800`) explicitly invites users to add an
  `EnvironmentVariables` block to the plist. A byte-comparison against the
  template flags every user who followed that advice, and a repair that rewrites
  from the template silently reverts their opt-out.
- **A version stamp needs new state** written by the installer, which no
  existing install has — so it cannot classify the machines that have the bug,
  which are exactly the ones that never re-ran install.
- **Doctor's value is its honesty** (ADR 0086-doctor-repairs-diagnosed). A
  check that flags healthy machines trains users to ignore it.

## Decision

**D1 — The check is one invariant, over the deployed bytes.**
`restartsOnCleanExit(goos, content)` answers only: *will this definition restart
the daemon after `exit(0)`?* — the property ADR 0070's handoff depends on and
the one with shipped failure evidence. It parses the file on disk, never the
template. It is pure, so the gate is tested with no supervisor.

| platform | passes | fails |
|---|---|---|
| Linux | `Restart=always` (last directive wins, matching systemd) | `on-failure`, `on-success`, absent, commented out |
| macOS | `KeepAlive` `<true/>` | `KeepAlive` `<dict>` (`SuccessfulExit=false` suppresses exactly the exit-0 restart), absent |

Deliberately **not** content equality. An invariant check flags exactly the
broken machines: a user who adds `EnvironmentVariables` keeps `KeepAlive`, so
their check passes, no repair runs, and nothing is clobbered. Arbitrary template
drift is not detected — that is the accepted cost of never firing on a healthy
machine, and no drift other than the restart policy has ever broken a user.

**D2 — One contract, both platforms.** `serviceSpec` / `daemonServiceSpec(home)`
is the single source for *where the definition lives and what it should
contain*, per-OS content behind one OS-agnostic shape (ADR 0034). The installer,
doctor, and update all derive from it; `renderServiceTemplate` is the one
placeholder-patcher. Every path is fixed under `~/.agentjail`, so the spec is
reconstructible from `home` alone with no recorded state — that is what lets a
later `update` or `doctor` classify an install it did not perform.
`TestSpecMatchesWhatTheInstallerWrites` pins the two derivations together.

**D3 — Both reach the affected population, sharing one function.**
`ensureDaemonRestartPolicy(home)` rewrites only when the invariant fails, and
reports whether it did.

- **`update` calls it before relying on the handoff** (step 8c). Update is the
  command that *triggers* the bug, so it must not hand the daemon to a
  supervisor that will not catch it. This is the path that reaches existing
  installs.
- **`doctor` registers `repairServiceDef`** in `repairRegistry`, gated on
  `serviceRestartPolicyCheck` failing, per ADR 0086's D1. This reaches users who
  do not update.

`repairServiceDef` is a third entry in a registry whose membership ADR 0086's D2
table defines. That table is not amended here; this row extends it:

| finding | repairable? | why |
|---|---|---|
| **Supervisor definition** deployed but will not restart after `exit(0)` | **yes** — rewrite from the current template, then reload | The AGE-233 bug. Idempotent, addresses exactly what the check observed, and fires only on a definition that is already broken — a definition satisfying the invariant is never touched, so consented customization survives. |
| Supervisor definition absent | no | No supervisor at all is `agentjail install`, not a repair (D4). |

**D4 — A missing definition is not a repair.** Absent means no supervisor at
all; writing a unit for an install that may not exist is `agentjail install`'s
job, not doctor's — the same line ADR 0086 drew for the shield binary, and the
same shape as `pathShimCheck` (dangling repairs, absent advises). The check
fails with advice and carries no `repairID`.

**D5 — The rewrite is followed by a supervisor reload, and it is load-bearing.**
Without it systemd keeps the stale unit in memory and the daemon still strands
on the next `exit(0)`. Named per-OS difference (ADR 0034): launchd has no
reload-in-place, so `launchctlLoad`'s unload+load restarts the daemon, where
systemd's `daemon-reload` does not. In `update` on darwin the reload is skipped
deliberately — step 6 already unloaded the plist and step 9's load reads the
rewrite; loading it twice would fail and trigger the rollback path.

**D6 — launchd does not truncate crash.log; the comment claiming it does was
wrong.** Verified in launchd's source: `job_start_child` opens both paths with
`O_WRONLY|O_CREAT|O_APPEND` (`launchd src/core.c:5189-5190`,
apple-oss-distributions/launchd). There is no `O_TRUNC` and no plist key
controlling it. **There is no drift to fix** — launchd appends, matching
systemd's `append:`, so both platforms retain crash history across a crash loop.
The comment at `install.go:1812-1816` is corrected to state the verified
behaviour and cite its source. Consequently AGE-212's "crash.log is empty,
therefore it exited cleanly" reasoning is **not** undermined by truncation: 18
restarts would have appended 18 times, so an empty crash.log means the daemon
genuinely wrote nothing to stdout/stderr — which is what a clean `exit(0)` looks
like, and is consistent with the ADR 0070 handoff being the root cause.

## Consequences

- The AGE-233 population is repaired on their next `agentjail update` — the same
  command that would otherwise have stranded them — and on `doctor --fix` for
  everyone else. Neither requires re-running install.
- **`doctor` gains a failing check on every affected machine**, in the `Daemon`
  section, which gates the exit code. Machines that looked healthy will now
  correctly report a failure and exit 1 until repaired. That is a correction, not
  a regression, but it will surface as new noise on stale installs.
- The invariant check does not detect template drift outside the restart policy.
  A future change to `ExecStart` or the log paths will still only reach existing
  installs via `agentjail install`. Accepted per D1; if such a drift ever bites,
  this ADR is the place to reverse the trade.
- A hand-edited definition that *violates* the invariant is rewritten wholesale
  and the edit is lost. Only a user who deliberately disabled restart is
  affected, and that is the state the daemon cannot be left in.
- `ensureDaemonRestartPolicy` is idempotent and never creates a definition, so
  update on a machine with no agentjail service does nothing.
- Adding the repair required the `repairRegistry` entry, the D3 table row above,
  and the `TestOnlyDiagnosedRepairsAreRegistered` edit — ADR 0086's pin held.
  The registry's definition is now split across two ADRs; a third repair should
  consolidate the table back into 0086.

Related: ADR 0070 (supervisor restarts the daemon on clean exit), ADR
0086-doctor-repairs-diagnosed (repair only what was diagnosed), ADR 0034
(platform backends share one contract), ADR 0082-doctor-attests-enforcement.
