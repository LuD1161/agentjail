# sbpl control-socket probe (AGE-216 item 3)

Every macOS claim in ADR 0067 / 0068 / 0069 originally came from **reading shared code**,
never from running it. This directory is the executable answer: it drives the **real**
`agentjail-shield` binary and probes the **real** control-socket paths with a real
`AF_UNIX` client under `sandbox-exec`.

The bug this guards against (AGE-214) survived precisely because a property that held on
one platform was generalised to both in comments, with no test on either. Reading the
generator is not evidence about Seatbelt. Only execution is.

## Why this must run on an unshielded box

Inside an agentjail shielded session, `sandbox_apply` accepts only a profile that is
**semantically identical to the one the shield already applied**. Measured on the host:

| profile applied from inside a shielded session | result |
|---|---|
| the shield's own profile, byte-identical | ACCEPTED |
| same profile + a trailing comment / newline | ACCEPTED (so it is semantic, not byte-identity) |
| same profile + **one unrelated harmless deny** (`/tmp/zzz-unrelated.sock`) | `sandbox_apply: EPERM` |
| same profile, control-socket denies merely **reordered** | `sandbox_apply: EPERM` |
| `(version 1)(allow default)` - a *widening* profile | `sandbox_apply: EPERM` |

Two consequences, both easy to get wrong:

1. **You cannot probe alternative profiles from inside the shield.** Any experiment that
   varies the profile is refused before it runs. Do not read that EPERM as "the sandbox
   denied my connect" - the sandbox was never applied. And note the tempting
   generalisation "macOS refuses to nest Seatbelt, so `sandbox-exec` never works in a
   shielded session" is **false**: the identical profile applies fine. (That wrong
   generalisation was drawn, and then corrected by measurement, while writing this.)
2. **The in-repo `sandbox-exec` integration tests are environment-sensitive.**
   `TestSandboxExec_DarwinTempDirCarveOuts` passes inside a shielded session only because
   it regenerates the profile already applied to the test process. **Any** change to the
   generator - correct or not - makes it fail in-shield with `exit status 71`. That is not
   a regression signal. Verify such a change on an unshielded box (`guest-carveout.sh`
   reproduces that test's assertions there) before believing either its pass or its fail.

`test/testbed` already boots an unshielded macOS session from
`golden-macos-mitm` via Tart; the installed extension remains inert unless a
tunnel session starts it. That is the venue.

    # from an UNSHIELDED terminal on the Mac
    tart run --no-graphics tb-release-gate &
    scp guest-probe.sh guest-mutate.sh admin@$(tart ip tb-release-gate):/Users/admin/probe-kit/
    ssh admin@$(tart ip tb-release-gate) 'bash /Users/admin/probe-kit/guest-probe.sh'

`guest-carveout.sh` reproduces `TestSandboxExec_DarwinTempDirCarveOuts`'s assertions
against the generated profile on the guest - use it whenever a generator change makes that
test fail in-shield, to tell a real regression from the nesting artifact above.

The `guest-*.sh` scripts are the only probe implementation - there is deliberately no
second host-side copy. `KIT`, `PROBE_HOME` and `WORK` are overridable, so the same scripts
run directly on an unshielded Mac without a VM:

    KIT=/tmp/probe-kit PROBE_HOME="$HOME/ajprobe-run" bash guest-probe.sh

A separate host-side runner (`run-probe.sh`) existed and was deleted in the AGE-216
review: it had drifted from these scripts on both counts that matter - it looked for
`secrets.sock` under `run/` (it is not there; see `sandbox.SecretsSocketPathForHome`), so
it probed a path with no server and no rule, and its mutation step was the
`grep -v <sock>` trap described above, which silently tests nothing. A probe that has
drifted is worse than no probe: it produces confident, wrong evidence. One copy only.

Binaries copied into the guest need an ad-hoc re-sign (`codesign --force -s -`) or the
kernel SIGKILLs them; pure-Go binaries also need `-ldflags=-linkmode=external`, since
internal linking omits `LC_UUID` and dyld then refuses to exec them.

## Probe hygiene - these silently invalidate results if violated

The scripts assert all of these at runtime and abort rather than emit a false pass:

- probe `$HOME` must be **outside `/tmp`** - the shield grants `/tmp` read-write.
- **cwd must not enclose `$HOME`** - the cwd-encloses-home path is a silent pass.
- socket paths must stay **< 104 bytes** (`sockaddr_un`).

## Measured results (macOS 15.7.7, clean guest, real binary)

These are the results **as first measured**, against the generator BEFORE the AGE-216 fix.
They are kept as the evidence trail. For the state after the fix, see "After the fix" below.

| id | experiment | result |
|----|-----------|--------|
| E0 | unsandboxed connect, all 3 sockets | CONNECT_OK - later denials are not vacuous |
| E1 | `(allow default)(deny network*)` + AF_UNIX connect | **EPERM** - Seatbelt **does** model `AF_UNIX connect()` as `network-outbound` |
| E2 | same-specificity rules, same path: deny→allow / allow→deny | CONNECT_OK / DENIED - last-match-wins among same-specificity rules |
| E2c | filtered allow THEN unfiltered `(deny network*)` | **CONNECT_OK** - an unfiltered catch-all does **not** override an earlier *filtered* allow |
| E3 | real profile → netproxy-ctl / daemon-ctl / secrets.sock | all **DENIED** |
| M1/M2 | delete the explicit ctl-socket deny rules entirely (still compiles) | **STILL DENIED** - the path denies are **not load-bearing** |
| M3 | delete only `(deny network*)` | secrets.sock → **CONNECT_OK**; netproxy-ctl → DENIED. The catch-all is the real gate |
| E5 | `SSH_AUTH_SOCK=<daemon-ctl.sock>` | **CONNECT_OK** - the later allow defeats the earlier deny *and* the catch-all |

## What this proves

The ADRs' **conclusion is right**: a shielded agent cannot reach the control plane on
macOS, so the control token is redundant there today. E1 and E3 confirm it by execution.

The ADRs' **stated mechanism is wrong**. They credit the explicit
`(deny network-outbound (literal <ctl socket>))` rules. Those are dead code: M1/M2 delete
them and the sockets stay denied. The `(deny network*)` catch-all is what actually
enforces, for all three sockets - including `secrets.sock`, which has no explicit deny at
all (M3).

"sbpl uses LAST-MATCH-WINS" (asserted in several comments) is **incomplete**: it holds
among same-specificity rules (E2), but an unfiltered catch-all does not beat an earlier
filtered allow (E2c). That is *why* the network allow-list survives the trailing
`(deny network*)` rather than being dead - and it is why the file-rule carve-outs and the
network catch-all can both be correct despite looking contradictory.

E5 is the live fragility: a later `(allow network-outbound (path ...))` naming a control
socket beats everything before it. Not reachable by the agent today (`SSH_AUTH_SOCK` is
read from the *shield's* env at generation time, not the agent's), but the ordering is one
edit away from mattering.

## After the fix

Re-measured on the same clean guest with the fixed binary:

- **E5 → DENIED** (was CONNECT_OK). `SSH_AUTH_SOCK` pointed at `daemon-ctl.sock` no longer
  yields a connect. The profile now emits no `(path ...)` allow for it at all - the
  fail-closed guard suppresses it - and the deny is emitted last regardless.
- **All three sockets now carry an explicit deny**, `secrets.sock` included, at its real
  path (`~/.agentjail/secrets.sock`, *not* under `run/`).
- The `$TMPDIR` / `/tmp` carve-outs still behave as before (`guest-carveout.sh`):
  `bind_tmp=ok`, `bindconnect_tmpdir=ok`, `write_tmpdir=ok`, `write_vardb=denied`,
  `connect_tmp=denied`.

For the two `run/` sockets the explicit denies remain **not** what stops an agent today -
the catch-all still does that (M1/M2 are unchanged). They are defence-in-depth, and they
become load-bearing the moment an allow grows to cover a control-socket path, which is
exactly what `SSH_AUTH_SOCK` did. `internal/shieldapp/shield_darwin_ctlsocket_test.go`
guards the ordering in CI, where `sandbox-exec` cannot be trusted to run.

**`secrets.sock` is the exception, and it changed with the fix.** The M3 row above records
the *pre-fix* state: with the catch-all removed, `secrets.sock` was `CONNECT_OK`, because
it had no deny of its own. Re-running `guest-mutate.sh` against the fixed binary now gives
**M3 → DENIED**: the explicit `secrets.sock` deny added here stands on its own, without the
catch-all. So for that socket the defence-in-depth is no longer hypothetical - it is the
one control-socket deny that is measurably load-bearing under mutation. `guest-mutate.sh`'s
M3 step states the post-fix expectation (`DENIED`) and records the pre-fix answer as
history, so the runnable script and this table cannot disagree.

## Independent re-verification (AGE-216 review)

Everything above was re-measured from scratch on a clean `tb-release-gate` guest by a
second, unshielded session that did not trust the original numbers: E0 `CONNECT_OK`,
E1 `DENIED`, E2 last-match-wins, E2c `CONNECT_OK` (catch-all does not beat a filtered
allow), E3 all three `DENIED` with all three explicit denies present, E5 `DENIED`. M1/M2
still `DENIED`; M3 `DENIED` per the paragraph above. `TestSandboxExec_DarwinTempDirCarveOuts`
passes unshielded, where it is a valid signal.

## Mutation testing is mandatory here

A green security test that cannot fail proves nothing. The first mutation attempt in this
work deleted only the `(literal ...)` line of a two-line rule, leaving a dangling
`(deny network-outbound` → sbpl **syntax error**. `sandbox-exec` refused the profile, the
connect failed, and it *looked* like the gate held. It tested nothing.

`guest-mutate.sh` therefore deletes whole rules and **asserts the mutated profile still
COMPILES** before drawing any conclusion. Assert the side effect (the connect actually
happened), not just that the reply said no.
