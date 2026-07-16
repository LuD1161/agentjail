# sbpl control-socket probe (AGE-216 item 3)

Every macOS claim in ADR 0067 / 0068 / 0069 originally came from **reading shared code**,
never from running it. This directory is the executable answer: it drives the **real**
`agentjail-shield` binary and probes the **real** control-socket paths with a real
`AF_UNIX` client under `sandbox-exec`.

The bug this guards against (AGE-214) survived precisely because a property that held on
one platform was generalised to both in comments, with no test on either. Reading the
generator is not evidence about Seatbelt. Only execution is.

## Why this cannot run in CI (or in a shielded session)

macOS refuses to nest a Seatbelt sandbox: inside an agentjail shielded session,
`sandbox_apply` returns `EPERM` and **every** `sandbox-exec` call fails - even
`(version 1)(allow default)`. So the probe must run on an unshielded macOS box.
`test/testbed` already boots one (`golden-macos` via tart); that is the venue.

    # from an UNSHIELDED terminal on the Mac
    tart run --no-graphics tb-release-gate &
    scp guest-probe.sh guest-mutate.sh admin@$(tart ip tb-release-gate):/Users/admin/probe-kit/
    ssh admin@$(tart ip tb-release-gate) 'bash /Users/admin/probe-kit/guest-probe.sh'

`run-probe.sh` is the host-side variant (unshielded Mac, builds everything itself).
Binaries copied into the guest need an ad-hoc re-sign (`codesign --force -s -`) or the
kernel SIGKILLs them; pure-Go binaries also need `-ldflags=-linkmode=external`, since
internal linking omits `LC_UUID` and dyld then refuses to exec them.

## Probe hygiene - these silently invalidate results if violated

The scripts assert all of these at runtime and abort rather than emit a false pass:

- probe `$HOME` must be **outside `/tmp`** - the shield grants `/tmp` read-write.
- **cwd must not enclose `$HOME`** - the cwd-encloses-home path is a silent pass.
- socket paths must stay **< 104 bytes** (`sockaddr_un`).

## Measured results (macOS 15.7.7, clean guest, real binary)

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

## Mutation testing is mandatory here

A green security test that cannot fail proves nothing. The first mutation attempt in this
work deleted only the `(literal ...)` line of a two-line rule, leaving a dangling
`(deny network-outbound` → sbpl **syntax error**. `sandbox-exec` refused the profile, the
connect failed, and it *looked* like the gate held. It tested nothing.

`guest-mutate.sh` therefore deletes whole rules and **asserts the mutated profile still
COMPILES** before drawing any conclusion. Assert the side effect (the connect actually
happened), not just that the reply said no.
