# AGE-216 item 3 - review record: macOS sbpl control-socket isolation

Status: complete. Branch `age-216-sbpl-verify`.
Evidence: [`test/sbpl-probe/README.md`](../../test/sbpl-probe/README.md).
Decisions: [ADR 0067](../adr/0067-control-plane-token-auth.md), [ADR 0069](../adr/0069-daemon-control-token.md).

This is the record of the Codex review that CLAUDE.md mandates for any shield
change and that the original fix shipped without - `codex exec` cannot run
inside a shielded session (ADR 0055: `~/.codex` is write-denied, app-server
socket blocked), so it was skipped and the fix landed on execution evidence
alone. It was re-run later from an unshielded terminal.

Outcome: **REVISE x4, then APPROVED**. The design was right; three defects were
real. Two of them were security-relevant. Kept because the *reasoning* is the
durable part - the diffs are in git, but why a rule is or is not load-bearing is
not recoverable from a diff.

## The design held up

- **"Denies last" is the right narrow fix.** Making the network section
  deny-default would be a semantic rewrite requiring fresh execution probes for
  every network rule, because the allow-list only works today thanks to
  filtered-allow specificity beating the trailing catch-all (E2c).
- **Keeping the redundant explicit denies is defence-in-depth, not a lie in the
  profile** - conditional on the comments staying honest about which rule is
  actually enforcing. They do.

## Defect 1: the SSH_AUTH_SOCK guard had an exploitable bypass

`isControlSocketPath` fell back to `filepath.Clean` whenever `EvalSymlinks`
failed - which is the *normal* case, since the socket is usually unbound when
the profile is generated and `EvalSymlinks` fails on a missing leaf. `Clean`
does not resolve a symlinked parent:

    home=/private/tmp/X   SSH_AUTH_SOCK=/tmp/X/.agentjail/secrets.sock
      -> guard returns FALSE
      -> (allow network-outbound) emitted for the credential broker's socket

`secrets.sock` is the exploitable one **precisely because it lives outside
`~/.agentjail/run/`**: the "inside the control-socket dir" check resolves an
existing directory, so it covers the other two sockets even with a broken
resolver. The one socket outside that dir is guarded only by exact-path
comparison - and that is the one holding the credential broker.

Fixed by `resolvePathBestEffort` (walk to the deepest existing ancestor,
resolve it, re-append the unresolved remainder).

Not agent-reachable today - `SSH_AUTH_SOCK` is read from the shield's env, not
the agent's - so this was a latent trap, not a live escape.

## Defect 2: the shared contract was not shared

`controlSocketPaths` was defined in `shield_darwin.go` (build-tagged darwin)
while its doc comment claimed to be the ADR 0034 "one source of truth". Linux
cannot compile against it. This is the exact drift the contract exists to
prevent, in a repo whose AGENTS.md carries a cautionary example about it.

Moved to the tag-free `shield_contract.go` as `ControlSocketPaths`, beside the
other shared lists. Its comment names the Linux non-parity explicitly rather
than implying coverage.

## Defect 3: the probe had drifted from the thing it was probing

`run-probe.sh` (host-side duplicate of the `guest-*.sh` scripts) was stale in
both ways that matter, and deleted rather than patched:

- it looked for `secrets.sock` under `run/`. It is not there - the same layout
  mistake the generator had, reproduced in the tool meant to catch it. It bound
  a server at a path with no deny rule and probed a socket nothing listened on.
- its mutation step was `grep -v netproxy-ctl.sock`, which `guest-probe.sh`
  documents *by name* as a trap: it strips only the `(literal ...)` line of a
  two-line rule, leaving a dangling `(deny network-outbound` -> sbpl syntax
  error -> `sandbox-exec` refuses the profile -> the connect fails -> the gate
  looks like it held while testing nothing.

The `guest-*.sh` scripts are now host-runnable (`KIT` / `PROBE_HOME` / `WORK`
overridable), verified reproducing E0-E5 on the host with no VM. One probe, not
two. **A drifted probe is worse than no probe: it produces confident, wrong
evidence.**

## The finding that outlived the ticket: false mechanism claims

The review's most valuable catch was not in the sbpl code. A comment written
during this very fix asserted that Linux closes the control-socket boundary by
withholding write access to `~/.agentjail` - the precise claim ADR 0067 exists
to refute. It had been inherited from existing code and promoted into the
*shared contract*, where it would be read as authoritative.

The package's own test had recorded the truth the whole time:

```go
// Landlock cannot prevent AF_UNIX connect() - FS-only LSM. Issue #10.
if strings.Contains(output, "ctl_connect=EACCES") {
    t.Logf("ctl_connect denied (bonus)")
} else {
    t.Logf("ctl_connect=ok (Landlock limitation; grant-socket isolation needs Tier 2+)")
}
```

A denied connect is logged as a **bonus**; `ctl_connect=ok` is the expectation -
roughly 190 lines below a comment calling that socket "agent-unreachable".

**Six sites corrected**, which the earlier "all nine are now corrected" pass had
missed: five in `internal/shieldapp`, one in `internal/daemonapp/grantserver.go`.
The last was the worst: its package doc said "the sandboxed agent cannot reach
this socket **(see `grantctl.ControlSocketPath`)**" - citing as evidence the
package that says *"the socket path itself is not a boundary on Linux"*.
`grantctl` was corrected when the token landed; this caller was missed and kept
pointing at it.

**The lesson, for item 1 and anything like it:** correcting the instances you
find by reading does not converge. The first pass fixed nine and left six,
including one that cited a corrected file as proof of the opposite. Grep the
*class*, not the instance.

Sweep is clean as of `5ded95c9`: nothing in `internal/` or `cmd/` claims path or
peer-UID is the boundary. `grantctl`, `ctlauth`, `cmd_grants` and `proxyctl` all
credit the token correctly.

## Mutation testing caught a test that could not fail

Required here, and it earned its keep. Defeating the guard and reverting the
ordering each failed correctly. But the **new** canonicalization test passed
against the reintroduced bug: it used `netproxy-ctl.sock` (caught by the ctlDir
check regardless of the resolver) and named `home` through the same alias as the
probe path, so both sides fell back to `Clean` and compared equal by accident.

Rewritten to target `secrets.sock` with `home` resolved and the socket aliased.
It now fails on the bug and passes on the fix. Both facts are load-bearing and
both are asserted in the test's own comment, so the next person cannot
accidentally re-weaken it.

## What changed under measurement

`M3` flipped. Pre-fix, removing the `(deny network*)` catch-all left
`secrets.sock` at `CONNECT_OK`, because it had no deny of its own - the basis
for "the explicit denies are dead code". It now has one, so **M3 is DENIED**:
the `secrets.sock` deny is the one control-socket rule that is *measurably
load-bearing under mutation*, not merely defence-in-depth. The two `run/` denies
remain redundant (M1/M2 unchanged).

`guest-mutate.sh` had stated the pre-fix expectation as if it were live, so a
reader running it today would have seen `DENIED` beside text calling that a
failure. Corrected, and re-measured on a clean guest.

## Deliberately not done

The `~/.agentjail/daemon.sock` single-file write grant stays. Its stated
rationale is false, which *suggests* it is a no-op that could be dropped - but
"the reason is wrong" is not "the grant is unnecessary", and the enforcement
test only ever runs with the grant present, so it cannot attribute
`sock_connect=ok` to it. Nobody has measured a Landlocked `connect()` without
it.

Removing a grant by reasoning, from the wrong OS, is exactly the failure this
ticket exists to correct. Recorded as open and unmeasured in ADR 0067 and in the
code; needs someone on a Landlock kernel.
