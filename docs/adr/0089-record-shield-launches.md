# ADR 0089-record-shield-launches: a shield that cannot record says so

Status: Accepted

## Context

The shield opened its audit store and discarded the error:

```go
var emitter audit.Emitter = audit.NopEmitter{}
home, _ := os.UserHomeDir()
if home != "" {
    dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
    if st, err := store.Open(dbPath); err == nil {
        emitter = st
        defer st.Close()
    }
}
```

No `else`, no log, no stderr. A locked, corrupt, or unwritable store left the emitter as
`NopEmitter{}` and the shield launched normally, recording nothing. `os.UserHomeDir()`'s
error was dropped on the line above — the same bug in miniature.

`shield.activated` is not decoration. The shield opens the store directly, so it is the
only surface still recording while the daemon is down, and two things are built on that:

- **[ADR 0082-doctor-attests-enforcement](./0082-doctor-attests-enforcement.md)** cross-checks
  the newest `shield.activated` against the newest decision to attest that enforcement ran.
  Its own words: the shield "keeps recording precisely when policy enforcement is off. That
  makes it a bad health metric and an excellent cross-check." With no `shield.activated`,
  `enforcementGapCheck` takes its `LastShield.IsZero()` branch and reports **skip — "no
  recent shield activity to cross-check"**. The check is defeated at its source, and doctor
  cannot distinguish *the shield never ran* from *the shield ran but could not write*.
- **The divergence signal (AGE-224)** — "`shield.activated` climbing while `decisions` stays
  flat" is the machine-detectable signature of a daemon-down window. If the shield cannot
  write, `shield.activated` stays flat too, the divergence never appears, and a future
  detector reports all-clear during exactly the incident it exists to catch.

So the defect produced a session that was **genuinely sandboxed but invisible to every
attestation surface**, silently. This is the inverse of
[ADR 0087-shielded-means-sandboxed](./0087-shielded-means-sandboxed.md): there the env var
claimed protection that did not exist; here real protection existed but went unrecorded.
Same broken contract — the record must match reality — approached from the other side.

## Decision

**The shield launches, loudly, and drops a marker. It does not fail closed.**

### Why not fail closed

Fail-closed is the reflex here and it is wrong, because the shield is a *wrapper* and the
user's workaround is to drop it. Refusing to launch does not produce a recorded session; it
produces `claude` run bare — **unsandboxed and unrecorded**. Fail-closed on the hook is
cheap (one tool call is denied; the agent stays inside the sandbox). Fail-closed on the
shield costs the whole sandbox, because the thing being denied is the sandbox's own
entrypoint. A corrupt DB would block every launch on the machine until the user deleted the
wrapper, and then the enforcement would be gone too.

The rule this follows: **never trade real enforcement for a lost log line.** The existing
refusal on a malformed policy file (`main.go`, ADR 0040 / ADR 0041) is not a
counter-example, it is the boundary. There the *content of the sandbox* is unknown, so
launching would enforce something nobody chose. Here the sandbox is fully known and applied
exactly as configured; only the record is lost. Refuse when enforcement is wrong, not when
the bookkeeping is.

### On ADR 0018's fail-open-on-logging rule

The same posture, reached by different reasoning, and the difference matters.
[ADR 0018](./0018-sqlite-local-store.md) says "fail-open on logging: a DB write failure does
not block the decision", and justifies it explicitly on latency: "This is the right
trade-off for a <5ms latency target (a synchronous DB write per decision would risk the
budget)" — the daemon's per-tool-call hot path, governed by
[ADR 0002-latency-as-engineering-metric](./0002-latency-as-engineering-metric.md). **That
reasoning does not transfer.** A shield launch happens once per session, before exec, and is
not latency-bound; a synchronous store open costs nothing anyone would notice. Citing 0018
here would be inheriting a conclusion whose premise is absent.

The conclusion survives on its own footing — the workaround argument above — and it is worth
naming that the two rules are only coincidentally aligned. If 0018's latency premise were
ever revisited, this decision would not move with it.

### What loud means

The store open sits **before** Landlock/Seatbelt applies. That is the one moment in the
shield's life when stderr is unambiguously the user's terminal and not something the sandbox
might interfere with. The banner names the store path and the open error, states that the
sandbox still applies, and states the consequence in the user's own vocabulary — the session
will be missing from `agentjail logs` and invisible to `agentjail doctor`.

Loud is necessary and not sufficient. Stderr scrolls away, and neither doctor nor a future
detector reads the user's scrollback. Note that the shield's failure to be heard is a
solved-and-relearned lesson: [ADR 0073](./0073-fail-open-notice-uses-systemmessage.md)
records three days of an invisible fail-open banner because Claude Code discards hook stderr
on exit 0. A banner alone is a warning, not a record.

### The marker

The shield writes `~/.agentjail/shield-unrecorded` (JSON: timestamp, pid, open error) when
it launches without a store. This is the only part of the fix that repairs what the Context
describes: it restores doctor's ability to tell "never ran" from "could not write", turning
a **skip** into evidence.

It mirrors the fail-open sentinel ([ADR 0050-daemon-unreachable-policy](./0050-daemon-unreachable-policy.md),
read by ADR 0082) deliberately — same directory, same best-effort posture, same job of dating an outage
for a reader who arrives later. Out-of-band is not a workaround here but the requirement:
the record of "the store is unavailable" cannot live in the store.

**The marker is best-effort and degrades in the correlated case.** The causes that break the
store — unwritable `~/.agentjail`, full disk — break the marker write too. It is written for
the common shape (a corrupt or locked DB file in a healthy directory), and the stderr banner
is what covers the rest. Claiming otherwise would repeat this ADR's own bug one level up.

### Home resolution

`shieldStateDir()` returns an error instead of falling back to `/tmp`. `defaultPolicyPath()`
falls back because a policy read from `/tmp` still enforces something; a store *written* to
`/tmp` is one no reader ever looks in — an unrecorded session wearing the costume of a
recorded one.

## Consequences

- A store failure is now impossible to miss at launch and leaves dated evidence on disk. The
  session still runs and is still fully sandboxed.
- **The marker's reader is not wired up.** `agentjail doctor` does not yet consult
  `shield-unrecorded`, so the ADR 0082 skip stands until it does; this change guarantees the
  evidence exists at the only moment it can be captured. Wiring the Protection section to
  report the marker is the follow-up, and it is a `cmd/agentjail` change.
- A stale marker is not cleaned up by anything. The fail-open sentinel is re-armed by the
  daemon on startup; nothing plays that role here, so the reader must treat the marker's
  mtime as the signal and not its mere presence. Deciding the cleanup owner is deferred to
  the reader change rather than guessed at now.
- The banner is a fourth thing the shield can print before exec. It fires only on a real
  failure, so it does not add noise to a healthy launch.
- The posture is now explicit and testable: tests assert an unopenable store produces an
  error, a banner naming the cause, and a marker — rather than asserting only that the happy
  path still works, which is what let this survive.

Related: ADR 0082-doctor-attests-enforcement (the defeated cross-check), ADR
0087-shielded-means-sandboxed (the inverse defect), ADR 0018-sqlite-local-store (the rule
that does not apply), ADR 0073-fail-open-notice-uses-systemmessage (why loud is not enough).
