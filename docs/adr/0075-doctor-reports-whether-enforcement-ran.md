# 0075 — doctor reports whether enforcement ran, not just whether it is configured

Status: Accepted

## Context

Every existing `agentjail doctor` check answers a **present-tense** question:
is the binary installed, is the hook registered, does the socket accept a
connection. All of them pass on a machine that spent the last three days
completely unprotected, because by the time anyone runs doctor the daemon has
usually been restarted — the evidence of the outage is in the past.

The failure this project cannot have is a silent unprotected window, and the
data to detect one after the fact already exists:

- The **shield** writes `shield.activated` to the store on its own path,
  independent of the daemon. It therefore keeps recording precisely when policy
  enforcement is off. That makes it a bad health metric and an excellent
  cross-check: `shield.activated` advancing while `decisions` stands still is
  the signature of the whole bug class (daemon down, hook not firing, hook
  failing open).
- The **fail-open sentinel** is written by the hook the first time it cannot
  reach the daemon, and cleared by the daemon on startup. A surviving sentinel
  therefore dates the start of the current outage — it was already described in
  the code as forensics for exactly this, and nothing read it.
- `decisions.dropped` (ADR 0072) says the record is incomplete.

Three signals, all already on disk, none surfaced anywhere.

## Decision

Add a **Protection** section to `agentjail doctor` reporting whether
enforcement actually ran:

1. **Enforcement** — cross-check the newest `shield.activated` against the
   newest decision. Shield activity leading decisions by more than
   `enforcementGapMargin` (1h) is a **fail**: shielded work went unrecorded, so
   policy was likely not enforced. A shielded session that runs tool calls
   records decisions within seconds, so the margin distinguishes a broken window
   from a brief quiet one. No shield activity within `protectionLookback` (7d)
   **skips** — an idle machine is not a broken one.
2. **Fail-open history** — surface the sentinel's age as a **warn**.
3. **Decision recording** — surface `decisions.dropped` as a **warn**.

The checks are pure functions of a `protectionSignals` struct, so the
thresholds are tested against the real incident's shape without a database.
Reading is best-effort and read-only (`store.OpenReadOnly`): a missing or
unreadable DB yields zero signals, and doctor still reports every other
section.

## Consequences

- A past unprotected window is now visible from the CLI, after the fact,
  which is the only time anyone thinks to look.
- Enforcement gaps are a `fail` (exit 1), so scripts and CI can gate on it.
  Fail-open history and dropped decisions are `warn`: both describe damage
  already done rather than a currently broken install, and doctor's failure
  exit is wired to "run `agentjail install --all` to fix", which would be the
  wrong advice.
- This is detection, not alerting. Doctor only speaks when run; it does not
  watch. A live alarm on the same divergence is the natural follow-up, and this
  ADR deliberately settles the signal and thresholds first so the alarm has
  something proven to build on.
- The sentinel check can misreport if a hook failed open against an overridden
  socket while a healthy daemon was running. It is a `warn` on a diagnostic,
  and the alternative — reading nothing — is what allowed a three-day outage to
  pass unnoticed.

Related: ADR 0050 (daemon unreachable), ADR 0072 (dropped decisions), ADR 0073
(fail-open notice).
