# Plan 028: Design a read-only canonical-ask observer

> **Executor instructions:** This is a deferred post-MVP design/spike, not an
> implementation authorization. Begin only when the orchestrator explicitly
> moves it from DEFERRED and plan 024 is DONE. Produce a security decision and
> evidence before assigning source paths. The macOS app must never answer or
> synthesize a Codex command approval.
>
> **Drift check:** re-read the then-current native approval ADRs and installed
> Codex version/docs. External hook and prompt contracts are versioned security
> dependencies; remembered behavior is not evidence. After the orchestrator
> reserves exact ADR/handoff/follow-up-plan paths, run the coordination
> protocol's scoped diff/status checks; any uncommitted overlap is a STOP.

## Status

- **Priority:** P3
- **Effort:** M for design/spike; implementation unestimated
- **Risk:** HIGH
- **Depends on:** plan 024 and explicit orchestrator activation
- **Category:** research / security / notifications
- **Planned at:** commit `d2afaf2c`, 2026-08-15
- **Initial state:** DEFERRED — outside the project-host MVP

## Why this matters

A menu notification that says an agent is waiting could be useful even when
the actual decision must remain inside Codex's native approval prompt. But an
observed historical event is not necessarily a currently pending ask, and
exposing raw commands/challenges adds privacy and replay risk. The observer
therefore needs a canonical, read-only, daemon-owned lifecycle rather than UI
log parsing or a second approval path.

## Security invariants

- Codex remains the only interactive decision surface for command asks.
- Existing native-prompt observation, epoch, one-use challenge, and process
  lineage enforcement remain unchanged.
- The app receives no challenge, response secret, raw command, environment,
  working-directory detail, or process identifier it does not need.
- “Pending” is shown only when the daemon can prove a live canonical ask; a
  decision event/history row alone is never presented as pending.
- Notification actions may open/focus the relevant native context if a safe,
  documented mechanism exists; they can never allow, deny, or execute.
- No direct SQLite reads, log tailing, process scraping, Accessibility control,
  Apple Events automation, shelling out, or screen capture.

## Phase 1 scope: decision only

**In scope:**

- current official Codex documentation and installed-version verification
- a minimal live compatibility probe that does not relax enforcement
- inspection of current daemon/native-approval lifecycle and audit records
- one new ADR with next free mainline number and at-most-three-word slug, if a
  safe observer contract is selected
- a follow-up implementation task split with exclusive file ownership
- `plans/macos-app/handoffs/028.md`

**Out of scope:** production source, Swift UI changes, new mutation endpoints,
challenge export, raw command display, Accessibility/Apple Events automation,
SQLite/log readers, notification approval actions, release changes, or public
reporting.

## Research questions

1. What exact installed Codex version and official contract identify the start,
   continued liveness, resolution, cancellation, and expiry of a native ask?
2. Can the daemon model that lifecycle without observing private prompt text or
   weakening the one-use approval bridge?
3. What stable opaque ID can correlate start/end without becoming a replay or
   cross-session capability?
4. Can the app truthfully say “waiting for review,” or only “approval activity
   observed”? What is the maximum stale interval?
5. Is there a documented, non-automating way to focus the originating Codex UI?
6. What redacted fields are genuinely useful: agent kind, age bucket, generic
   category? Which fields must never cross the socket?
7. How do daemon restart, Codex exit, process-tree change, timeout, and duplicate
   hooks resolve observer state?

## Steps

### Step 1: Verify the external contract

Check the locally installed Codex binary/version, current official OpenAI
documentation, and current hook/config schemas. Run the smallest safe live
probe necessary to observe lifecycle ordering. Record source URLs, versions,
date, commands, and redacted results in the ADR/handoff.

Do not infer “pending” from a pre-tool hook alone unless a documented terminal
event and liveness rule are proven.

### Step 2: Threat-model the observer

Model spoofed starts, missing terminal events, daemon/app restart, PID reuse,
epoch rollover, delayed notifications, replay, denial-of-service, privacy
leakage, and an app compromise. Explain why the proposed read model cannot be
used to manufacture or satisfy the native approval challenge.

Reject any design that exports the challenge or relies on the app as a security
authority.

### Step 3: Select or reject a canonical read model

If evidence supports it, define a typed, versioned daemon snapshot with:

- opaque non-capability ID;
- bounded enum for ask kind/source;
- server-derived state and timestamps;
- explicit expiry/liveness semantics;
- no raw command, challenge, token, full path, or arbitrary agent prose;
- read-only authentication and bounded list size;
- restart behavior that fails stale/closed.

If liveness cannot be established, choose a truthful activity-history design
or reject the feature. Do not relabel history as pending.

### Step 4: Record the decision and split implementation

Ask the orchestrator to reserve the next free ADR number at claim time, then
recheck it and run `rtk make adr-check` while holding the commit lock. Write the
ADR with Context / Decision / Consequences and verification metadata.
If accepted, create new follow-up plans with exclusive daemon contract,
endpoint, Swift model/state, UI/notification, and acceptance ownership. Any
shared dispatch/app-entry edit gets its own serial integration plan.

Run `rtk make adr-check`; commit only the ADR, handoff, and new plans in one
signed local docs commit under the shared lock. Do not push.

## Done criteria

- [ ] Current installed Codex behavior and official sources are recorded.
- [ ] Live lifecycle, terminal events, restart, and stale semantics are proven or explicitly found unprovable.
- [ ] Threat model demonstrates the app cannot answer/synthesize native approval.
- [ ] Selected snapshot is typed, bounded, privacy-minimal, read-only, and non-capability-bearing — or feature is rejected.
- [ ] ADR and follow-up ownership split pass `rtk make adr-check` in a signed local commit.
- [ ] No production source or external/public state changed.

## STOP conditions

- Official/current behavior is uncertain or conflicts with the installed probe.
- A challenge, raw command, direct DB/log read, Accessibility control, or shell
  command would be needed.
- Ask liveness cannot be distinguished from historical activity but the product
  requires “pending” wording.
- The design adds any allow/deny/execute action outside the native Codex prompt.
- The observer would weaken current epoch, lineage, one-use, or fail-closed rules.

## Maintenance notes

Keep this feature independent from project-host grants. They have different
authorities and effects; sharing a generic “approval” enum would erase the very
security distinction the UI must communicate.
