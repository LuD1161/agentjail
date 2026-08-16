# Plan 027: Publish local approval-app guidance

> **Executor instructions:** This task is deliberately blocked while README.md
> has pre-existing user edits. Begin only after the orchestrator confirms those
> edits are committed, moved, or otherwise safe to integrate, and plan 026 has
> board status DONE with acceptance verdict PASS. Re-read the final code and
> handoffs; document observed behavior, not the planning proposal.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for every exact target document and handoff. Any unowned modification to a
> target is a STOP condition.

## Status

- **Priority:** P2
- **Effort:** S
- **Risk:** LOW
- **Depends on:** plan 026 board DONE + acceptance PASS and explicit dirty-path clearance
- **Category:** documentation
- **Planned at:** commit `d2afaf2c`, 2026-08-15
- **Initial state:** BLOCKED — `README.md` contains pre-existing user changes

## Why this matters

The app's most important behavior is semantic: approval persists host access
for future matching project sessions and does not change the current sandbox.
Local build/install, notification privacy, login behavior, and known MVP limits
must be explicit so users do not infer live command approval or stronger
distribution guarantees than were tested.

## Scope

**In scope after clearance:**

- a narrow AgentJail Approval section in `README.md`
- `macos/AgentjailApproval/README.md`
- `macos/README.md` when needed to distinguish Approval from AgentjailTunnel
- `plans/macos-app/handoffs/027.md`

These are the only default claimable documents. If plan 026 proves another
specific flow/sandbox file is stale, report its exact path before claiming this
task. The orchestrator must amend/acknowledge the owned path list (or create a
separate docs task) before it may be edited.

**Out of scope:** source, ADR revisions unless facts contradict the accepted
decision, installer/release workflows, version bump, screenshots with host
data, every unnamed document, website changelog, GitHub release/issue/PR, or
publishing artifacts.

## Git workflow

One signed local commit: `docs(macos): explain approval companion`. Follow the
shared lock. No push or public report.

## Steps

### Step 1: Verify the documentation baseline

Confirm plan 026 is board DONE with a PASS verdict, inspect the final plist/build commands/settings,
and reconcile every claim against tests. Record the exact reviewed commit in
the handoff. If README remains dirty, do not stage, patch, or reformat it.

### Step 2: Document the product truthfully

Cover, in plain language:

- the app is a separate menu-bar companion, not AgentjailTunnel;
- it reviews daemon-owned pending project host grants;
- Approve means “approve for future sessions”; current sandbox unchanged;
- Deny/expiry behavior and daemon-disconnected stale-state behavior;
- notifications are optional, generic, and expose Review/Deny but not Approve;
- notification and login-at-startup permissions are explicit settings;
- the app reads the existing local control token only for per-request daemon
  authentication and does not persist/log it;
- it does not read SQLite, parse logs, write policy directly, or approve Codex
  command challenges;
- macOS 13+, local build/sign/package commands, and current distribution status.

Do not call an ad-hoc-signed build notarized, Gatekeeper-ready, App-Store-ready,
or publicly released.

### Step 3: Add local developer/install guidance

Document exact tested commands from plan 026, artifact locations, how to launch
the local app without overwriting an installed copy, notification/login setup,
how to quit, and how to diagnose missing daemon/token/socket state without
printing secrets. Clearly label any Developer ID/notary variables as optional,
untested, or outside the local MVP according to evidence.

### Step 4: Check links, copy, and drift

Run repository markdown/link tooling if present, `rtk make adr-check`, and
search docs for prohibited claims:

```sh
rtk rg -n 'Allow once|Allow now|current session|temporary grant|Codex.*approve|notarized|App Store' README.md macos docs
```

Review every hit in context; historical ADR/GOTCHAS statements may be valid.
Confirm no token, username, home path, private project, or MCP name appears.

### Step 5: Commit after orchestrator review

Show the exact diff to the orchestrator, especially the integration with the
pre-existing README changes. Write the handoff and create the signed local
commit under the lock only after approval of that diff.

## Done criteria

- [ ] Dirty-path clearance was explicit and recorded before editing README.
- [ ] User docs match plan 026's tested behavior and commands.
- [ ] Future-session semantics and current-session non-effect are prominent.
- [ ] Privacy, notification, login, disconnect, and Codex limitations are clear.
- [ ] Local/ad-hoc distribution is not described as a public notarized release.
- [ ] No sensitive host data or unrelated user edits are overwritten.
- [ ] Documentation checks pass in a signed local-only commit.

## STOP conditions

- README or another target remains modified by the user/another agent.
- Plan 026 is not PASS or the app behavior is still changing.
- A statement cannot be backed by a test, handoff, accepted ADR, or inspected code.
- The task would require publishing, installing globally, or changing source.

## Maintenance notes

When distribution changes, update these docs in the same implementation commit.
Never let “approval” lose its future-session qualifier unless the underlying
policy semantics change through a new decision and test matrix.
