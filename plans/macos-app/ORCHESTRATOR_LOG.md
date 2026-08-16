# AgentJail Approval orchestrator log

Local coordination record for the macOS approval companion. The orchestrator
owns this file; executors report through messages and their unique handoffs.
Nothing in this log authorizes a push, PR, issue, upload, notarization request,
or other public action.

## 2026-08-15 — planning baseline

- Repository: `/Users/aseemshrey/Repos/AgentJail-Repos/agentjail`
- Branch/commit observed: `main` at `d2afaf2c`
- Product source changed by planning: no
- Remote/public action: none
- Planning artifacts: `plans/015` through `plans/030` and `plans/macos-app/`
- Root README and the exact other user-owned dirty paths are reserved in
  `COORDINATION.md`; no task may touch them except plan 027 after clearance.

Three read-only reconnaissance tracks reviewed Apple UX/platform constraints,
the existing daemon/control seams, and macOS build layout. Three fresh read-only
plan reviewers then audited backend security, Swift/packaging feasibility, and
common-worktree orchestration.

## Findings incorporated before dispatch

1. The only MVP mutation seam is the existing authenticated
   `daemon-ctl.sock` project-host grant flow. Codex command asks remain native
   and have no external Approve action.
2. Darwin currently falls back to a self-reported CWD when kernel verification
   is unavailable. Plan 016 is a P0 release gate; the composed app cannot expose
   Approve until the live CGO-disabled resolver and fail-closed behavior pass.
3. Pending expiry was enforced only by a periodic reaper, so an expired item
   could be claimed before cleanup. Plan 029 makes expiry atomic under the
   registry lock.
4. `json.Decoder(io.LimitReader(...))` did not prove a single complete bounded
   frame. Plan 030 defines strict newline-delimited, size-checked control frames.
5. Authority strings can exceed a safe snapshot budget. Plan 017 includes a
   bounded typed context: authority fields are complete or deny-only and
   unrepresentable, never truncated-and-actionable.
6. Cold review fixed executable/bundle identity drift, foreground notification
   presentation, notification action authentication/identifier privacy,
   hardened-runtime verification, canonical fixture ownership, ADR-number
   reservation, scoped dirty-worktree drift checks, and the impossible
   self-referential handoff commit SHA.

## Dispatch state

No implementation task is claimed. The first safe task is plan 015. After its
orchestrator review, Wave B may run plans 016, 017, and 019 concurrently because
their product paths do not overlap. Later waves are listed on the task board.

## Execution entry template

The orchestrator appends one entry after reviewing each task:

```text
date/time:
plan:
agent:
claim acknowledged at HEAD:
commit SHA:
changed paths matched ownership: yes/no
verification rerun:
security/privacy scan:
board verdict: DONE | REWORK | BLOCKED
dependent tasks released:
remote action: none
```
