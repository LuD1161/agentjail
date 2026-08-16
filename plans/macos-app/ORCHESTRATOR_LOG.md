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

At planning completion no implementation task was claimed. The first safe task
was plan 015. After its orchestrator review, Wave B may run plans 016, 017, and
019 concurrently because their product paths do not overlap. Later waves are
listed on the task board.

## 2026-08-15 — Plan 015 claimed

- Agent: `plan015_architecture` (Terra)
- Starting HEAD: `7e34bdbdc5e744df74c8239645dc7cc859dd5356`
- Reserved ADR: `docs/adr/0133-macos-menu-review.md`
- Owned handoff: `plans/macos-app/handoffs/015.md`
- State: CLAIMED
- Remote action: none authorized

## 2026-08-15 — Plan 015 accepted; Wave B claimed

- Plan 015 agent: `plan015_architecture` (Terra)
- Commit: `e1220db91d13e43482d2529b42e5d419050f6b18`
- Changed paths matched ownership: yes
- Review rerun: `rtk make adr-check` passed with 129 ADRs and no duplicate
  numbers; `rtk git diff --check e1220db9^ e1220db9` passed; signed-off
  trailer present.
- Security/architecture verdict: PASS. ADR 0133 fixes the app identity,
  daemon-only authority, future-session approval semantics, macOS CWD and
  atomic-expiry release gates, strict framing, notification privacy, and local
  distribution posture.
- Board verdict: DONE
- Wave B agents at starting HEAD `e1220db9`:
  - Plan 016: `plan016_prep` (Darwin verified CWD/fail-closed binding)
  - Plan 017: `plan017_protocol` (typed review protocol)
  - Plan 019: `plan019_prep` (standalone SwiftPM scaffold)
- Pre-existing `go.work.sum` drift appeared during baseline tooling and is not
  owned by any Wave B agent; it remains unstaged and reserved for orchestrator
  review.
- Remote action: none

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
