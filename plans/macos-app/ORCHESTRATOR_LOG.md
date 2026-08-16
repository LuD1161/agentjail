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

## 2026-08-15 — Plan 032 claimed; Plan 029 scope clarified

- Plan 032 agent: `plan019_prep` (Terra)
- Starting HEAD: `f10e5285` plus any independent committed task movement
- Ownership: new `scripts/test-macos-approval.sh` and handoff 032 only.
- Acceptance: official Xcode `swiftc`/Darwin `xctest`, all current tests,
  arm64+x86_64 production type-check, isolated validated `/private/tmp`
  artifacts, no policy/environment/SwiftPM workaround.
- Plan 029 additionally owns the smallest mechanical `ListPending(now)` and
  expired-assertion migration in `internal/grantctl/review_test.go`. Plan 017
  made that test the only compile-time consumer outside the originally named
  registry/daemon files. No JSON/fixture/projection-semantic edit is authorized.
- Remote action: none

## 2026-08-15 — Plan 032 accepted

- Agent: `plan019_prep` (Terra)
- Commit: `de698f31180bd0e6c98f3a155ad66a06600f6740`
- Changed paths matched ownership: yes; only the new harness and handoff 032.
- Review: Bash 3.2-compatible deterministic source discovery, validated
  `mktemp` artifact ownership, cleanup-on-success/preserve-on-failure, and no
  SwiftPM, policy, HOME, Terminal, launchd, SSH, or network workaround.
- Orchestrator rerun: both Darwin XCTest bundles discovered and passed their
  tests; production sources type-checked for arm64 and x86_64 with a macOS 13
  deployment target; the task-specific `/private/tmp` root was removed.
- DCO, Bash syntax, owned paths, and repository-debris checks: PASS.
- Board verdict: DONE
- Remote action: none

## 2026-08-15 — Plan 029 accepted; Plan 030 claimed

- Plan 029 agent: `plan017_protocol` (Terra)
- Commit: `980057e16146290a8cdfc2832a53cf583bc748ff`
- Changed paths matched ownership: yes, including only the previously approved
  mechanical time-aware migration in `review_test.go`; DCO/diff checks passed.
- Security review: `Expires <= now` is one lock-held predicate across claim,
  deny, reads, duplicate renewal, caps, and cleanup. Claim has no find/claim
  race, and an expired decision returns no authority closure, writes no policy
  overlay, and emits no policy-change audit event.
- Orchestrator reruns: focused registry and daemon expiry/grant tests, full
  two-package race, vet, and CGO-disabled CLI/daemon builds: PASS.
- Board verdict: Plan 029 DONE.
- Plan 030 agent: `plan017_protocol` (Terra); starting HEAD `980057e1`.
- Plan 030 ownership: typed grant-control frame helpers/tests, client framing,
  serialized daemon decoder/reply and focused tests, one GOTCHAS entry, and
  handoff 030. Review dispatch, registry semantics, Swift, and proxy framing
  remain out of scope.
- Remote action: none

## 2026-08-15 — Supplemental Plan 033 claimed

- Agent: `plan016_prep` (Terra)
- Starting HEAD: the committed Plan 030 dispatch baseline plus independent
  shared-HEAD movement.
- Reason: untrusted display sanitization and exhaustive Unicode tests are pure
  and do not depend on Plan 021 state or SwiftUI, so they can safely leave the
  Plan 022 critical path without sharing files.
- Ownership: exactly `DisplaySanitizer.swift`, its matching XCTest, and handoff
  033. Plan 022 now excludes those two files and consumes the reviewed helper.
- Acceptance: all C0/C1 and bidi scalars, ANSI/multiline/whitespace handling,
  grapheme-safe ellipsis, exact empty-reason fallback, dual-architecture
  type-check, Darwin XCTest discovery, and no dependency/authority/action code.
- Remote action: none

## 2026-08-15 — Plan 020 parallel implementation claimed

- Agent: `plan019_prep` (Terra)
- Contract prerequisite: Plan 030's exact claim was acknowledged at
  `15af2111`; its normative frame rule is unchanged from the reviewed plan.
- Concurrency decision: Models/Transport Swift paths and Go framing paths are
  disjoint. Plan 020 may implement and run fake-server tests in parallel, but
  it cannot receive DONE until Plan 030 lands and the Swift behavior is checked
  against the reviewed Go helpers/tests.
- Ownership: Swift core `Models/**`, `Transport/**`, their matching tests, and
  handoff 020 only. The canonical Go fixture is read-only.
- Required inherited interfaces: `ReviewID` is bounded/validated, Hashable and
  Sendable; errors are typed and token-free; mutations carry IDs only; snapshot
  retains order/truncation; token loads once per request; one bounded frame and
  connection per operation; no mutation retry.
- Remote action: none

## 2026-08-15 — Supplemental Plan 033 accepted

- Agent: `plan016_prep` (Terra)
- Commit: `5424f3d33a751f40e832ed5a88525425d694797f`
- Changed paths matched ownership: yes; exact sanitizer, matching XCTest, and
  handoff 033 only. DCO/diff/source-scope scans passed.
- Review: ESC and all specified bidi scalars are removed before remaining
  C0/C1 replacement; whitespace is normalized; truncation uses extended
  grapheme clusters plus one ellipsis; empty untrusted reasons receive the
  exact non-misleading fallback.
- Orchestrator rerun: eight sanitizer tests plus existing suites were
  runtime-discovered and passed; arm64 and x86_64 macOS production type-checks
  passed; task-specific artifacts cleaned successfully.
- Board verdict: DONE; Plan 022 may consume this helper after Plan 021.
- Remote action: none

## 2026-08-15 — Plan 030 read-ahead contract clarified

- An adversarial review correctly noted that `bufio.Reader` can read beyond
  the first delimiter into frame two. The first proposed correction performed
  one underlying read per byte.
- That correction is rejected: `daemon-ctl.sock` parsing precedes token
  authentication, so a hostile 64-KiB frame could force roughly 64,000 syscalls
  per connection and create a same-UID denial-of-service amplifier.
- Locked rule: use fixed bounded chunks and at most the frame budget plus one
  byte of storage; decode/dispatch only the first delimited prefix, discard any
  bounded read-ahead, reply once, and close. Frame two is never an operation.
- Plan 030 now explicitly tests semantic single-frame handling and forbids a
  per-byte underlying read loop.
- Remote action: none

## 2026-08-15 — Plan 030 accepted; Plan 018 claimed

- Plan 030 agent: `plan017_protocol` (Terra)
- Commit: `a20039773fc3d0da90c1744ba40775733b0f6ac1`
- Changed paths matched ownership: yes; DCO/diff checks passed.
- Security review: complete frames include LF in the 64-KiB limit; fixed 4-KiB
  reads use exactly `Max+1` storage; only the first delimiter prefix is decoded;
  invalid UTF-8/trailing values fail; unknown fields remain additive; complete
  writers size-check before output and oversize responses become one refusal.
- Authentication audit: peer UID remains first, bounded frame decode second,
  token validation third, and typed dispatch only afterward. The agent-facing
  socket and proxy protocols are unchanged.
- Orchestrator reruns: focused request/client/server framing, two-package race,
  vet, and CGO-disabled CLI/daemon builds: PASS.
- Board verdict: Plan 030 DONE. Plan 020 may finish its Go/Swift cross-check.
- Plan 018 agent: `plan017_protocol` (Terra); owns only the narrow projector,
  authenticated review dispatch/tests, and handoff 018.
- Remote action: none

## 2026-08-15 — Plan 021 parallel implementation claimed

- Agent: `plan016_prep` (Terra)
- Stable prerequisite: Plan 020 commit `afec1180` fixed the public
  `ReviewControlling`, `ReviewSnapshotV1`, `ReviewID`, timestamp, and typed
  error surface. Its narrow cancellation-safety follow-up changes only
  transport execution, not this API.
- Concurrency decision: Plan 021 owns only State sources/tests and may implement
  against that stable interface now. It cannot receive DONE until Plan 020's
  active-request cancellation and fd-ownership follow-up is reviewed.
- Required boundary: authoritative ready snapshots are distinct from stale
  cache; `refreshNow` is awaitable for notification revalidation; local expiry
  is inclusive; one poll loop uses deterministic 2/4/8/16/30 backoff; same-ID
  decisions are single-flight and mutation failures never auto-retry.
- Remote action: none

## 2026-08-15 — Supplemental Plan 031 claimed

- Agent: `plan016_prep` (Terra)
- Starting HEAD: `c72a4c44`
- Reason: full daemon package gates are blocked by two pre-existing SIGHUP
  subprocess tests inheriting home-derived log/database paths. Their product
  assertions never execute on this host.
- Ownership: only `internal/daemonapp/main_test.go`, restricted to those two
  tests, and `plans/macos-app/handoffs/031.md`.
- Acceptance: explicit per-test temporary log/database paths; focused normal
  and race runs, vet, diff check, signed local commit.
- Production behavior change: none
- Remote action: none

## 2026-08-15 — Plans 016 and 031 accepted

- Plan 016 commit: `c72a4c440a00af2081827b842c58fa716b0314f8`
- Plan 031 commit: `f3eed6e215e368d99364af100788d3b1e8930179`
- Changed paths matched both ownership lists: yes
- Security review: Darwin CWD uses the Apple XNU `SYS_PROC_INFO` PID-info ABI,
  exact checked buffer layout, strict decode validation, and no cgo or
  self-reported fallback. Resolver failure/mismatch leaves a grant unbound and
  an attempted approval writes no project overlay.
- Test-isolation review: only the two SIGHUP subprocess tests changed; each now
  passes explicit log/database paths beneath its existing `t.TempDir()` and
  neither production defaults nor `HOME` changed.
- Orchestrator reruns:
  - focused Darwin binding, grant, and both SIGHUP tests: PASS;
  - the same focused set with `-race`: PASS;
  - daemon package vet: PASS;
  - CGO-disabled Darwin arm64 and amd64 daemon test compiles to distinct
    `/private/tmp` outputs: PASS;
  - DCO, owned paths, and diff checks: PASS.
- Board verdicts: Plan 016 DONE; Plan 031 DONE
- Dependent release: Plan 029 still waits only for Plan 017 review.
- Remote action: none

## 2026-08-15 — Plans 017 and 019 accepted; Plan 029 claimed

- Plan 017 commit: `f3f10053422fd9839e13e311b1cd08906e7b39f3`
- Plan 019 commit: `8e327f1afd53a83c681e3c7ecffca2f4125ab47c`
- Changed paths matched both ownership lists; DCO and diff checks passed.
- Protocol review: v1 types are named/additive; snapshots use only complete
  verified `BoundCWD` authority, are deterministic/newest-first, filter
  `Expires <= now`, cap at three, keep worst-case frames below 64 KiB, and make
  unbound/unrepresentable reviews deny-only. The golden fixture has no token,
  challenge, command, or tool input.
- Orchestrator reruns: grantctl race, grantctl vet, daemon grant tests, golden
  fixture, and privacy scan passed.
- Scaffold review: exact product/binary/bundle identity, macOS 13 target,
  dependency-free target graph, `MenuBarExtra(.window)`, plist, placeholder,
  DCO, and forbidden-import scans passed.
- SwiftPM's build engine cannot atomically write its generated output map under
  this running AgentJail sandbox. Direct official Xcode-toolchain `swiftc` and
  Darwin `xctest` fallback compiled both modules, ran both scaffold tests, and
  type-checked production sources for arm64 and x86_64. Plan 019 permits a
  genuine local runner blocker when recorded; its product code is accepted.
- Board verdicts: Plan 017 DONE; Plan 019 DONE
- Plan 029 agent: `plan017_protocol` (Terra)
- Plan 029 starting product baseline: `f3f10053`; ownership is registry expiry
  paths, the narrow daemon call site/tests, one GOTCHAS entry, and handoff 029.
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
