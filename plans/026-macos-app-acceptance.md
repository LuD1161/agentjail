# Plan 026: Prove cross-language and real-Mac behavior

> **Executor instructions:** This is an independent verification task, not a
> feature task. Begin only after plans 018, 024, and 025 are reviewed DONE.
> Read all handoffs, record the shared worktree's scoped dirty baseline, rerun
> their gates, and report product failures as REWORK against the owning plan.
> Do not fix product code here and do not stash/clean unrelated user work.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for `test/macos-approval/acceptance/**` and the handoff, then record whole-tree
> status and `rtk git log --oneline -20` for attribution. Preserve every
> pre-existing user path. If an assertion needs product edits, assign REWORK.

## Status

- **Priority:** P0
- **Effort:** L
- **Risk:** HIGH
- **Depends on:** plans 018, 024, and 025
- **Category:** verification / security
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Green unit suites do not prove that Go and Swift agree on the wire, Darwin CWD
binding works in a CGO-disabled daemon, notification callbacks revalidate
authority, or a packaged app reaches the real control socket. This gate proves
the complete local behavior on a physical Mac before documentation calls the
MVP usable.

## Current state

- Plan 016 is responsible for fail-closed Darwin project binding.
- Plans 017/018 define and serve the authenticated v1 review contract.
- Plans 020-024 implement the Swift client, state, UI, notifications, and app
  composition.
- Plan 025 produces a locally signed universal app and DMG.
- The control operation grants host access to **future project sessions** only;
  the current sandbox must remain unchanged.

## Test matrix

| Layer | Required cases |
|---|---|
| Go protocol | golden v1 snapshot, bounded list, token failure, unsupported op/version, malformed/trailing JSON |
| Swift protocol | same fixture semantics, unknown field tolerance, unknown version refusal, bounded frame, timeout |
| State | empty, pending, expiry/race, disconnect with stale disabled rows, recovery, daemon restart, duplicate snapshot |
| Mutations | approve success, deny success, unknown ID, atomically refused expired ID, reply loss with no automatic replay |
| Darwin binding | current process and child CWD, nonexistent PID, exited PID, permission/error path, CGO off, arm64 + amd64 compile |
| Notifications | explicit permission, generic content, Review route, Deny revalidation, no Approve action, dedupe/expiry |
| Packaging | universal binary, plist, exact entitlements, strict signature, DMG mount/read/verify |
| Real daemon | request appears, app reviews it, approve writes future overlay, current session unchanged, new session changed |

## Scope

**In scope:**

- `test/macos-approval/acceptance/**`
- local evidence under `plans/macos-app/handoffs/026.md`
- test-only fake daemon/socket helpers inside the acceptance tree

**Out of scope:** production Go/Swift source, product fixtures already owned by
other plans, README, release/installer workflows, tunnel, external CI, public
artifacts, or weakening an assertion to obtain green output.

## Git workflow

One signed local commit for durable acceptance tooling/evidence:
`test(macos): verify approval companion`. Follow the shared lock. No push.
If all work is ephemeral/manual and no durable test file is justified, create
only the handoff commit; never manufacture source churn.

## Steps

### Step 1: Reconcile the Go and Swift contracts

Build a test harness that feeds the canonical plan-017 v1 JSON fixture to both
decoders and compares typed meaning, including milliseconds, enum spellings,
IDs, `can_approve`, and untrusted display fields. Generate a Go response from a
fake/current registry and prove Swift accepts it. Prove both sides reject a
different envelope version and oversized/trailing frames consistently.

Do not duplicate or edit the fixture. Plan 017 is its sole owner; every Go,
Swift, and acceptance test references that file by relative path. A required
fixture/contract change is REWORK for plan 017/018.

**Verify:** a deliberate field/version mutation makes the compatibility test
fail with a precise diagnostic.

### Step 2: Exercise the socket security boundary

Use task-specific temporary directories, socket paths, and tokens. Cover:

- valid token and snapshot;
- missing, empty, wrong, and changed token;
- absent/refused/stalled socket;
- response above 64 KiB, malformed JSON, trailing bytes, and server close;
- missing newline, non-whitespace after JSON within a frame, and a second frame
  that is never dispatched;
- one request/one response/close behavior;
- approval response loss after a server-side commit, proving the client does
  not automatically replay the mutation.

Scan captured logs and test failures for the literal token; the test must fail
if it appears. Never point destructive test setup at `~/.agentjail`.

### Step 3: Run state/UI/notification scenarios

With deterministic clocks/fakes, prove the panel, menu label, and notification
coordinator agree on pending identity and actionability. Cached rows must be
disabled immediately after disconnection. A notification Deny action must
fetch a fresh snapshot and become a no-op when the item expired, disappeared,
or changed identity. No test or source may expose an Approve notification
action.

Perform keyboard-only navigation and accessibility-label checks in automated
tests where available; record manual-only checks separately.

### Step 4: Prove the real future-session flow

On a physical Mac, create a task-specific project with `rtk mktemp -d` beneath
`/private/tmp`, use the reserved inert host `approval-test.invalid`, and use the
real local daemon/control-token paths. Before starting, record the exact
temporary root and prove it is not a production repository or a descendant of
the user's home project tree. Capture only redacted evidence:

1. start a sandboxed project session without the host overlay;
2. file a host grant request;
3. observe the app notification/menu row;
4. approve from the detailed panel;
5. prove the current process/session did not gain host access;
6. start a new matching project session and prove the persisted overlay now
   applies;
7. repeat with Deny and with a request that expires before action;
8. restart the daemon and prove stale app state is disabled/cleared.

The only persisted overlay must be inside that temporary project. At teardown,
inspect and record its contents, prove no global/user policy file changed,
remove only the validated explicit temporary root, and verify it no longer
exists. STOP rather than test if isolation or cleanup cannot be proven.

Never record raw terminal casts, home paths, usernames, token values, project
secrets, or internal MCP names. Use the repository recording-hygiene rules if
any recording is made.

### Step 5: Inspect the built app

Before launching any copy, prove there is no running process, installed app, or
login registration with bundle ID `com.blinkerlm.agentjail.approval` other than
the task's known build/DMG artifacts. If one exists, STOP and ask the operator;
do not activate, quit, replace, unregister, or otherwise disturb it.

Run plan 025's architecture, plist, entitlement, signature, mount, and checksum
checks against the exact artifact. Test one copy at a time. Launch the DMG copy,
assert the running application's executable/bundle URL is that explicit copy,
quit it, and prove no matching process remains. Then repeat from one
task-specific Applications-style acceptance copy without overwriting an
installed app; record only a redacted path hash in durable evidence.
Confirm it does not contain or import tunnel binaries/entitlements. Assert the
product/binary is `AgentjailApproval`, `CFBundleExecutable` matches its
basename, bundle ID is `com.blinkerlm.agentjail.approval`, every executable
signature verifies, the runtime flag is set, and actual normalized entitlements
are exactly an empty dictionary matching plan 025.

### Step 6: Complete manual Apple UX gates

Record OS/hardware/app versions and pass/fail evidence for:

- first launch with notifications undecided, denied, and enabled;
- banner/list delivery through `willPresent` while foregrounded, plus Review
  and authentication-required Deny while foregrounded/backgrounded;
- Focus suppressing delivery without losing the durable menu item;
- login-item disabled by default, opt-in enable, relaunch, disable;
- VoiceOver reading project, untrusted reason, effect, status, and buttons;
- Voice Control, Switch Control, full keyboard access, increased contrast,
  reduced motion, and Accessibility Inspector;
- long Unicode/bidi/control input rendering without spoofing or layout escape.

Accessibility failures are product failures, not notes to defer silently.

Use only the preflighted task-specific acceptance copy for the login-item
scenario. Unregister it at teardown, remove only that explicit copy, and verify
`SMAppService` is no longer enabled and no matching process remains.

For each manual row, the handoff records: scenario, OS/hardware/app commit,
expected result, observed result, PASS/FAIL, redacted evidence path/hash, and
cleanup status. A prose assertion without reproducible redacted evidence is not
a PASS.

### Step 7: Run repository gates and report

Run, at minimum:

```sh
approval_acceptance_tmp=$(rtk mktemp -d /private/tmp/agentjail-macos-approval.XXXXXX)
rtk go test ./internal/grantctl ./internal/daemonapp -race
rtk env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go test -c -o "$approval_acceptance_tmp/daemonapp-arm64.test" ./internal/daemonapp
rtk env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -c -o "$approval_acceptance_tmp/daemonapp-amd64.test" ./internal/daemonapp
rtk swift test --package-path macos/AgentjailApproval
rtk swift build --package-path macos/AgentjailApproval --product AgentjailApproval
rtk go build ./...
rtk go vet ./...
rtk go test ./...
rtk make smoke
rtk make adr-check
rtk make macos-approval-app
rtk make macos-approval-dmg
```

Confirm `$approval_acceptance_tmp` has the expected `/private/tmp/` prefix,
inspect the two explicit outputs, remove those two files, then remove the empty
directory. Never use a broad recursive cleanup. The handoff lists each
command/result, links each product finding to its owning plan, and gives an
acceptance verdict PASS, PARTIAL, or REWORK.

The shared worktree is not expected to be globally clean. At the start require
an empty staged index, record `rtk git status --short --untracked-files=all`,
and compare it with the coordination file's reserved paths plus reviewed task
commits. A full-repo gate failure attributable to a product task is REWORK; one
attributable only to reserved user work is BLOCKED with evidence, never silently
waived or misassigned.

## Done criteria

- [ ] One canonical fixture proves Go/Swift v1 compatibility and mismatch failure.
- [ ] Socket, token, size, timeout, malformed-input, and mutation-loss cases pass.
- [ ] Disconnect/race/restart paths cannot leave an actionable stale row.
- [ ] Darwin CWD binding passes live and CGO-disabled architecture gates.
- [ ] Real approval changes only a new matching project session; Deny/expiry do not.
- [ ] Notification, login-item, privacy, and accessibility manual gates pass.
- [ ] Built app is universal, strictly signed, minimally entitled, and locally mountable.
- [ ] Full repository gates pass with redacted, local-only evidence.
- [ ] Every product failure is assigned REWORK; reserved-user-path failures are
  reported BLOCKED; none is repaired or waived in this task.
- [ ] Temporary project/artifacts are isolated, explicitly cleaned, and leave no global policy change.

## STOP conditions

- A prerequisite commit/handoff is missing or unreviewed.
- Real testing would require a production project, credential, public upload,
  destructive install, or disabling enforcement.
- Darwin CWD cannot be verified on the running host and CGO-disabled builds.
- Contract semantics differ between languages.
- Approval affects the current session, cached rows remain actionable, or a
  notification can approve.
- A failure can only be hidden by weakening, skipping, or editing product code.
- The staged index is non-empty or worktree drift cannot be attributed safely.

## Maintenance notes

Keep this matrix as the reusable release gate for the approval companion. Add
new review kinds as explicit rows with their own authority, privacy, and race
tests; do not inherit project-host assumptions implicitly.
