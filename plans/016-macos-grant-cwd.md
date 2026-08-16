# Plan 016: Verify macOS grant project binding

> **Executor instructions:** Read this plan, plan 015's accepted ADR,
> `AGENTS.md`, `docs/GOTCHAS.md`, and the shared coordination protocol. This is
> security-sensitive OS code. Run the live Darwin check and both CGO-disabled
> cross-builds. Do not retain the current self-reported fallback.
>
> **Drift check:** run the coordination protocol's scoped diff/status checks
> for `peerpid_darwin*`, `grantserver*`, GOTCHAS, and the handoff. Any
> uncommitted overlap is a STOP condition.

## Status

- **Priority:** P0
- **Effort:** M
- **Risk:** HIGH
- **Depends on:** plan 015
- **Category:** security / correctness
- **Planned at:** commit `d2afaf2c`, 2026-08-15

## Why this matters

Host approval writes `.agentjail/policy.yaml` inside the bound project. Linux
cross-checks the agent-reported CWD against `/proc/<pid>/cwd`; macOS currently
accepts the reported path whenever verification is unavailable. A one-click
GUI would amplify that gap. Approval must bind to kernel-observed process state
or fail closed before the app can expose Approve.

## Current state

`internal/daemonapp/peerpid_darwin.go:64-70` returns an unsupported error:

```go
func resolvePeerCWD(pid int) (string, error) {
    return "", fmt.Errorf("resolvePeerCWD: not supported on darwin")
}
```

`internal/daemonapp/grantserver.go:435-442` then trusts unverified input:

```go
if verifyErr != nil {
    return selfReportedCWD, selfReportedCWD != ""
}
```

The comment immediately above says the guarantee is Linux-only. The test at
`internal/daemonapp/grantserver_test.go:294-356` explicitly locks in the unsafe
fallback. Release binaries are built with `CGO_ENABLED=0`, so calling libproc
through cgo is not a shippable fix.

The macOS SDK headers provide `SYS_proc_info` (336),
`PROC_PIDVNODEPATHINFO` (9), and `struct proc_vnodepathinfo`; consult the
installed SDK headers and current Apple/XNU primary source rather than copying
unverified constants from a blog.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Focused tests | `rtk go test ./internal/daemonapp -run 'TestResolvePeerCWD|TestDecideBoundCWD|TestGrant' -count=1` | pass on Darwin |
| Race | `rtk go test ./internal/daemonapp -race` | pass |
| Vet | `rtk go vet ./internal/daemonapp` | exit 0 |
| arm64 CGO-off | `rtk env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go test -c -o /private/tmp/agentjail-daemonapp-arm64.test ./internal/daemonapp` | exit 0 |
| amd64 CGO-off | `rtk env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test -c -o /private/tmp/agentjail-daemonapp-amd64.test ./internal/daemonapp` | exit 0 |
| Builds | `rtk env CGO_ENABLED=0 go build ./cmd/agentjail ./cmd/agentjail-daemon` | exit 0 |

## Scope

**In scope:**

- `internal/daemonapp/peerpid_darwin.go`
- `internal/daemonapp/peerpid_darwin_test.go` (new)
- `internal/daemonapp/grantserver.go`
- `internal/daemonapp/grantserver_test.go`
- one concise new entry in `docs/GOTCHAS.md`
- `plans/macos-app/handoffs/016.md`

**Out of scope:**

- Linux peer credential/CWD implementation.
- Grant wire fields, UI, Swift, installer, README, tunnel, or release files.
- cgo, a new dependency, subprocesses such as `lsof` as the security boundary,
  or weakening audit/token checks.

## Git workflow

One signed local commit: `fix(grants): verify macOS project binding`. Use only
owned paths and the shared commit lock. Do not push.

## Steps

### Step 1: Turn unverifiable into fail-closed

First change the decision contract: `verifyErr != nil`, an empty verified CWD,
or a mismatch must return `("", false)`. Update the table test so no error
path accepts self-reported input. This safety change must stand even if the
Darwin resolver later fails at runtime.

**Verify:** a focused test named for unverifiable CWD proves the grant remains
unbound and `approve` writes no overlay.

### Step 2: Implement a CGO-disabled Darwin resolver

Use a thin Darwin-only implementation of the shared `resolvePeerCWD(pid)`
contract. Call the Darwin `SYS_PROC_INFO` syscall with the PID-info subcall and
`PROC_PIDVNODEPATHINFO`; decode only `pvi_cdir.vip_path`. Keep constants and C
layout in named Darwin-only types. At minimum:

- use `unix.SYS_PROC_INFO`, `unix.PathMax`, `unsafe.Sizeof`, and
  `unsafe.Offsetof` rather than allocating an unbounded buffer;
- call the complete PID-info ABI:
  `unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid),
  procPIDVnodePathInfo, 0, uintptr(unsafe.Pointer(&info)),
  unsafe.Sizeof(info))`, with both selectors verified from the installed SDK
  and current XNU primary source;
- verify the returned byte count equals the expected struct size;
- reject PID <= 0, empty/non-NUL-terminated paths, invalid UTF-8, relative
  paths, syscall errors, and partial replies;
- clean the result and require it to remain absolute;
- add compile-time/runtime layout assertions for arm64 and amd64. The current
  64-bit SDK layout has a 152-byte `vnode_info`, a 1,024-byte path, and a
  2,352-byte `proc_vnodepathinfo`; confirm those numbers from the installed SDK
  before encoding them.
- call `runtime.KeepAlive(&info)` after the syscall so the backing storage
  remains live through the kernel access.

Do not use cgo: release builds set `CGO_ENABLED=0`. Do not fall back to the
request field or an external executable.

**Verify:** both CGO-disabled `go test -c` commands exit 0.

### Step 3: Prove live behavior, not just layout

Add Darwin-tagged tests that:

- resolve the current test process and equal `os.Getwd()`;
- start a child whose `Cmd.Dir` is a new temporary directory, keep it alive via
  a pipe, and resolve that exact directory;
- reject an impossible PID;
- reject a PID after a deliberately started child has exited;
- exercise the verifier's permission/error path where the host permits it,
  otherwise record why that OS-level case is not reproducible without
  weakening the test environment;
- exercise a path with spaces/non-ASCII characters;
- prove a reported/verified mismatch remains unbound.

The child test is the enforcement compatibility check required for an OS API;
a struct-size test alone is insufficient.

**Verify:** run the focused tests on this real Mac and record OS/build/arch.

### Step 4: Record the green-suite blind spot

Add a short GOTCHAS entry: what looked fine (grant approval and Linux tests),
what actually happened (Darwin treated verification failure as permission to
trust agent input), and the general rule (an unavailable verifier is not a
verified match; cross-platform authorization must fail closed and be live
tested on each backend). Cite the accepted menu-review ADR slug.

**Verify:** the entry is concise and contains no essay-like code comment.

### Step 5: Full relevant verification and commit

Run focused tests, race, vet, CGO-disabled cross-builds, and binary builds.
Write `handoffs/016.md`, acquire the commit lock, inspect staged paths, and
commit.

## Done criteria

- [ ] No verification error can bind a self-reported project path.
- [ ] Darwin resolves current and child CWD from the kernel on a real Mac.
- [ ] Invalid/partial/relative results fail closed.
- [ ] Nonexistent and exited PIDs fail; the permission/error path is exercised
  or explicitly blocked by the real host rather than mocked as success.
- [ ] arm64 and amd64 compile with `CGO_ENABLED=0`.
- [ ] Focused, race, vet, and binary build gates pass.
- [ ] GOTCHAS records the hidden failure shape.
- [ ] Only owned paths are in a signed local commit.

## STOP conditions

- The raw Darwin syscall cannot be proven against current SDK primary sources.
- Either CGO-disabled architecture does not compile.
- The live child-CWD test is flaky or returns a self-reported value.
- A correct fix requires cgo, a new dependency, shield session registration,
  or another architectural seam. Stop and request a follow-up ADR instead.
- Plan 015's accepted decision selects a different verified-binding mechanism.

## Maintenance notes

Review the syscall argument order and C layout closely. The fail-closed
decision is the durable security property; the OS resolver is what restores
functionality. Future Darwin SDK changes must trip tests rather than silently
reactivate the request-field fallback.
