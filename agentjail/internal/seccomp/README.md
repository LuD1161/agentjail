# agentjail/internal/seccomp

Default-deny seccomp-BPF filter for the guest agent process inside an
agentjail Linux microVM.

- **Allowlist** in `profile.go::Baseline` — every entry annotated with
  WHY (one-line justification) and OBS (where in a real strace we saw
  it: Claude, Claude+tool, Codex/Aider, Go runtime, libc bring-up).
- **Filter compiler** in `profile_linux.go` — raw BPF bytecode + two
  `prctl(2)` calls. **No `libseccomp`, no cgo.** See
  `../../docs/DECISIONS.md` (seccomp design entry) for the libseccomp-vs-raw
  trade-off.
- **Cross-arch syscall tables** in `tables_linux_amd64.go` /
  `tables_linux_arm64.go` (with a sentinel `tables_linux_other.go`
  for any future Linux GOARCH).
- **Coverage tests** in `profile_test.go` — platform-independent; run
  on macOS too. The strace validator (`TestStraceValidate`) replays
  `testdata/claude-strace.txt` and fails if any observed syscall is
  missing from the allowlist.

## Quick reference

```go
import "github.com/LuD1161/agentjail/agentjail/internal/seccomp"

func main() {
    if err := seccomp.Default().Apply(); err != nil {
        log.Fatalf("seccomp: %v", err)
    }
    // agent code from here on runs under the filter
}
```

`Apply` returns `seccomp.ErrUnsupported` on non-Linux platforms; the
agentjail host MUST check the error and refuse to run an "enforced"
guest off-Linux.

## Verifying on a real Linux host

The default `go test ./...` runs on any platform and exercises the
allowlist coverage, typo detection, and BPF program emission — but
does NOT install the filter (which would risk killing the test
runner). The end-to-end install-and-survive verifier is a separate
harness intended for a disposable Linux CI runner.

### Verifier (run inside a throwaway container)

```sh
# 1. Pick a Linux runner with kernel >= 5.8 (faccessat2 is the floor).
docker run --rm -it -v $PWD:/src -w /src golang:1.22 bash

# 2. Run the in-process tests.
go test ./agentjail/internal/seccomp/...

# 3. The kernel-live smoke check is intentionally Skip'd by default —
#    edit profile_linux_test.go::TestApplySmoke to remove the
#    t.Skip line, or promote it to an env-guarded run via a follow-up
#    patch. Not enabled by default because the test installs a seccomp
#    filter on the test runner process (survivable but one-way).

# 4. Negative test (must crash with SIGSYS):
cat > /tmp/deny.go <<'EOF'
package main
import (
  "fmt"
  "syscall"
  "github.com/LuD1161/agentjail/agentjail/internal/seccomp"
)
func main() {
  if err := seccomp.Default().Apply(); err != nil { panic(err) }
  // ptrace is NOT on the allowlist -> SIGSYS, exit 159.
  syscall.Syscall6(syscall.SYS_PTRACE, 0, 0, 0, 0, 0, 0)
  fmt.Println("should never print")
}
EOF
go run /tmp/deny.go; echo "exit=$?"
# Expected: exit=159 (128 + SIGSYS=31)
```

The macOS workstation cannot run step 4 — that's why the
`profile_linux.go` file is build-tagged. macOS `go build ./...` still
compiles `profile_other.go`, which returns `ErrUnsupported`.

## When you find a missing syscall in production

1. Capture a strace of the failing run.
2. Add the syscall name to **both** `Baseline` (with a WHY + OBS) and,
   if it's net-new across all arches, `KnownNames`.
3. Add the line to `testdata/claude-strace.txt`.
4. Append an entry to `agentjail/docs/DECISIONS.md` explaining why the
   syscall is safe to allow (not just that the agent needs it).
5. Commit as `feat(agentjail/seccomp): allow <syscall> for <reason>`.

## What this filter does NOT defend against

- **Argument-level abuse.** Every `ioctl` is allowed regardless of
  request code; every `socket(AF_*, …)` regardless of family; every
  `mmap` regardless of `PROT_*` flags. Per-arg filtering is a follow-up
  task (tracked in DECISIONS.md). Today we lean on the microVM
  containment + eBPF LSM for that layer.
- **Side-channel data exfil.** The allowlist contains `socket` /
  `connect` / `sendto` so the agent can talk to the LLM API; nothing
  here stops the agent from sending stolen data to it. That's the
  responsibility of the redactor (`agentjail/internal/redactor`).
- **Privilege escalation outside the kernel.** Seccomp filters syscalls
  only; userspace-only attacks (memory corruption inside the agent
  process) are out of scope.
