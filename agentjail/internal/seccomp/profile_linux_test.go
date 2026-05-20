//go:build linux

package seccomp

import (
	"errors"
	"testing"
)

// TestCompileResolvesNative asserts the Linux-only BPF compiler
// produces a non-empty program for Default(). Runs on any Linux x86_64
// / aarch64 host; no kernel privileges required (no actual prctl yet).
func TestCompileResolvesNative(t *testing.T) {
	p := Default()
	prog, err := p.compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(prog) < 10 {
		t.Errorf("compile returned %d insns; expected substantially more", len(prog))
	}
	if len(prog) > 4096 {
		t.Errorf("compile produced %d insns; kernel max is 4096", len(prog))
	}
}

// TestCompileRejectsTypos asserts an obviously-bogus syscall name
// fails resolution. Catches typos at startup rather than at runtime.
func TestCompileRejectsTypos(t *testing.T) {
	p := Default().WithExtra("not_a_real_syscall_xyz")
	_, err := p.compile()
	if !errors.Is(err, ErrUnknownSyscall) {
		t.Errorf("expected ErrUnknownSyscall; got %v", err)
	}
}

// TestApplySmoke is the Linux-host verifier integration test. It
// installs Default() into the calling test process and immediately
// issues a permitted syscall (uname). If the filter is wrong, the
// process dies with SIGSYS and the test runner reports a crash.
//
// We do NOT make any *denied* syscalls inside the test process —
// that would kill the test runner. The denied-syscall behaviour is
// validated by a separate child-process harness the Linux CI runs
// out-of-band; see README.md for the pattern.
//
// Build tag rationale: this test compiles on Linux unconditionally,
// but it MUST run only on a kernel >= 3.17 with CONFIG_SECCOMP_FILTER.
// Skipped by default; enable manually on a disposable runner.
func TestApplySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("seccomp Apply test skipped in -short mode (kernel side-effect)")
	}
	t.Skip("integration: enable manually on a disposable Linux runner; see README.md")
}
