//go:build linux

package netns

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// hardenChildEnv, when set, turns this test binary into a one-shot child that
// calls ApplyHardening and encodes the result in its exit code. This keeps the
// (irreversible) hardening confined to a forked process so it never wrecks the
// parent test process.
const hardenChildEnv = "AGENTJAIL_HARDEN_CHILD"

const (
	hardenExitOK    = 0 // ApplyHardening returned nil
	hardenExitOther = 1 // ApplyHardening returned a non-permission error
	hardenExitPerm  = 3 // ApplyHardening failed with EPERM (insufficient caps)
)

// TestMain intercepts the child re-exec before the normal test runner starts.
func TestMain(m *testing.M) {
	if os.Getenv(hardenChildEnv) == "1" {
		switch err := ApplyHardening(); {
		case err == nil:
			os.Exit(hardenExitOK)
		case errors.Is(err, unix.EPERM):
			os.Exit(hardenExitPerm)
		default:
			os.Exit(hardenExitOther)
		}
	}
	os.Exit(m.Run())
}

// TestHardenSecurebitsMask verifies the computed securebits bitmask matches the
// canonical value from <linux/securebits.h> without touching process state.
func TestHardenSecurebitsMask(t *testing.T) {
	const want = 0x2f // NOROOT|NOROOT_LOCKED|NO_SETUID_FIXUP|NO_SETUID_FIXUP_LOCKED|KEEP_CAPS_LOCKED
	if hardenSecurebits != want {
		t.Fatalf("hardenSecurebits = 0x%x, want 0x%x", hardenSecurebits, want)
	}
}

// TestApplyHardeningInChild runs ApplyHardening in a forked copy of the test
// binary so the irreversible lockdown does not affect this process.
func TestApplyHardeningInChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=NoSuchTest")
	cmd.Env = append(os.Environ(), hardenChildEnv+"=1")
	out, err := cmd.CombinedOutput()

	code := cmd.ProcessState.ExitCode()
	switch code {
	case hardenExitOK:
		// Success: hardening applied cleanly in the child.
		if err != nil {
			t.Fatalf("child exited 0 but err = %v", err)
		}
	case hardenExitPerm:
		t.Skipf("ApplyHardening needs privileges unavailable here (EPERM); output: %s", out)
	case hardenExitOther:
		t.Fatalf("ApplyHardening failed in child (exit %d); output: %s", code, out)
	default:
		t.Fatalf("unexpected child exit code %d (err=%v); output: %s", code, err, out)
	}
}
