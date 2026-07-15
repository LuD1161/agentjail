//go:build linux

package daemonapp

import (
	"os"
	"testing"
)

// TestResolvePeerCWD_Self verifies that resolvePeerCWD reports the current
// process's own working directory when asked to resolve its own PID (P10).
func TestResolvePeerCWD_Self(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	got, err := resolvePeerCWD(os.Getpid())
	if err != nil {
		t.Fatalf("resolvePeerCWD: %v", err)
	}
	if got != want {
		t.Errorf("resolvePeerCWD(self) = %q, want %q", got, want)
	}
}

// TestResolvePeerCWD_NoSuchPID verifies resolvePeerCWD fails (rather than
// silently returning an empty/zero-value CWD) for a PID that cannot possibly
// exist, so callers using decideBoundCWD can rely on a non-nil error meaning
// "unverifiable" rather than "verified empty".
func TestResolvePeerCWD_NoSuchPID(t *testing.T) {
	// PID 2^30 is far beyond any realistic pid_max and cannot be a live
	// process; /proc/<pid> will not exist.
	const impossiblePID = 1 << 30
	if _, err := resolvePeerCWD(impossiblePID); err == nil {
		t.Errorf("expected error resolving CWD for nonexistent pid %d, got nil", impossiblePID)
	}
}
