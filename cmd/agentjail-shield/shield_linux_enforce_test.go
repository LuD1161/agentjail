//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain dispatches child-mode execution when AGENTJAIL_LANDLOCK_CHILD=1.
// Landlock is irreversible — we cannot restrict the test process itself and
// then continue running other tests.  Instead, we re-exec a child process
// that applies Landlock, performs the enforcement probes, and exits.
func TestMain(m *testing.M) {
	// Ignore SIGHUP so a concurrent pgrep-based daemon-reload helper in
	// another test package cannot terminate this test runner.
	signal.Ignore(syscall.SIGHUP)

	if os.Getenv("AGENTJAIL_LANDLOCK_CHILD") == "1" {
		runLandlockChild()
		// runLandlockChild always calls os.Exit; this is unreachable.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runLandlockChild applies Landlock and probes two paths:
//   - A fresh directory under /tmp (rw-allowed) — write must succeed.
//   - A file at the home directory root (ro-allowed) — write must be denied.
//
// Results are printed one per line as "tmp=ok", "tmp=ERR:<msg>",
// "home=EACCES", "home=ok", or "home=ERR:<msg>".
func runLandlockChild() {
	// Apply Landlock with nil config (no extra_allow entries).
	if err := applyLandlock(nil); err != nil {
		fmt.Fprintf(os.Stdout, "applyLandlock failed: %v\n", err)
		os.Exit(1)
	}

	// Probe 1: write a file inside a fresh /tmp sub-directory (rw-allowed).
	tmpDir, err := os.MkdirTemp("", "ajll")
	if err != nil {
		fmt.Fprintf(os.Stdout, "tmp=ERR:MkdirTemp:%v\nhome=ERR:skipped\n", err)
		os.Exit(0)
	}
	tmpFile := filepath.Join(tmpDir, "probe.txt")
	if err := os.WriteFile(tmpFile, []byte("ok"), 0600); err != nil {
		fmt.Fprintf(os.Stdout, "tmp=ERR:%v\n", err)
	} else {
		fmt.Fprintln(os.Stdout, "tmp=ok")
	}

	// Probe 2: write a file at the home root (ro-allowed — write must be denied).
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stdout, "home=ERR:no-home")
		os.Exit(0)
	}
	deniedPath := filepath.Join(home, fmt.Sprintf(".agentjail-landlock-denied-probe-%d", os.Getpid()))
	werr := os.WriteFile(deniedPath, []byte("should-be-denied"), 0600)
	if werr == nil {
		// Write succeeded — sandbox did not block it.
		_ = os.Remove(deniedPath)
		fmt.Fprintln(os.Stdout, "home=ok")
	} else if errors.Is(werr, unix.EACCES) {
		fmt.Fprintln(os.Stdout, "home=EACCES")
	} else {
		fmt.Fprintf(os.Stdout, "home=ERR:%v\n", werr)
	}

	os.Exit(0)
}

// TestLandlockEnforcement verifies that Landlock allows writes under /tmp and
// denies writes at the home-directory root.
//
// The test re-execs itself as a child process (env AGENTJAIL_LANDLOCK_CHILD=1)
// so that Landlock's irreversible restriction does not affect the parent test
// process or sibling tests.
func TestLandlockEnforcement(t *testing.T) {
	// Probe kernel Landlock support.
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		t.Skip("landlock unsupported on this kernel")
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("cannot determine home directory")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot determine cwd")
	}

	deniedPath := filepath.Join(home, fmt.Sprintf(".agentjail-landlock-denied-probe-%d", os.Getpid()))

	// Guard against false-pass: if home overlaps /tmp or cwd, the Landlock
	// deny we rely on may not fire (home is under an rw-allowed subtree).
	if strings.HasPrefix(deniedPath, "/tmp") ||
		strings.HasPrefix(deniedPath, cwd+string(os.PathSeparator)) ||
		deniedPath == cwd {
		t.Skip("home overlaps cwd/tmp; cannot isolate landlock denial")
	}

	// Re-exec self as child with env flag set.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "AGENTJAIL_LANDLOCK_CHILD=1")
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("child process failed: %v\noutput:\n%s", err, output)
	}

	if !strings.Contains(output, "tmp=ok") {
		t.Errorf("expected tmp=ok in child output, got:\n%s", output)
	}
	if !strings.Contains(output, "home=EACCES") {
		t.Errorf("expected home=EACCES in child output (Landlock did not deny home write), got:\n%s", output)
	}
}
