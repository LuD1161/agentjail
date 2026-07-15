package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWaitForDaemonStop_AlreadyStopped: no socket, so nothing to wait for. Must
// return promptly rather than burning the whole deadline.
func TestWaitForDaemonStop_AlreadyStopped(t *testing.T) {
	home, err := os.MkdirTemp("", "aj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".agentjail"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	start := time.Now()
	if stillRunning := waitForDaemonStop(2 * time.Second); stillRunning {
		t.Error("expected stopped when no socket exists")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("should return immediately, took %v", elapsed)
	}
}

// TestWaitForDaemonStop_StillListening is the case that made uninstall lie: a
// daemon the service manager does not own survives the stop and keeps
// answering. Uninstall must detect that instead of reporting success, because
// the surviving daemon's hookwatch re-injects the hooks it just removed
// (ADR 0065).
func TestWaitForDaemonStop_StillListening(t *testing.T) {
	home, err := os.MkdirTemp("", "aj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".agentjail"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	l, err := net.Listen("unix", filepath.Join(home, ".agentjail", "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	if stillRunning := waitForDaemonStop(300 * time.Millisecond); !stillRunning {
		t.Error("a live listener must be reported as still running")
	}
}

// TestFullUninstall_AbortsWhileDaemonAlive is the regression for the bug this
// whole ADR exists for: with a daemon still answering, hookwatch re-injects
// every hook the teardown removes, so uninstall must abort untouched rather
// than delete agentjail and leave the agents wired to a deleted binary.
func TestFullUninstall_AbortsWhileDaemonAlive(t *testing.T) {
	home, err := os.MkdirTemp("", "aj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })

	binDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A marker file standing in for the install: it must survive the abort.
	marker := filepath.Join(home, ".agentjail", "policy.yaml")
	if err := os.WriteFile(marker, []byte("mcp: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	l, err := net.Listen("unix", filepath.Join(home, ".agentjail", "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	r := performFullUninstall(home, "linux", false, false)

	if !r.Aborted {
		t.Error("expected the run to abort while the daemon is alive")
	}
	if !r.DaemonStillRunning || !r.HardFailed {
		t.Errorf("expected a hard failure naming the live daemon, got %+v", r)
	}
	if len(r.Agents) != 0 {
		t.Errorf("no agent may be unhooked before the daemon is down, got %+v", r.Agents)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("aborted uninstall must leave the install intact: %v", err)
	}
}

// TestFullUninstall_ForceProceedsPastLiveDaemon: --force is the escape hatch for
// a daemon that cannot be killed, so uninstall is never a trap.
func TestFullUninstall_ForceProceedsPastLiveDaemon(t *testing.T) {
	home, err := os.MkdirTemp("", "aj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".agentjail", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	l, err := net.Listen("unix", filepath.Join(home, ".agentjail", "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	r := performFullUninstall(home, "linux", false, true)

	if r.Aborted {
		t.Error("--force must not abort")
	}
	if !r.DaemonStillRunning {
		t.Error("--force must still report the surviving daemon")
	}
	if _, err := os.Stat(filepath.Join(home, ".agentjail")); !os.IsNotExist(err) {
		t.Errorf("--force must complete the teardown, ~/.agentjail still present: %v", err)
	}
}
