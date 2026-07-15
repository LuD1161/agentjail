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
