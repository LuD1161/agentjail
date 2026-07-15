package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// daemonSocketHome points HOME at a short-lived directory and returns the
// daemon socket path underneath it. Not t.TempDir(): its paths can exceed the
// ~108-byte AF_UNIX sun_path limit and fail the bind for unrelated reasons.
func daemonSocketHome(t *testing.T) string {
	t.Helper()

	home, err := os.MkdirTemp("", "aj")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })

	if err := os.MkdirAll(filepath.Join(home, ".agentjail"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HOME", home)

	return filepath.Join(home, ".agentjail", "daemon.sock")
}

// TestIsDaemonRunning_NoSocket: nothing ever listened, no socket file.
func TestIsDaemonRunning_NoSocket(t *testing.T) {
	daemonSocketHome(t)

	if isDaemonRunning() {
		t.Error("expected false when the daemon socket does not exist")
	}
}

// TestIsDaemonRunning_StaleSocket guards the dial-vs-stat decision (ADR 0061):
// a crashed daemon leaves its socket file behind, and only a dial catches it.
func TestIsDaemonRunning_StaleSocket(t *testing.T) {
	sock := daemonSocketHome(t)

	// Bind, then close WITHOUT unlinking, leaving the file on disk with no
	// listener behind it -- what an unclean daemon exit leaves. Go's
	// UnixListener unlinks on Close by default, which would erase the very
	// state under test, hence SetUnlinkOnClose(false).
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	l.SetUnlinkOnClose(false)
	_ = l.Close()

	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("test setup: socket file should still exist: %v", err)
	}

	if isDaemonRunning() {
		t.Error("expected false for a stale socket file with no listener behind it")
	}
}

// TestIsDaemonRunning_LiveListener: a hand-started daemon that no service
// manager owns still reports running (ADR 0061).
func TestIsDaemonRunning_LiveListener(t *testing.T) {
	sock := daemonSocketHome(t)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	if !isDaemonRunning() {
		t.Error("expected true while a listener is accepting on the daemon socket")
	}
}
