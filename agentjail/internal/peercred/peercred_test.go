package peercred

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGet_SelfConnect dials a Unix-domain socket from the test process
// and asserts the daemon-side Accept'd conn reports our PID via
// peercred.Get. Validates that LOCAL_PEERPID (macOS) / SO_PEERCRED
// (Linux) returns the IMMEDIATE peer — not the listener's PID, which
// is a common implementation mistake.
func TestGet_SelfConnect(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("peercred not implemented on %s", runtime.GOOS)
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Logf("accept: %v", err)
			close(accepted)
			return
		}
		accepted <- c
	}()
	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	serverConn := <-accepted
	if serverConn == nil {
		t.Fatal("accept failed")
	}
	defer serverConn.Close()

	creds, err := Get(serverConn)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if creds.PID != os.Getpid() {
		t.Errorf("peer PID = %d, want self %d", creds.PID, os.Getpid())
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Errorf("peer UID = %d, want self %d", creds.UID, os.Getuid())
	}
}

func TestGet_NotUnixConn(t *testing.T) {
	// A pipe pair is a net.Conn but not a *UnixConn — must return
	// ErrNotUnixConn rather than panic.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_, err := Get(c1)
	if !errors.Is(err, ErrNotUnixConn) {
		t.Errorf("expected ErrNotUnixConn, got %v", err)
	}
}
