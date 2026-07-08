package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// errPeerUIDTest is a sentinel error used only to exercise the fail-closed
// branch of peerUIDAllowed in tests.
var errPeerUIDTest = errors.New("simulated extractPeerUID failure")

// TestExtractPeerPID verifies that extractPeerPID reports the PID of the
// connecting process. Since both ends of the socket pair are opened by this
// test process, the expected peer PID is the current process's own PID.
func TestExtractPeerPID(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		pid int
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{0, err}
			return
		}
		defer conn.Close()
		pid, err := extractPeerPID(conn)
		done <- result{pid, err}
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	res := <-done
	if res.err != nil {
		t.Fatalf("extractPeerPID: %v", res.err)
	}
	if res.pid != os.Getpid() {
		t.Errorf("expected peer pid %d, got %d", os.Getpid(), res.pid)
	}
}

// TestExtractPeerPID_NotUnixConn verifies that extractPeerPID rejects
// non-Unix-domain connections (e.g. TCP).
func TestExtractPeerPID_NotUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, err = extractPeerPID(conn)
		done <- err
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err == nil {
		t.Errorf("expected error for non-unix connection, got nil")
	}
}

// TestExtractPeerUID verifies that extractPeerUID reports the UID of the
// connecting process. Both ends of the socket pair are opened by this test
// process, so the expected peer UID is the current process's own UID (P5).
func TestExtractPeerUID(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		uid int
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{0, err}
			return
		}
		defer conn.Close()
		uid, err := extractPeerUID(conn)
		done <- result{uid, err}
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	res := <-done
	if res.err != nil {
		t.Fatalf("extractPeerUID: %v", res.err)
	}
	if res.uid != os.Getuid() {
		t.Errorf("expected peer uid %d, got %d", os.Getuid(), res.uid)
	}
}

// TestExtractPeerUID_NotUnixConn verifies that extractPeerUID rejects
// non-Unix-domain connections (e.g. TCP) — the fail-closed path exercised by
// peerUIDAllowed when uidErr != nil.
func TestExtractPeerUID_NotUnixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, err = extractPeerUID(conn)
		done <- err
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err == nil {
		t.Errorf("expected error for non-unix connection, got nil")
	}
}

// TestPeerUIDAllowed covers the UID-compare gate (P5) in isolation, without
// needing to actually run as a second UID (not available in CI/sandboxes).
func TestPeerUIDAllowed(t *testing.T) {
	cases := []struct {
		name      string
		peerUID   int
		daemonUID int
		uidErr    error
		want      bool
	}{
		{"same uid allowed", 1000, 1000, nil, true},
		{"different uid rejected", 1001, 1000, nil, false},
		{"root peer against non-root daemon rejected", 0, 1000, nil, false},
		{"extract error fails closed even if uids happen to match", 1000, 1000, errPeerUIDTest, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := peerUIDAllowed(tc.peerUID, tc.daemonUID, tc.uidErr)
			if got != tc.want {
				t.Errorf("peerUIDAllowed(%d, %d, %v) = %v, want %v", tc.peerUID, tc.daemonUID, tc.uidErr, got, tc.want)
			}
		})
	}
}
