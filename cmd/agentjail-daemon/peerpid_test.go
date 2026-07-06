package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

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
