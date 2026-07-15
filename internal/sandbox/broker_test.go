package sandbox

import (
	"net"
	"path/filepath"
	"testing"
)

// TestEnsureSecretsBroker_AlreadyListening: when the broker is already up,
// EnsureSecretsBroker is a fast no-op and never tries to start anything.
func TestEnsureSecretsBroker_AlreadyListening(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "secrets.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot bind unix socket in this environment: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	if err := EnsureSecretsBroker(sock); err != nil {
		t.Fatalf("EnsureSecretsBroker should no-op when the socket already listens, got: %v", err)
	}
}

// TestBrokerReachable_FalseWhenAbsent: a missing socket is reported unreachable
// (and, in EnsureSecretsBroker, would trigger a start attempt).
func TestBrokerReachable_FalseWhenAbsent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nope.sock")
	if brokerReachable(sock, 100_000_000 /*100ms*/) {
		t.Fatal("brokerReachable returned true for a nonexistent socket")
	}
}
