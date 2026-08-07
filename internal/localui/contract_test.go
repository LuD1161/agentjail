package localui

import (
	"net"
	"testing"
	"time"
)

func TestDefaultURLDerivesFromAddr(t *testing.T) {
	if got, want := DefaultURL, "http://"+DefaultAddr; got != want {
		t.Fatalf("DefaultURL = %q, want %q", got, want)
	}
}

func TestReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if !Reachable(ln.Addr().String(), 100*time.Millisecond) {
		t.Fatal("live listener reported unreachable")
	}
	closed := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if Reachable(closed, 20*time.Millisecond) {
		t.Fatal("closed listener reported reachable")
	}
}
