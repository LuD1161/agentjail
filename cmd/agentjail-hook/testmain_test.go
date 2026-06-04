package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// TestMain makes this test-runner process immune to SIGHUP.
//
// Under a parallel `go test ./...` run, other package test binaries may
// inadvertently deliver SIGHUP to sibling processes (e.g. via pgrep-based
// daemon-reload helpers that match on a broad name pattern). The default
// SIGHUP disposition terminates the process, so ignoring it here removes
// that race without affecting any test assertions.
func TestMain(m *testing.M) {
	signal.Ignore(syscall.SIGHUP)
	os.Exit(m.Run())
}
