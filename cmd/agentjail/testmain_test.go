package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// TestMain makes this test-runner process immune to SIGHUP and disables the
// real sighupDaemon implementation for all tests in this package.
//
// Under a parallel `go test ./...` run, tests in this package call
// runPolicyEnable / runPolicyDisable (and the MCP equivalents) which invoke
// sighupDaemonFn() to reload a live daemon after a policy change.  The real
// implementation uses `pgrep -f agentjail-daemon` which also matches the
// agentjail-daemon.test binary running concurrently — causing that test binary
// to receive a fatal SIGHUP (flaky "signal: hangup" failure).
//
// A no-op replacement is correct here: unit tests do not need an actual daemon
// to reload, and the sighup path is exercised by daemon-specific integration
// tests.
func TestMain(m *testing.M) {
	signal.Ignore(syscall.SIGHUP)

	// Replace the pgrep-based daemon-reload with a no-op for all tests.
	sighupDaemonFn = func() {}

	os.Exit(m.Run())
}
