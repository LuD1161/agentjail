package ui

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// TestMain installs two SIGHUP safeguards before running any test in this
// package:
//
//  1. signal.Ignore(syscall.SIGHUP) — makes this test-runner process immune
//     to SIGHUP, which can be delivered by concurrent test packages (e.g. if
//     another test binary happens to have "ui" or "agentjail" in its path and
//     is targeted by a broad pgrep pattern).
//
//  2. Replace sighupDaemonFn with a no-op — the handler tests (e.g.
//     TestPolicyEnableEndpoint) trigger handlePolicyEnable, which calls
//     sighupDaemonFn() to reload the daemon after a policy change.  Under
//     `go test ./...`, the agentjail-daemon test binary is also running and
//     its path contains "agentjail-daemon", so the real sighupDaemon()
//     implementation (which uses `pgrep -f agentjail-daemon`) would find and
//     SIGHUP that test binary — killing it with a flaky "signal: hangup"
//     failure.  A no-op here is correct for tests: no real daemon is running
//     and no reload is needed.
func TestMain(m *testing.M) {
	signal.Ignore(syscall.SIGHUP)

	// Replace the real sighupDaemon with a no-op for all tests in this
	// package. The real implementation is tested end-to-end in integration
	// tests; unit tests only need to verify that the handler calls through.
	sighupDaemonFn = func() {}

	os.Exit(m.Run())
}
