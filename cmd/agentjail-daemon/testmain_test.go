package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

// TestMain makes the test-runner process immune to SIGHUP.
//
// The reload tests (TestDaemon_SIGHUP*) spawn daemon subprocesses in their own
// process groups (SysProcAttr.Setpgid) and send them SIGHUP to exercise hot
// reload. Each daemon-under-test installs and handles SIGHUP itself. The test
// runner, however, has no legitimate reason to react to SIGHUP — yet the default
// disposition is to terminate, so a stray signal reaching this process group
// under a parallel `go test ./...` run would kill the runner with a flaky
// "signal: hangup" failure. Ignoring SIGHUP here removes that race without
// changing any product behavior (the daemon processes are separate).
func TestMain(m *testing.M) {
	signal.Ignore(syscall.SIGHUP)
	os.Exit(m.Run())
}
