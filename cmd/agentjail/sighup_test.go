package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

// fakeControlDaemonSocket is a minimal stand-in for the daemon's
// agent-reachable socket (daemon.sock) that only understands
// wire.ControlType/wire.ControlOpReload -- the verb sighupDaemon's
// socket-first path sends. It binds at exactly wire.DefaultSocketPath() for
// the given home dir, same pattern as fakeDaemonSocket in cmd_allow_test.go.
type fakeControlDaemonSocket struct {
	ok      bool
	errMsg  string
	calls   int
	lastReq wire.ControlRequest
}

func startFakeControlDaemonSocket(t *testing.T, home string, ok bool, errMsg string) *fakeControlDaemonSocket {
	t.Helper()
	dir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir daemon socket dir: %v", err)
	}
	sockPath := filepath.Join(dir, "daemon.sock")

	f := &fakeControlDaemonSocket{ok: ok, errMsg: errMsg}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on fake daemon socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeControlDaemonSocket) serve(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	var req wire.ControlRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		return
	}
	f.calls++
	f.lastReq = req

	resp := wire.ControlResponse{OK: f.ok, Error: f.errMsg}
	_ = json.NewEncoder(conn).Encode(resp)
}

// TestSighupDaemon_ControlSocketSuccess verifies that when the daemon's
// control socket accepts the reload and reports ok=true, sighupDaemon
// completes quietly (no warning printed) via the socket path -- it never
// falls back to pgrep+SIGHUP.
func TestSighupDaemon_ControlSocketSuccess(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeControlDaemonSocket(t, home, true, "")

	_, stderr, _ := captureOutput(t, func() int {
		sighupDaemon()
		return 0
	})

	if fake.calls != 1 {
		t.Fatalf("expected exactly 1 control-socket call, got %d", fake.calls)
	}
	if fake.lastReq.Type != wire.ControlType || fake.lastReq.Op != wire.ControlOpReload {
		t.Errorf("request = %+v, want Type=%q Op=%q", fake.lastReq, wire.ControlType, wire.ControlOpReload)
	}
	if strings.Contains(stderr, "warning") {
		t.Errorf("expected no warning on stderr for a successful reload, got %q", stderr)
	}
}

// TestSighupDaemon_ControlSocketFailureSurfacesError verifies that when the
// daemon reports ok=false (e.g. a bad policy.yaml failed to compile),
// sighupDaemon surfaces the daemon's error message to the operator instead
// of silently doing nothing -- this is the core fix over pgrep+SIGHUP, which
// had no way to report back whether the reload actually took effect.
func TestSighupDaemon_ControlSocketFailureSurfacesError(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeControlDaemonSocket(t, home, false, "compile rego: unexpected token")

	_, stderr, _ := captureOutput(t, func() int {
		sighupDaemon()
		return 0
	})

	if fake.calls != 1 {
		t.Fatalf("expected exactly 1 control-socket call, got %d", fake.calls)
	}
	if !strings.Contains(stderr, "compile rego: unexpected token") {
		t.Errorf("stderr missing daemon error message: %q", stderr)
	}
}

// TestSighupDaemon_NoSocketFallsBackWithoutCrashing verifies that when no
// daemon socket exists (daemon not running, or a stale/missing socket file),
// sighupDaemon falls back to the pgrep+SIGHUP path without panicking. It
// cannot assert a running daemon was actually found (there usually isn't
// one in a test sandbox), only that the call completes safely.
func TestSighupDaemon_NoSocketFallsBackWithoutCrashing(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	// No fake daemon socket started -- wire.DefaultSocketPath() resolves
	// under an empty temp $HOME, so the dial must fail and sighupDaemon must
	// fall back to sighupDaemonViaSignal.

	captureOutput(t, func() int {
		sighupDaemon()
		return 0
	})
	// No assertion beyond "did not panic/hang" -- the fallback path's
	// own behavior (warn if daemon not running) is exercised indirectly;
	// pgrep may or may not find an unrelated process on the test box, but
	// either way sighupDaemon must return promptly.
}
