package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/LuD1161/agentjail/internal/ctlauth"
	"github.com/LuD1161/agentjail/internal/grantctl"
)

// fakeControlDaemonSocket is a minimal stand-in for the daemon's PRIVILEGED
// control socket (daemon-ctl.sock) that only understands
// grantctl.ReqDaemonReload -- the verb sighupDaemon's socket-first path sends.
// It binds at exactly grantctl.ControlSocketPathForHome(home).
//
// It deliberately does NOT bind daemon.sock: reload moved off the agent-facing
// socket because the sandboxed agent can reach that one by design (ADR 0066).
// A fake listening on the wrong socket would let a regression pass.
type fakeControlDaemonSocket struct {
	mu      sync.Mutex
	ok      bool
	errMsg  string
	calls   int
	lastReq grantctl.Request
}

func (f *fakeControlDaemonSocket) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeControlDaemonSocket) request() grantctl.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func startFakeControlDaemonSocket(t *testing.T, home string, ok bool, errMsg string) *fakeControlDaemonSocket {
	t.Helper()
	sockPath := grantctl.ControlSocketPathForHome(home)
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o700); err != nil {
		t.Fatalf("mkdir control socket dir: %v", err)
	}

	// Callers set HOME to this dir, so Ensure writes the token where the CLI
	// under test will look for it -- the same handoff a real daemon performs.
	if _, err := ctlauth.Ensure(); err != nil {
		t.Fatalf("mint control token: %v", err)
	}

	f := &fakeControlDaemonSocket{ok: ok, errMsg: errMsg}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on fake control socket: %v", err)
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

	var req grantctl.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	f.mu.Lock()
	f.calls++
	f.lastReq = req
	ok, errMsg := f.ok, f.errMsg
	f.mu.Unlock()

	_ = json.NewEncoder(conn).Encode(grantctl.Response{OK: ok, Error: errMsg})
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

	if got := fake.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 control-socket call, got %d", got)
	}
	if got := fake.request().Type; got != grantctl.ReqDaemonReload {
		t.Errorf("request type = %q, want %q", got, grantctl.ReqDaemonReload)
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

	if got := fake.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 control-socket call, got %d", got)
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
