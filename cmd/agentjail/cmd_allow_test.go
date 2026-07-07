package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/wire"
)

// fakeDaemonSocket is a minimal stand-in for the daemon's agent-reachable
// socket (daemon.sock, internal/wire) that only understands grant_request --
// the one verb runAllowHost sends. It binds at exactly the path
// wire.DefaultSocketPath() resolves to for the given home dir, so
// runAllowHost (which hardcodes wire.DefaultSocketPath()) finds it via $HOME
// alone, same pattern as fakeControlSocket in cmd_grants_test.go.
type fakeDaemonSocket struct {
	grantID string
	refuse  string
	lastReq grantctl.Request
	calls   int
}

func startFakeDaemonSocket(t *testing.T, home string, grantID, refuse string) *fakeDaemonSocket {
	t.Helper()
	dir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir daemon socket dir: %v", err)
	}
	sockPath := filepath.Join(dir, "daemon.sock")

	f := &fakeDaemonSocket{grantID: grantID, refuse: refuse}

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

func (f *fakeDaemonSocket) serve(conn net.Conn) {
	defer conn.Close()
	var req grantctl.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	f.calls++
	f.lastReq = req

	var resp grantctl.Response
	switch req.Type {
	case grantctl.ReqGrantRequest:
		if f.refuse != "" {
			resp = grantctl.Response{OK: false, Error: f.refuse}
		} else {
			resp = grantctl.Response{OK: true, GrantID: f.grantID}
		}
	default:
		resp = grantctl.Response{OK: false, Error: "unsupported request type in fake daemon socket"}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func TestRunAllowHost_PendingOnAccepted(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeDaemonSocket(t, home, "g-123", "")

	stdout, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", "need it for tests")
	})

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "pending human approval") {
		t.Errorf("stdout missing pending message: %q", stdout)
	}
	if !strings.Contains(stdout, "g-123") {
		t.Errorf("stdout missing grant_id: %q", stdout)
	}

	if fake.calls == 0 {
		t.Fatal("daemon socket was never called")
	}
	if fake.lastReq.Type != grantctl.ReqGrantRequest {
		t.Errorf("request type = %q, want grant_request", fake.lastReq.Type)
	}
	if fake.lastReq.Host != "api.example.com" {
		t.Errorf("host = %q, want api.example.com", fake.lastReq.Host)
	}
	if fake.lastReq.TTLMs != int64(3600000) {
		t.Errorf("ttl_ms = %d, want 3600000 (1h)", fake.lastReq.TTLMs)
	}
	if fake.lastReq.Reason != "need it for tests" {
		t.Errorf("reason = %q, want %q", fake.lastReq.Reason, "need it for tests")
	}
}

func TestRunAllowHost_ServerRefusal(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeDaemonSocket(t, home, "", "pending cap exceeded")

	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when the daemon refuses the request")
	}
	if !strings.Contains(stderr, "pending cap exceeded") {
		t.Errorf("stderr missing server message: %q", stderr)
	}
}

func TestRunAllowHost_NoDaemonRunning(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	// No fake daemon socket started -- wire.DefaultSocketPath() resolves
	// under an empty temp $HOME, so the dial must fail.

	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when no daemon socket exists")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestRunAllowHost_LocalValidationFailsBeforeNetwork(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeDaemonSocket(t, home, "g-xyz", "")

	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("not-a-valid-bare-hostname", "1h", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for a host that fails hostgrant.Validate")
	}
	if stderr == "" {
		t.Error("expected a validation error message on stderr")
	}
	if fake.calls != 0 {
		t.Errorf("daemon socket was called (%d times) even though local validation should have failed first", fake.calls)
	}
}

func TestRunAllowHost_InvalidTTL(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeDaemonSocket(t, home, "g-xyz", "")

	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "not-a-duration", "")
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an invalid --ttl")
	}
	if !strings.Contains(stderr, "ttl") {
		t.Errorf("stderr should mention ttl: %q", stderr)
	}
	if fake.calls != 0 {
		t.Errorf("daemon socket was called even though --ttl should have failed validation first")
	}
}

func TestRunAllowHost_ReasonTooLong(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	fake := startFakeDaemonSocket(t, home, "g-xyz", "")

	longReason := strings.Repeat("x", 257)
	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", longReason)
	})
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an over-long --reason")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
	if fake.calls != 0 {
		t.Errorf("daemon socket was called even though --reason should have failed validation first")
	}
}

// TestRunAllowHost_UsesWireDefaultSocketPath guards against a regression
// back to a hardcoded/HTTP address: it asserts runAllowHost dials exactly
// wire.DefaultSocketPath() by starting the fake socket at that exact path
// and confirming the round trip succeeds.
func TestRunAllowHost_UsesWireDefaultSocketPath(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	sockPath := wire.DefaultSocketPath()
	if !strings.HasPrefix(sockPath, home) {
		t.Fatalf("wire.DefaultSocketPath() = %q, want under HOME %q", sockPath, home)
	}
	startFakeDaemonSocket(t, home, "g-verify", "")

	_, stderr, code := captureOutput(t, func() int {
		return runAllowHost("api.example.com", "1h", "")
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
}
