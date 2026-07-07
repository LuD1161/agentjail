package main

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/grantctl"
)

type fakeGrantCtlSocket struct {
	pending map[string]grantctl.GrantInfo
}

func shortHomeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ajgrant")
	if err != nil {
		t.Fatalf("create short temp home dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startFakeGrantCtlSocket(t *testing.T, home string, grants []grantctl.GrantInfo) *fakeGrantCtlSocket {
	t.Helper()
	dir := grantctl.ControlSocketDirForHome(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir control socket dir: %v", err)
	}
	sockPath := grantctl.ControlSocketPathForHome(home)
	f := &fakeGrantCtlSocket{pending: make(map[string]grantctl.GrantInfo)}
	for _, g := range grants {
		f.pending[g.GrantID] = g
	}
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

func (f *fakeGrantCtlSocket) serve(conn net.Conn) {
	defer conn.Close()
	var req grantctl.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	var resp grantctl.Response
	switch req.Type {
	case grantctl.ReqGrantList:
		list := make([]grantctl.GrantInfo, 0, len(f.pending))
		for _, g := range f.pending {
			list = append(list, g)
		}
		resp = grantctl.Response{OK: true, Grants: list}
	case grantctl.ReqGrantApprove:
		if _, ok := f.pending[req.GrantID]; ok {
			delete(f.pending, req.GrantID)
			resp = grantctl.Response{OK: true}
		} else {
			resp = grantctl.Response{OK: false, Error: "unknown grant_id"}
		}
	case grantctl.ReqGrantDeny:
		if _, ok := f.pending[req.GrantID]; ok {
			delete(f.pending, req.GrantID)
			resp = grantctl.Response{OK: true}
		} else {
			resp = grantctl.Response{OK: false, Error: "unknown grant_id"}
		}
	default:
		resp = grantctl.Response{OK: false, Error: "unsupported request type"}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func TestRunGrantsList_NoPending(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, nil)
	stdout, stderr, code := captureOutput(t, runGrantsList)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "no pending grant requests") {
		t.Errorf("stdout = %q, want a no-pending message", stdout)
	}
}

func TestRunGrantsList_ListsPending(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, []grantctl.GrantInfo{
		{GrantID: "g-1", Host: "api.example.com", TTLMs: 3600000, CWD: "/repo/one", Reason: "need it"},
	})
	stdout, stderr, code := captureOutput(t, runGrantsList)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	for _, want := range []string{"g-1", "api.example.com", "/repo/one", "need it"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunGrantsList_NoDaemonRunning(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	_, stderr, code := captureOutput(t, runGrantsList)
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when no daemon control socket exists")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestRunGrantDeny(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, []grantctl.GrantInfo{
		{GrantID: "g-deny", Host: "deny.example.com", TTLMs: 60000},
	})
	stdout, stderr, code := captureOutput(t, func() int { return runGrantDeny("g-deny") })
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "denied") {
		t.Errorf("stdout = %q, want a denied confirmation", stdout)
	}
}

func TestRunGrantDeny_UnknownID(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, nil)
	_, stderr, code := captureOutput(t, func() int { return runGrantDeny("does-not-exist") })
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an unknown grant_id")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestRunGrantApprove(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, []grantctl.GrantInfo{
		{GrantID: "g-approve", Host: "approve.example.com", TTLMs: 60000},
	})
	stdout, stderr, code := captureOutput(t, func() int { return runGrantApprove("g-approve") })
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "approved") {
		t.Errorf("stdout = %q, want an approved confirmation", stdout)
	}
}

func TestRunGrantApprove_UnknownID(t *testing.T) {
	home := shortHomeDir(t)
	t.Setenv("HOME", home)
	startFakeGrantCtlSocket(t, home, nil)
	_, stderr, code := captureOutput(t, func() int { return runGrantApprove("does-not-exist") })
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when the grant_id does not exist")
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}
