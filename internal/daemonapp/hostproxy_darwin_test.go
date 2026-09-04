//go:build darwin

package daemonapp

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/hostproxy"
	"github.com/LuD1161/agentjail/internal/store"
)

func TestDarwinHostProxyHandlerExecutesExactApprovedRequest(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(cwd, "benign-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s' \"$1\"\nprintf err >&2\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := hostproxy.Target{Executable: helper, Argv: []string{"benign-helper", "literal;$(nope)|*"}}
	manager := hostproxy.NewManager(nil, time.Minute)
	auth, err := manager.Issue(hostproxy.Authorization{
		SessionID: "session", Target: target, CWD: cwd, Root: cwd, Path: cwd,
		Reason: "inspect the requested local file", BrokerPID: os.Getpid(), FreshAfter: 1,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(cwd, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tracker := newActiveTracker(cwd)
	tracker.sessions["session"] = &sessionState{PID: os.Getpid(), CWD: cwd, Root: cwd, Path: cwd, LaunchPID: os.Getpid()}
	srv := &server{hostProxyApprovals: manager, hostProxyExecutor: hostproxy.NewExecutor(), activeSessions: tracker, eventStore: st}

	response := runDarwinHostProxyHandler(t, srv, hostproxy.WireRequest{
		Type: hostproxy.RequestType, Request: hostproxy.Request{Proof: auth.Proof, Target: target, Reason: auth.Reason, CWD: cwd},
	})
	if !response.OK || response.Result.ExitCode != 42 || string(response.Result.Stdout) != "literal;$(nope)|*" || string(response.Result.Stderr) != "err" {
		t.Fatalf("response = %+v", response)
	}
}

func runDarwinHostProxyHandler(t *testing.T, srv *server, request hostproxy.WireRequest) hostproxy.WireResponse {
	t.Helper()
	socketDir, err := os.MkdirTemp("/tmp", "ajhp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	listener, err := net.Listen("unix", filepath.Join(socketDir, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		line, readErr := bufio.NewReader(conn).ReadBytes('\n')
		if readErr == nil {
			srv.handleHostProxyExec(context.Background(), conn, json.NewEncoder(conn), line)
		}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response hostproxy.WireResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	<-done
	return response
}
