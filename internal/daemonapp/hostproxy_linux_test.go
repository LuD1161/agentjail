//go:build linux

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

func TestHostProxyHandlerExecutesExactApprovedRequest(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	helper := filepath.Join(dir, "benign-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf started > \"$2\"\nprintf '%s' \"$1\"\nprintf err >&2\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := hostproxy.Target{Executable: helper, Argv: []string{"benign-helper", "literal;$(nope)|*", marker}}
	manager := hostproxy.NewManager(nil, time.Minute)
	auth, err := manager.Issue(hostproxy.Authorization{
		SessionID: "session", Target: target, CWD: cwd, Root: cwd, Path: filepath.Dir(helper),
		BrokerPID: os.Getpid(), FreshAfter: 1,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tracker := newActiveTracker(dir)
	tracker.sessions["session"] = &sessionState{PID: os.Getpid(), CWD: cwd, Root: cwd, Path: filepath.Dir(helper), LaunchPID: os.Getpid()}
	srv := &server{hostProxyApprovals: manager, hostProxyExecutor: hostproxy.NewExecutor(), activeSessions: tracker, eventStore: st}

	response := runHostProxyHandler(t, srv, hostproxy.WireRequest{
		Type:    hostproxy.RequestType,
		Request: hostproxy.Request{Proof: auth.Proof, Target: target, CWD: cwd},
	})
	if !response.OK || response.Result.ExitCode != 42 || string(response.Result.Stdout) != "literal;$(nope)|*" || string(response.Result.Stderr) != "err" {
		t.Fatalf("response = %+v", response)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("approved helper did not start: %v", err)
	}

	missingMarker := filepath.Join(dir, "missing-proof-started")
	missingTarget := target
	missingTarget.Argv = []string{"benign-helper", "unchanged", missingMarker}
	response = runHostProxyHandler(t, srv, hostproxy.WireRequest{
		Type:    hostproxy.RequestType,
		Request: hostproxy.Request{Target: missingTarget, CWD: cwd},
	})
	if response.OK {
		t.Fatalf("missing proof response = %+v", response)
	}
	if _, err := os.Stat(missingMarker); !os.IsNotExist(err) {
		t.Fatalf("missing proof launched helper: %v", err)
	}

	for _, test := range []struct {
		name      string
		sessionID hostproxy.SessionID
		mutate    func(*hostproxy.Request)
	}{
		{name: "changed argv", sessionID: "session", mutate: func(req *hostproxy.Request) { req.Target.Argv[1] = "changed" }},
		{name: "changed executable", sessionID: "session", mutate: func(req *hostproxy.Request) { req.Target.Executable = "/usr/bin/true" }},
		{name: "changed cwd", sessionID: "session", mutate: func(req *hostproxy.Request) { req.CWD = filepath.Dir(cwd) }},
		{name: "wrong session", sessionID: "other", mutate: func(*hostproxy.Request) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			caseMarker := filepath.Join(dir, test.name+".marker")
			caseTarget := hostproxy.Target{Executable: helper, Argv: []string{"benign-helper", "literal", caseMarker}}
			caseAuth, err := manager.Issue(hostproxy.Authorization{
				SessionID: test.sessionID, Target: caseTarget, CWD: cwd, Root: cwd, Path: filepath.Dir(helper),
				BrokerPID: os.Getpid(), FreshAfter: 1,
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			requestTarget := caseTarget
			requestTarget.Argv = append([]string(nil), caseTarget.Argv...)
			request := hostproxy.Request{Proof: caseAuth.Proof, Target: requestTarget, CWD: cwd}
			test.mutate(&request)
			response := runHostProxyHandler(t, srv, hostproxy.WireRequest{Type: hostproxy.RequestType, Request: request})
			if response.OK {
				t.Fatalf("mismatch response = %+v", response)
			}
			if _, err := os.Stat(caseMarker); !os.IsNotExist(err) {
				t.Fatalf("mismatch launched helper: %v", err)
			}
		})
	}
}

func runHostProxyHandler(t *testing.T, srv *server, request hostproxy.WireRequest) hostproxy.WireResponse {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "proxy.sock")
	listener, err := net.Listen("unix", socket)
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
		if readErr != nil {
			return
		}
		srv.handleHostProxyExec(context.Background(), conn, json.NewEncoder(conn), line)
	}()
	client, err := net.Dial("unix", socket)
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
