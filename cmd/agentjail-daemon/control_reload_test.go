package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/wire"
)

// newTestServerWithReloadPaths is like newTestServer but wires
// policyPath/rulesDir onto the server so reloadPolicy (exercised via the
// control socket below) has something real to reload.
func newTestServerWithReloadPaths(t *testing.T, policyPath, rulesDir string) (*server, string) {
	t.Helper()

	sockPath := filepath.Join(shortSockDir(t), "test.sock")

	eng, err := policy.NewHookOPAEngine(context.Background(), [][2]string{
		{"test.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	srv := &server{
		evaluator:  policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", testRegoPolicy}}, nil),
		policyPath: policyPath,
		rulesDir:   rulesDir,
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				return
			}
			srv.acceptConn(ctx, conn)
		}
	}()

	return srv, sockPath
}

// sendControlReload dials sockPath, sends a ControlOpReload request, and
// returns the decoded ControlResponse.
func sendControlReload(t *testing.T, sockPath string) wire.ControlResponse {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(wire.ControlRequest{
		Type: wire.ControlType,
		Op:   wire.ControlOpReload,
	}); err != nil {
		t.Fatalf("encode control request: %v", err)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("no response received")
	}
	var resp wire.ControlResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("decode control response: %v", err)
	}
	return resp
}

// TestDaemon_ControlReload_Success verifies that a reload control message
// over daemon.sock reports ok=true when policy.yaml is well-formed, mirroring
// what a successful SIGHUP reload does today but with an explicit ack instead
// of a fire-and-forget signal.
func TestDaemon_ControlReload_Success(t *testing.T) {
	withTempHome(t) // reloadPolicy's writeHookFallback resolves $HOME; keep it off the real home dir.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := agentconfig.Save(agentconfig.Default(), policyPath); err != nil {
		t.Fatalf("write policy.yaml: %v", err)
	}

	_, sockPath := newTestServerWithReloadPaths(t, policyPath, "")

	resp := sendControlReload(t, sockPath)
	if !resp.OK {
		t.Fatalf("expected ok=true, got ok=false error=%q", resp.Error)
	}
	if resp.Error != "" {
		t.Errorf("expected empty error on success, got %q", resp.Error)
	}
}

// TestDaemon_ControlReload_Failure verifies that a reload control message
// reports ok=false with a non-empty error when policy.yaml is malformed, AND
// that the daemon keeps serving eval requests afterward using the OLD policy
// (never-fail-open contract — a bad reload must not silently take effect or
// crash the daemon).
func TestDaemon_ControlReload_Failure(t *testing.T) {
	withTempHome(t) // same rationale as TestDaemon_ControlReload_Success.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := agentconfig.Save(agentconfig.Default(), policyPath); err != nil {
		t.Fatalf("write initial policy.yaml: %v", err)
	}

	srv, sockPath := newTestServerWithReloadPaths(t, policyPath, "")

	// Corrupt policy.yaml with an unknown top-level key — loadConfig/
	// agentconfig.LoadOrDefault rejects this.
	if err := os.WriteFile(policyPath, []byte("unknown_bad_key: true\n"), 0o600); err != nil {
		t.Fatalf("corrupt policy.yaml: %v", err)
	}

	resp := sendControlReload(t, sockPath)
	if resp.OK {
		t.Fatal("expected ok=false for malformed policy.yaml, got ok=true")
	}
	if resp.Error == "" {
		t.Error("expected a non-empty error message for the failed reload")
	}

	// The daemon must still be alive and still evaluate against the OLD
	// (pre-corruption) policy — the reload failure must not have mutated any
	// daemon state.
	got := sendRequest(t, sockPath, Request{
		ID:        "still-alive",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /"},
		SessionID: "s1",
		CWD:       "/tmp",
	})
	if got.Action != "deny" {
		t.Errorf("expected old policy (deny rm -rf) still in effect after failed reload, got action=%q", got.Action)
	}

	// srv.evaluator must be the same instance behavior as before -- sanity
	// check that reloadPolicy truly returned an error rather than silently
	// succeeding.
	if err := srv.reloadPolicy(context.Background()); err == nil {
		t.Error("reloadPolicy() with corrupted policy.yaml should return a non-nil error")
	}
}
