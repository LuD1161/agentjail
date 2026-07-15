package daemonapp

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/policyeval"
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

// serveCtlFor starts a grant control server wired to srv.reloadPolicy and
// returns its socket path. Reload lives on this privileged socket, not the
// agent-facing daemon.sock (ADR 0066).
func serveCtlFor(t *testing.T, srv *server) string {
	t.Helper()

	ctlSock := filepath.Join(shortSockDir(t), "ctl.sock")
	gs, err := newGrantServer(ctlSock, testCtlToken, grantctl.NewRegistry(), audit.NopEmitter{}, false, nil, srv.reloadPolicy)
	if err != nil {
		t.Fatalf("newGrantServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		gs.close()
	})
	go gs.serveCtl(ctx)
	return ctlSock
}

// TestDaemon_ControlReload_Success verifies that a reload over the privileged
// control socket succeeds when policy.yaml is well-formed — what a successful
// SIGHUP reload does, but with an explicit ack instead of a fire-and-forget
// signal.
func TestDaemon_ControlReload_Success(t *testing.T) {
	withTempHome(t) // reloadPolicy's writeHookFallback resolves $HOME; keep it off the real home dir.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := agentconfig.Save(agentconfig.Default(), policyPath); err != nil {
		t.Fatalf("write policy.yaml: %v", err)
	}

	srv, _ := newTestServerWithReloadPaths(t, policyPath, "")
	ctlSock := serveCtlFor(t, srv)

	if err := grantctl.DaemonReload(ctlSock, testCtlToken, 2*time.Second); err != nil {
		t.Fatalf("expected reload to succeed, got %v", err)
	}
}

// TestDaemon_ControlReload_Failure verifies that a reload reports failure with a
// non-empty error when policy.yaml is malformed, AND that the daemon keeps
// serving eval requests afterward using the OLD policy (never-fail-open contract
// — a bad reload must not silently take effect or crash the daemon).
func TestDaemon_ControlReload_Failure(t *testing.T) {
	withTempHome(t) // same rationale as TestDaemon_ControlReload_Success.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := agentconfig.Save(agentconfig.Default(), policyPath); err != nil {
		t.Fatalf("write initial policy.yaml: %v", err)
	}

	srv, sockPath := newTestServerWithReloadPaths(t, policyPath, "")
	ctlSock := serveCtlFor(t, srv)

	// Corrupt policy.yaml with an unknown top-level key — loadConfig/
	// agentconfig.LoadOrDefault rejects this.
	if err := os.WriteFile(policyPath, []byte("unknown_bad_key: true\n"), 0o600); err != nil {
		t.Fatalf("corrupt policy.yaml: %v", err)
	}

	err := grantctl.DaemonReload(ctlSock, testCtlToken, 2*time.Second)
	if err == nil {
		t.Fatal("expected failure for malformed policy.yaml, got success")
	}
	// Must be a refusal (the daemon answered), not a transport error — the CLI
	// distinguishes these to decide whether to fall back to SIGHUP.
	var refused *grantctl.RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("expected *RefusedError, got %T: %v", err, err)
	}
	if refused.Reason == "" {
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
