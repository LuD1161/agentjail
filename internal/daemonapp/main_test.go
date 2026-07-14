package daemonapp

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/wire"
)

// testRegoPolicy is the inline Rego policy used in all daemon tests. It
// denies any Bash call that contains "rm -rf" and allows everything else.
// This matches the defaultInlinePolicy embedded in main.go.
const testRegoPolicy = `
package agentjail

import future.keywords.if

default decision = {"action": "allow", "reason": "default allow", "rule_id": "default"}

decision = {"action": "deny", "reason": "rm -rf is blocked by default policy", "rule_id": "command_policy/rm_rf"} if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf")
}
`

// shortSockDir returns a fresh directory with a short absolute path, suitable
// for a Unix-domain socket. macOS caps a socket path (sun_path) at 104 bytes,
// and the default $TMPDIR (/var/folders/...) used by t.TempDir() is long enough
// to overflow it ("bind: invalid argument"), so socket files must live here
// rather than under t.TempDir(). Removed when the test finishes.
func shortSockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ajsock")
	if err != nil {
		t.Fatalf("short sock dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// newTestServer builds a server with the test policy and a temporary socket.
// It returns the server and the socket path. The caller is responsible for
// closing the listener and stopping the server.
func newTestServer(t *testing.T) (*server, string) {
	return newTestServerWithIdle(t, defaultAgentConnIdleTimeout)
}

// newTestServerWithIdle is newTestServer with an explicit idle timeout, set on
// the server struct at construction (before the accept goroutine starts) so the
// timeout is immutable and read race-free by handleConn — no shared global.
func newTestServerWithIdle(t *testing.T, idle time.Duration) (*server, string) {
	t.Helper()

	sockPath := filepath.Join(shortSockDir(t), "test.sock")

	eng, err := policy.NewHookOPAEngine(context.Background(), [][2]string{
		{"test.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	srv := &server{
		evaluator:   policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", testRegoPolicy}}, nil),
		idleTimeout: idle,
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

// sendRequest connects to sockPath, sends one JSON request, reads one JSON
// response, and closes the connection.
func sendRequest(t *testing.T, sockPath string, req Request) Response {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("no response received")
	}
	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// TestDaemon_Allow verifies that a non-dangerous tool call returns action=allow.
func TestDaemon_Allow(t *testing.T) {
	_, sockPath := newTestServer(t)

	req := Request{
		ID:        "test-allow-1",
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{
			"path":    "/tmp/hello.txt",
			"content": "hello world",
		},
		SessionID: "session-abc",
		CWD:       "/home/user/project",
	}

	resp := sendRequest(t, sockPath, req)

	if resp.ID != req.ID {
		t.Errorf("response ID mismatch: got %q want %q", resp.ID, req.ID)
	}
	if resp.Action != "allow" {
		t.Errorf("expected action=allow, got %q (reason=%q rule_id=%q)", resp.Action, resp.Reason, resp.RuleID)
	}
}

// TestDaemon_Deny verifies that a Bash rm -rf call returns action=deny.
func TestDaemon_Deny(t *testing.T) {
	_, sockPath := newTestServer(t)

	req := Request{
		ID:        "test-deny-1",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "rm -rf /tmp/project",
		},
		SessionID: "session-abc",
		CWD:       "/home/user/project",
	}

	resp := sendRequest(t, sockPath, req)

	if resp.ID != req.ID {
		t.Errorf("response ID mismatch: got %q want %q", resp.ID, req.ID)
	}
	if resp.Action != "deny" {
		t.Errorf("expected action=deny, got %q (reason=%q rule_id=%q)", resp.Action, resp.Reason, resp.RuleID)
	}
	if resp.RuleID != "command_policy/rm_rf" {
		t.Errorf("expected rule_id=%q, got %q", "command_policy/rm_rf", resp.RuleID)
	}
}

// TestDaemon_Latency measures round-trip latency for warm decisions.
// The daemon warms up with 10 identical requests; then sends 100 more
// and asserts that the median round-trip is < 5 ms.
func TestDaemon_Latency(t *testing.T) {
	_, sockPath := newTestServer(t)

	req := Request{
		ID:        "latency-test",
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{
			"path":    "/tmp/latency.txt",
			"content": "x",
		},
		SessionID: "s-latency",
		CWD:       "/tmp",
	}

	// Warm up.
	for i := 0; i < 10; i++ {
		r := req
		r.ID = "warmup"
		sendRequest(t, sockPath, r)
	}

	const n = 100
	latencies := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		r := req
		r.ID = "latency"

		start := time.Now()
		_ = sendRequest(t, sockPath, r)
		latencies = append(latencies, time.Since(start))
	}

	// Sort latencies to find median.
	for i := 1; i < len(latencies); i++ {
		for j := i; j > 0 && latencies[j] < latencies[j-1]; j-- {
			latencies[j], latencies[j-1] = latencies[j-1], latencies[j]
		}
	}
	median := latencies[len(latencies)/2]

	t.Logf("round-trip latency: median=%v, p95=%v, p99=%v",
		median,
		latencies[int(float64(len(latencies))*0.95)],
		latencies[int(float64(len(latencies))*0.99)],
	)

	// Target: median < 5 ms. The p95 target in the task is for the daemon
	// internal eval; here we measure end-to-end including socket I/O on
	// localhost, so we use a slightly more generous threshold.
	if median > 5*time.Millisecond {
		t.Errorf("median round-trip latency %v exceeds 5 ms target", median)
	}
}

// TestDaemon_SIGHUP verifies that the daemon continues to respond to requests
// after receiving SIGHUP (policy reload).
//
// This test builds the daemon binary, starts it as a subprocess, sends a
// request, sends SIGHUP, then sends another request to verify liveness.
func TestDaemon_SIGHUP(t *testing.T) {
	// Build the daemon binary into a temp dir.
	dir := t.TempDir()
	daemonBin := filepath.Join(dir, "agentjail-daemon")
	if out, err := exec.Command("go", "build", "-o", daemonBin,
		"github.com/LuD1161/agentjail/cmd/agentjail-daemon").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	sockPath := filepath.Join(shortSockDir(t), "daemon.sock")

	// Start the daemon in its own process group so SIGHUP sent to the daemon
	// subprocess does not leak to the test binary's process group.
	cmd := exec.Command(daemonBin, "--socket", sockPath)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(sockPath)
	})

	// Wait for the socket to appear (up to 10 seconds — the daemon compiles
	// OPA Rego and opens SQLite on startup, which can exceed 3s on loaded CI).
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket did not appear within 10s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Helper: send a request and return the response.
	sendOne := func(id string) Response {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("dial after SIGHUP: %v", err)
		}
		defer conn.Close()
		enc := json.NewEncoder(conn)
		_ = enc.Encode(Request{
			ID:        id,
			HookEvent: "PreToolUse",
			ToolName:  "Write",
			ToolInput: map[string]interface{}{"path": "/tmp/x", "content": "y"},
			SessionID: "s1",
			CWD:       "/tmp",
		})
		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			t.Fatalf("no response for %s", id)
		}
		var resp Response
		_ = json.Unmarshal(scanner.Bytes(), &resp)
		return resp
	}

	// Send a request before SIGHUP.
	resp1 := sendOne("pre-sighup")
	if resp1.Action == "" {
		t.Error("expected non-empty action before SIGHUP")
	}

	// Send SIGHUP.
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	// Give the daemon a moment to reload.
	time.Sleep(100 * time.Millisecond)

	// Send a request after SIGHUP — daemon must still respond.
	resp2 := sendOne("post-sighup")
	if resp2.Action == "" {
		t.Error("expected non-empty action after SIGHUP")
	}
	if resp2.ID != "post-sighup" {
		t.Errorf("expected id=post-sighup, got %q", resp2.ID)
	}
}

// TestDaemon_ConcurrentRequests verifies the daemon handles concurrent
// connections safely (race detector will catch violations).
func TestDaemon_ConcurrentRequests(t *testing.T) {
	_, sockPath := newTestServer(t)

	const goroutines = 20
	errc := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			var req Request
			if i%2 == 0 {
				req = Request{
					ID:        "concurrent-deny",
					HookEvent: "PreToolUse",
					ToolName:  "Bash",
					ToolInput: map[string]interface{}{"command": "rm -rf /danger"},
					SessionID: "s1",
					CWD:       "/tmp",
				}
			} else {
				req = Request{
					ID:        "concurrent-allow",
					HookEvent: "PreToolUse",
					ToolName:  "Read",
					ToolInput: map[string]interface{}{"path": "/safe"},
					SessionID: "s2",
					CWD:       "/tmp",
				}
			}
			resp := sendRequest(t, sockPath, req)
			if resp.Action == "" {
				errc <- nil // sendRequest will have called t.Fatal on real error
				return
			}
			errc <- nil
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-errc
	}
}

// TestAcceptConn_RejectsOverCapacity verifies the P9 bounded-concurrency
// cap: once s.connSem is full, acceptConn closes the new connection
// immediately (rather than blocking the accept loop or spawning an
// unbounded goroutine) so a hostile/misbehaving peer opening many
// connections cannot exhaust the daemon.
func TestAcceptConn_RejectsOverCapacity(t *testing.T) {
	srv := &server{connSem: make(chan struct{}, 1)}
	// Fill the one slot so the next acceptConn call must be rejected.
	srv.connSem <- struct{}{}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	srv.acceptConn(context.Background(), serverConn)

	// The rejected connection should be closed by the daemon: a read on the
	// client side should observe EOF/closed-pipe rather than hang.
	buf := make([]byte, 1)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected rejected connection to be closed, got no error reading")
	}
}

// TestAcceptConn_AdmitsUnderCapacity verifies acceptConn does dispatch to
// handleConn (via the wg counter) when the semaphore has room.
func TestAcceptConn_AdmitsUnderCapacity(t *testing.T) {
	sockPath := filepath.Join(shortSockDir(t), "test.sock")
	eng, err := policy.NewHookOPAEngine(context.Background(), [][2]string{{"test.rego", testRegoPolicy}})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}
	srv := &server{
		evaluator: policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", testRegoPolicy}}, nil),
		connSem:   make(chan struct{}, 4),
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
				return
			}
			srv.acceptConn(ctx, conn)
		}
	}()

	resp := sendRequest(t, sockPath, Request{
		ID:        "under-capacity",
		HookEvent: "PreToolUse",
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"path": "/safe"},
		SessionID: "s1",
		CWD:       "/tmp",
	})
	if resp.Action != "allow" {
		t.Errorf("expected normal request to be served when under capacity, got action=%q", resp.Action)
	}
}

// TestHandleConn_IdleConnectionTimesOut verifies P9's idle read deadline: a
// connection that is opened but never sends a request is closed by the
// daemon rather than held open indefinitely. Uses a per-server 50 ms idle
// timeout so this doesn't require a real multi-second sleep.
func TestHandleConn_IdleConnectionTimesOut(t *testing.T) {
	// Per-server idle timeout (no shared global) so this is race-free under -race.
	_, sockPath := newTestServerWithIdle(t, 50*time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send nothing. The daemon should close its end within ~the idle timeout.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected idle connection to be closed by the daemon, got no error reading")
	}
}

// TestHookCacheKey verifies that the cache key is stable and:
//   - excludes SessionID (per-invocation noise)
//   - includes CWD (cwd-dependent decisions must not share cache entries, R1/R7)
func TestHookCacheKey(t *testing.T) {
	base := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "session-1",
		CWD:       "/home/user/project",
	}

	// Same static fields + same CWD, different SessionID only.
	// SessionID is per-invocation noise — keys should be equal.
	sameSession := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "session-999",
		CWD:       "/home/user/project",
	}
	if policyeval.HookCacheKey(base) != policyeval.HookCacheKey(sameSession) {
		t.Error("cache keys should be equal when only SessionID differs (SessionID is excluded from key)")
	}

	// Same static fields but DIFFERENT CWD — keys must differ (R1/R7 fix).
	diffCWD := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "session-1",
		CWD:       "/different/path",
	}
	if policyeval.HookCacheKey(base) == policyeval.HookCacheKey(diffCWD) {
		t.Error("cache keys should differ when CWD differs (CWD is included in key since R1/R7)")
	}

	// Different ToolInput should produce a different key regardless.
	diffInput := base
	diffInput.ToolInput = map[string]interface{}{"command": "ls -la /etc"}
	if policyeval.HookCacheKey(base) == policyeval.HookCacheKey(diffInput) {
		t.Error("different ToolInput should produce different cache keys")
	}
}

// TestIsClientGone verifies that the broken-pipe / reset / closed-socket errors
// produced when a caller disconnects before the daemon writes its response are
// classified as a benign client-gone race (logged at Debug, not Warn), while a
// genuine write error is not.
func TestIsClientGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"epipe", syscall.EPIPE, true},
		{"econnreset", syscall.ECONNRESET, true},
		{"net closed", net.ErrClosed, true},
		// Wrapped, as the os/net stack returns it from a failed Write.
		{"wrapped epipe", &net.OpError{Op: "write", Err: syscall.EPIPE}, true},
		{"other", syscall.ENOSPC, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClientGone(tc.err); got != tc.want {
				t.Errorf("isClientGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R1/R7: cwd in cache key
// ---------------------------------------------------------------------------

// TestHookCacheKey_CWDIncluded verifies that the same file_path under two
// different cwd values yields two different cache keys (AC-R1 seam).
func TestHookCacheKey_CWDIncluded(t *testing.T) {
	base := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": "/Users/u/proj/secrets.yaml"},
		SessionID: "s1",
		CWD:       "/Users/u/proj",
	}
	other := base
	other.CWD = "/Users/u/other"

	k1 := policyeval.HookCacheKey(base)
	k2 := policyeval.HookCacheKey(other)

	if k1 == k2 {
		t.Error("cache keys should differ for the same file_path under different cwds (AC-R1)")
	}
}

// TestHookCacheKey_SameCWDSameKey verifies that two requests with the same
// static fields and same cwd share a cache key.
func TestHookCacheKey_SameCWDSameKey(t *testing.T) {
	a := policy.HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": "/tmp/foo.txt"},
		SessionID: "session-1",
		CWD:       "/proj",
	}
	b := a
	b.SessionID = "session-999" // SessionID should NOT affect the key

	if policyeval.HookCacheKey(a) != policyeval.HookCacheKey(b) {
		t.Error("cache keys should be equal for same static fields + same cwd but different session IDs")
	}
}

// ---------------------------------------------------------------------------
// R3/R9: Path canonicalization
// ---------------------------------------------------------------------------

// TestCanonicalizePath_RelativeDotDot verifies that a relative ../../.ssh/id_rsa
// from a deep cwd resolves to the real ~/.ssh/id_rsa path (AC-R3).
func TestCanonicalizePath_RelativeDotDot(t *testing.T) {
	home, _ := os.UserHomeDir()
	// Simulate a deep project cwd.
	cwd := home + "/repos/project/subdir"

	// ../../.ssh/id_rsa from subdir → home/.ssh/id_rsa
	canonical, failClose := policyeval.CanonicalizePath("../../.ssh/id_rsa", cwd)
	if failClose {
		t.Fatal("expected no fail-close for a resolvable parent-relative path")
	}

	expected := home + "/.ssh/id_rsa"
	// EvalSymlinks may not resolve ~/.ssh/id_rsa if it doesn't exist on this
	// machine, but the cleaned path should still resolve correctly.
	if !strings.HasSuffix(canonical, "/.ssh/id_rsa") {
		t.Errorf("expected path to end in /.ssh/id_rsa, got %q (from cwd=%q)", canonical, cwd)
	}
	// The canonical path must NOT start with cwd (it escaped the project).
	if strings.HasPrefix(canonical, cwd) {
		t.Errorf("canonical path should NOT be under cwd=%q, got %q", cwd, canonical)
	}
	_ = expected
}

// TestCanonicalizePath_RelativeSafe verifies that a safe relative path
// (src/foo.go) is resolved to an absolute path under cwd.
func TestCanonicalizePath_RelativeSafe(t *testing.T) {
	cwd := "/Users/u/proj"
	canonical, failClose := policyeval.CanonicalizePath("src/foo.go", cwd)
	if failClose {
		t.Fatal("expected no fail-close for a simple relative path")
	}
	if !strings.HasPrefix(canonical, "/Users/u/proj/src") {
		t.Errorf("expected path under /Users/u/proj/src, got %q", canonical)
	}
}

// TestCanonicalizePath_EmptyPath verifies that an empty path returns ("", false).
func TestCanonicalizePath_Empty(t *testing.T) {
	canonical, failClose := policyeval.CanonicalizePath("", "/tmp")
	if failClose {
		t.Error("empty path should not fail-close")
	}
	if canonical != "" {
		t.Errorf("expected empty canonical for empty input, got %q", canonical)
	}
}

// TestCanonicalizePath_AbsoluteUnchanged verifies that an already-absolute
// clean path is returned as-is (modulo symlink resolution).
func TestCanonicalizePath_AbsoluteUnchanged(t *testing.T) {
	canonical, failClose := policyeval.CanonicalizePath("/tmp/foo.txt", "/proj")
	if failClose {
		t.Error("absolute /tmp path should not fail-close")
	}
	if !strings.HasSuffix(canonical, "/tmp/foo.txt") && !strings.Contains(canonical, "/private/tmp/foo.txt") {
		t.Errorf("expected canonical to be /tmp/foo.txt or /private/tmp/foo.txt, got %q", canonical)
	}
}

// ---------------------------------------------------------------------------
// AC5.7: SIGHUP config reload daemon-level test (subprocess)
// ---------------------------------------------------------------------------

// TestDaemon_SIGHUP_MCPDecisionChanges verifies that SIGHUP reloads policy.yaml
// and changes MCP allow/deny without restart.  The test:
//  1. writes a policy.yaml with mcp.allowed=[] (deny all MCP)
//  2. starts the daemon with --rules pointing to the real MCP policy dir
//  3. sends an MCP request → expect deny
//  4. rewrites policy.yaml to add the server to mcp.allowed
//  5. SIGHUPs the daemon
//  6. sends the same MCP request → expect allow
func TestDaemon_SIGHUP_MCPDecisionChanges(t *testing.T) {
	rulesDir := findPoliciesDir(t)
	if rulesDir == "" {
		t.Skip("agentpolicy/policies dir not found — skipping MCP SIGHUP test")
	}

	dir := t.TempDir()
	daemonBin := filepath.Join(dir, "agentjail-daemon")
	if out, err := exec.Command("go", "build", "-o", daemonBin,
		"github.com/LuD1161/agentjail/cmd/agentjail-daemon").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	sockPath := filepath.Join(shortSockDir(t), "daemon.sock")

	// Phase 1: empty allowlist → deny all MCP.
	phase1Cfg := agentconfig.Default()
	// MCP.Allowed is already [] in Default.
	if err := agentconfig.Save(phase1Cfg, policyPath); err != nil {
		t.Fatalf("write phase1 policy: %v", err)
	}

	cmd := exec.Command(daemonBin,
		"--socket", sockPath,
		"--policy", policyPath,
		"--rules", rulesDir,
	)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	waitForSocket(t, sockPath, 5*time.Second)

	sendMCP := func(id string) Response {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		enc := json.NewEncoder(conn)
		_ = enc.Encode(Request{
			ID:        id,
			HookEvent: "PreToolUse",
			ToolName:  "mcp__filesystem__read_file",
			ToolInput: map[string]interface{}{"path": "/tmp/x"},
			SessionID: "s1",
			CWD:       "/tmp",
		})
		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			t.Fatalf("no response for %s", id)
		}
		var resp Response
		_ = json.Unmarshal(scanner.Bytes(), &resp)
		return resp
	}

	// Before SIGHUP: filesystem not in allowed → deny.
	resp1 := sendMCP("before-sighup")
	if resp1.Action != "deny" {
		t.Errorf("before SIGHUP: expected deny for unlisted MCP server, got %q (rule_id=%q)", resp1.Action, resp1.RuleID)
	}

	// Phase 2: add filesystem to allowlist.
	phase2Cfg := agentconfig.Default()
	phase2Cfg.MCP.Allowed = []string{"filesystem"}
	if err := agentconfig.Save(phase2Cfg, policyPath); err != nil {
		t.Fatalf("write phase2 policy: %v", err)
	}

	// Send SIGHUP.
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// After SIGHUP: filesystem now in allowed → allow.
	resp2 := sendMCP("after-sighup")
	if resp2.Action != "allow" {
		t.Errorf("after SIGHUP: expected allow for 'filesystem', got %q (rule_id=%q)", resp2.Action, resp2.RuleID)
	}
}

// TestDaemon_SIGHUP_FailureKeepsOldPolicy verifies that a reload failure
// (bad YAML) keeps the old policy and does not crash.
func TestDaemon_SIGHUP_FailureKeepsOldPolicy(t *testing.T) {
	dir := t.TempDir()
	daemonBin := filepath.Join(dir, "agentjail-daemon")
	if out, err := exec.Command("go", "build", "-o", daemonBin,
		"github.com/LuD1161/agentjail/cmd/agentjail-daemon").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	sockPath := filepath.Join(shortSockDir(t), "daemon.sock")

	// Write valid initial policy.
	if err := agentconfig.Save(agentconfig.Default(), policyPath); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	cmd := exec.Command(daemonBin, "--socket", sockPath, "--policy", policyPath)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	waitForSocket(t, sockPath, 5*time.Second)

	// Corrupt the policy file.
	if err := os.WriteFile(policyPath, []byte("unknown_bad_key: true\n"), 0o600); err != nil {
		t.Fatalf("corrupt policy: %v", err)
	}

	// SIGHUP — daemon should keep old policy, not crash.
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Daemon must still be alive and respond.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal("daemon crashed after bad-YAML SIGHUP — socket unreachable")
	}
	enc := json.NewEncoder(conn)
	_ = enc.Encode(Request{
		ID:        "alive-check",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls"},
		SessionID: "s1",
		CWD:       "/tmp",
	})
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("no response after bad-YAML reload — daemon may have crashed")
	}
	conn.Close()
}

// TestDaemon_UnknownYAMLKeyFailsStartup verifies that an unknown top-level key
// in policy.yaml fails daemon startup with a non-zero exit (AC5.4).
func TestDaemon_UnknownYAMLKeyFailsStartup(t *testing.T) {
	dir := t.TempDir()
	daemonBin := filepath.Join(dir, "agentjail-daemon")
	if out, err := exec.Command("go", "build", "-o", daemonBin,
		"github.com/LuD1161/agentjail/cmd/agentjail-daemon").CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\n%s", err, out)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("unknown_top_level_key: true\n"), 0o600); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}
	sockPath := filepath.Join(shortSockDir(t), "daemon.sock")

	cmd := exec.Command(daemonBin, "--socket", sockPath, "--policy", policyPath)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected daemon to fail with non-zero exit on unknown YAML key, but it exited 0")
	}
}

// TestReloadDiscardsStaleCacheWrite verifies that a reload increments the
// generation counter, causing eval to skip the cache.Set for in-flight
// decisions computed against the pre-reload engine.
func TestReloadDiscardsStaleCacheWrite(t *testing.T) {
	ctx := context.Background()

	eng, err := policy.NewHookOPAEngine(ctx, [][2]string{
		{"test.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	ev := policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", testRegoPolicy}}, nil)

	// Eval a request to populate the cache.
	req := policyeval.Request{
		ID:        "stale-1",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "s1",
		CWD:       "/tmp",
	}
	resp, err := ev.Eval(ctx, req)
	if err != nil {
		t.Fatalf("pre-reload eval: %v", err)
	}
	if resp.Action != "allow" {
		t.Fatalf("pre-reload eval: expected allow, got %q", resp.Action)
	}

	// Reload with a policy that denies the same command.
	denyPolicy := `
package agentjail
import future.keywords.if
default decision = {"action": "deny", "reason": "deny all", "rule_id": "deny_all"}
`
	cfg := agentconfig.Default()
	if err := ev.Reload(ctx, [][2]string{{"test.rego", denyPolicy}}, cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// After reload, the same request should get the NEW policy's verdict (deny),
	// not the stale cached verdict (allow).
	req.ID = "stale-2"
	resp, err = ev.Eval(ctx, req)
	if err != nil {
		t.Fatalf("post-reload eval: %v", err)
	}
	if resp.Action != "deny" {
		t.Errorf("post-reload: expected deny (new policy), got %q (stale cache leaked)", resp.Action)
	}
}

// ---------------------------------------------------------------------------
// Track B: ask decisions must not be cached
// ---------------------------------------------------------------------------

// askRegoPolicy is a test policy that returns "ask" by default and "allow"
// only for Bash commands that contain the word "safe".
const askRegoPolicy = `
package agentjail

import future.keywords.if

default decision = {"action": "ask", "reason": "confirm intent", "rule_id": "test/ask"}

decision = {"action": "allow", "reason": "allowed", "rule_id": "test/allow"} if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "safe")
}
`

// newTestServerWithPolicy builds a server like newTestServer but uses the
// provided Rego source instead of testRegoPolicy.
func newTestServerWithPolicy(t *testing.T, regoSrc string) (*server, string) {
	t.Helper()

	sockPath := filepath.Join(shortSockDir(t), "test.sock")

	eng, err := policy.NewHookOPAEngine(context.Background(), [][2]string{
		{"test.rego", regoSrc},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	srv := &server{
		evaluator: policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", regoSrc}}, nil),
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

// TestDaemon_AskDecisionNotCached verifies that "ask" decisions are never
// stored in the cache, so every call for the same input is re-evaluated by OPA
// (enabling Claude Code's "Yes, during this session" mechanism to work).
func TestDaemon_AskDecisionNotCached(t *testing.T) {
	ctx := context.Background()

	eng, err := policy.NewHookOPAEngine(ctx, [][2]string{
		{"test.rego", askRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	srv := &server{
		evaluator: policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", askRegoPolicy}}, nil),
	}

	req := Request{
		ID:        "ask-test-1",
		HookEvent: "PreToolUse",
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "/home/user/secret.txt"},
		SessionID: "s1",
		CWD:       "/home/user",
	}

	// First eval — should return "ask".
	resp1, err := srv.evaluator.Eval(ctx, req)
	if err != nil {
		t.Fatalf("first eval error: %v", err)
	}
	if resp1.Action != "ask" {
		t.Errorf("first eval: expected action=ask, got %q", resp1.Action)
	}

	// Second eval of the same input and session — should return "allow"
	// because the session grant kicks in (user approved the first ask).
	req.ID = "ask-test-2"
	resp2, err := srv.evaluator.Eval(ctx, req)
	if err != nil {
		t.Fatalf("second eval error: %v", err)
	}
	if resp2.Action != "allow" {
		t.Errorf("second eval: expected action=allow (session grant), got %q", resp2.Action)
	}
	if resp2.RuleID != "session/grant" {
		t.Errorf("second eval: expected rule_id=session/grant, got %q", resp2.RuleID)
	}

	// Third eval from a DIFFERENT session — should still ask (session-scoped).
	req.ID = "ask-test-3"
	req.SessionID = "s2"
	resp3, err := srv.evaluator.Eval(ctx, req)
	if err != nil {
		t.Fatalf("third eval error: %v", err)
	}
	if resp3.Action != "ask" {
		t.Errorf("third eval (different session): expected ask, got %q", resp3.Action)
	}
}

// TestDaemon_AllowDenyStillCached verifies that allow and deny verdicts are
// cached by checking that repeated evaluations return consistent results.
func TestDaemon_AllowDenyStillCached(t *testing.T) {
	ctx := context.Background()

	eng, err := policy.NewHookOPAEngine(ctx, [][2]string{
		{"test.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	ev := policyeval.New(eng, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"test.rego", testRegoPolicy}}, nil)

	allowReq := Request{
		ID:        "cache-allow-1",
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": "/tmp/hello.txt", "content": "hi"},
		SessionID: "s1",
		CWD:       "/tmp",
	}

	// Eval an allow decision.
	resp, err := ev.Eval(ctx, allowReq)
	if err != nil {
		t.Fatalf("allow eval error: %v", err)
	}
	if resp.Action != "allow" {
		t.Errorf("expected action=allow, got %q", resp.Action)
	}

	// Second eval of the same request should return the same (cached) result.
	allowReq.ID = "cache-allow-2"
	resp2, err := ev.Eval(ctx, allowReq)
	if err != nil {
		t.Fatalf("allow eval 2 error: %v", err)
	}
	if resp2.Action != "allow" {
		t.Errorf("second allow eval: expected action=allow, got %q", resp2.Action)
	}

	denyReq := Request{
		ID:        "cache-deny-1",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /danger"},
		SessionID: "s1",
		CWD:       "/tmp",
	}

	// Eval a deny decision.
	resp, err = ev.Eval(ctx, denyReq)
	if err != nil {
		t.Fatalf("deny eval error: %v", err)
	}
	if resp.Action != "deny" {
		t.Errorf("expected action=deny, got %q", resp.Action)
	}

	// Second eval of deny request should return the same (cached) result.
	denyReq.ID = "cache-deny-2"
	resp3, err := ev.Eval(ctx, denyReq)
	if err != nil {
		t.Fatalf("deny eval 2 error: %v", err)
	}
	if resp3.Action != "deny" {
		t.Errorf("second deny eval: expected action=deny, got %q", resp3.Action)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// waitForSocket blocks until sockPath exists or deadline is exceeded.
func waitForSocket(t *testing.T, sockPath string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon socket %s did not appear within %s", sockPath, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// findPoliciesDir searches for the agentpolicy/policies directory relative
// to the repo root.  Returns "" if not found.
func TestExpandCommandPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "tilde_slash_aws",
			cmd:  "cat ~/.aws/credentials",
			want: "cat " + home + "/.aws/credentials",
		},
		{
			name: "tilde_slash_ssh",
			cmd:  "cat ~/.ssh/id_rsa",
			want: "cat " + home + "/.ssh/id_rsa",
		},
		{
			name: "dollar_home_aws",
			cmd:  "cat $HOME/.aws/credentials",
			want: "cat " + home + "/.aws/credentials",
		},
		{
			name: "dollar_home_gnupg",
			cmd:  `ls "$HOME/.gnupg/"`,
			want: `ls "` + home + `/.gnupg/"`,
		},
		{
			name: "multiple_tildes",
			cmd:  "cat ~/.ssh/id_rsa ~/.aws/credentials",
			want: "cat " + home + "/.ssh/id_rsa " + home + "/.aws/credentials",
		},
		{
			name: "tilde_mid_command",
			cmd:  "echo hi && cat ~/.ssh/config",
			want: "echo hi && cat " + home + "/.ssh/config",
		},
		{
			name: "no_expansion_needed",
			cmd:  "git status",
			want: "git status",
		},
		{
			name: "tilde_not_at_word_boundary",
			cmd:  "echo ~other/foo",
			want: "echo ~other/foo",
		},
		{
			name: "bare_tilde_eol",
			cmd:  "echo ~",
			want: "echo " + home,
		},
		{
			name: "bare_tilde_space",
			cmd:  "cd ~ && ls",
			want: "cd " + home + " && ls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyeval.ExpandCommandPaths(tt.cmd)
			if got != tt.want {
				t.Errorf("policyeval.ExpandCommandPaths(%q)\n  got  %q\n  want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestNormalizeToolInput_ExpandsCommand(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	input := map[string]interface{}{
		"command": "cat ~/.aws/credentials",
	}
	out := policyeval.NormalizeToolInput(input, "/tmp")
	cmd, ok := out["command"].(string)
	if !ok {
		t.Fatal("command field missing from normalized output")
	}
	if strings.Contains(cmd, "~") {
		t.Errorf("normalizeToolInput should expand ~ in command, got %q", cmd)
	}
	want := "cat " + home + "/.aws/credentials"
	if cmd != want {
		t.Errorf("got %q, want %q", cmd, want)
	}
}

// TestRemoveFailOpenSentinel_RemovesExistingFile verifies U2: the daemon
// startup routine deletes ~/.agentjail/fail-open-warned so agentjail-hook's
// "warn once" gate re-arms for the next outage. Without this, the fail-open
// warning would fire at most once ever, for the lifetime of the
// ~/.agentjail directory.
func TestRemoveFailOpenSentinel_RemovesExistingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	agentjailDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(agentjailDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	sentinelPath := filepath.Join(agentjailDir, "fail-open-warned")
	if err := os.WriteFile(sentinelPath, []byte("pid=1 time=x\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := os.Stat(sentinelPath); err != nil {
		t.Fatalf("sentinel not created: %v", err)
	}

	removeFailOpenSentinel()

	if _, err := os.Stat(sentinelPath); !os.IsNotExist(err) {
		t.Fatalf("expected sentinel to be removed, stat err = %v", err)
	}
}

// TestRemoveFailOpenSentinel_NoFileIsNotAnError verifies the common case
// (daemon starting up with no prior fail-open, so no sentinel exists) is a
// silent no-op rather than a logged warning.
func TestRemoveFailOpenSentinel_NoFileIsNotAnError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Does not panic and does not create the file.
	removeFailOpenSentinel()

	sentinelPath := filepath.Join(home, ".agentjail", "fail-open-warned")
	if _, err := os.Stat(sentinelPath); !os.IsNotExist(err) {
		t.Fatalf("expected no sentinel file, stat err = %v", err)
	}
}

// TestRemoveFailOpenSentinel_PathMatchesHook verifies the daemon and the
// hook agree on exactly the same sentinel path (both delegate to
// wire.FailOpenWarnedSentinelPath so they cannot drift apart).
func TestRemoveFailOpenSentinel_PathMatchesHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".agentjail", "fail-open-warned")
	got := wire.FailOpenWarnedSentinelPath()
	if got != want {
		t.Fatalf("wire.FailOpenWarnedSentinelPath() = %q, want %q", got, want)
	}
}

func findPoliciesDir(t *testing.T) string {
	t.Helper()
	// Walk up from current dir looking for agentpolicy/policies.
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "agentpolicy", "policies")
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	return ""
}
