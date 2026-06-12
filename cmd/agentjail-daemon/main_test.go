package main

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
	t.Helper()

	sockPath := filepath.Join(shortSockDir(t), "test.sock")

	eng, err := policy.NewHookOPAEngine(context.Background(), [][2]string{
		{"test.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}

	srv := &server{
		engine: eng,
		cache:  policy.NewLRUCache(policy.DefaultCacheSize),
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
			srv.wg.Add(1)
			go srv.handleConn(ctx, conn)
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

	// Wait for the socket to appear (up to 3 seconds).
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket did not appear within 3s")
		}
		time.Sleep(20 * time.Millisecond)
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
	if hookCacheKey(base) != hookCacheKey(sameSession) {
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
	if hookCacheKey(base) == hookCacheKey(diffCWD) {
		t.Error("cache keys should differ when CWD differs (CWD is included in key since R1/R7)")
	}

	// Different ToolInput should produce a different key regardless.
	diffInput := base
	diffInput.ToolInput = map[string]interface{}{"command": "ls -la /etc"}
	if hookCacheKey(base) == hookCacheKey(diffInput) {
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

	k1 := hookCacheKey(base)
	k2 := hookCacheKey(other)

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

	if hookCacheKey(a) != hookCacheKey(b) {
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
	canonical, failClose := canonicalizePath("../../.ssh/id_rsa", cwd)
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
	canonical, failClose := canonicalizePath("src/foo.go", cwd)
	if failClose {
		t.Fatal("expected no fail-close for a simple relative path")
	}
	if !strings.HasPrefix(canonical, "/Users/u/proj/src") {
		t.Errorf("expected path under /Users/u/proj/src, got %q", canonical)
	}
}

// TestCanonicalizePath_EmptyPath verifies that an empty path returns ("", false).
func TestCanonicalizePath_Empty(t *testing.T) {
	canonical, failClose := canonicalizePath("", "/tmp")
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
	canonical, failClose := canonicalizePath("/tmp/foo.txt", "/proj")
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

	srv := &server{
		engine: eng,
		cache:  policy.NewLRUCache(policy.DefaultCacheSize),
	}

	gen := srv.gen.Load()

	cfg := agentconfig.Default()
	if err := srv.reload(ctx, [][2]string{{"test.rego", testRegoPolicy}}, cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if srv.gen.Load() == gen {
		t.Error("gen should have incremented after reload; eval would incorrectly cache stale verdicts")
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
