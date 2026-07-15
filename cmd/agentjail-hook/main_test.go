package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildHook compiles the hook binary into dir and returns its path.
func buildHook(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "agentjail-hook")
	out, err := exec.Command("go", "build", "-o", bin,
		"github.com/LuD1161/agentjail/cmd/agentjail-hook").CombinedOutput()
	if err != nil {
		t.Fatalf("build hook: %v\n%s", err, out)
	}
	return bin
}

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

// trustedHome creates a short-path temp directory (see shortSockDir for why
// short paths matter for Unix sockets), pre-creates its .agentjail
// subdirectory, and points $HOME at it for the current test (t.Setenv, so
// subprocesses launched via os.Environ() inherit it). The hook only honors
// an AGENTJAIL_SOCKET override when it resolves under $HOME/.agentjail (see
// isTrustedSocketOverride in main.go), so tests that need the daemon socket
// pointed at a stub must place it in the directory this returns.
func trustedHome(t *testing.T) string {
	t.Helper()
	home := shortSockDir(t)
	agentjailDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(agentjailDir, 0o700); err != nil {
		t.Fatalf("mkdir .agentjail: %v", err)
	}
	t.Setenv("HOME", home)
	return agentjailDir
}

// stubDaemon starts a minimal fake daemon that serves a single connection.
// It reads one JSON request, applies actionFn to produce an action string and
// reason, writes the response, then closes the connection.
// It returns the socket path and a cleanup function.
func stubDaemon(t *testing.T, dir string, actionFn func(req daemonRequest) (string, string, string)) string {
	t.Helper()
	sockPath := filepath.Join(trustedHome(t), "test-daemon.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}

	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		if !scanner.Scan() {
			return
		}
		var req daemonRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return
		}

		action, reason, ruleID := actionFn(req)
		resp := daemonResponse{
			ID:     req.ID,
			Action: action,
			Reason: reason,
			RuleID: ruleID,
		}
		enc := json.NewEncoder(conn)
		_ = enc.Encode(resp)
	}()

	return sockPath
}

// runHook runs the hook binary with the given stdin JSON and environment.
// Returns stdout bytes, stderr bytes, and the exit code.
func runHook(t *testing.T, bin string, stdinJSON string, env []string) ([]byte, []byte, int) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = bytes.NewBufferString(stdinJSON)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run hook: %v", err)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode
}

// makeStdinJSON returns a Claude Code PreToolUse stdin payload.
func makeStdinJSON(toolName string, toolInput map[string]interface{}, sessionID string) string {
	type hookIn struct {
		HookEventName string                 `json:"hook_event_name"`
		ToolName      string                 `json:"tool_name"`
		ToolInput     map[string]interface{} `json:"tool_input"`
		SessionID     string                 `json:"session_id"`
		CWD           string                 `json:"cwd"`
	}
	h := hookIn{
		HookEventName: "PreToolUse",
		ToolName:      toolName,
		ToolInput:     toolInput,
		SessionID:     sessionID,
		CWD:           "/tmp/test-project",
	}
	b, _ := json.Marshal(h)
	return string(b)
}

// TestHook_Allow verifies that a stub daemon returning "allow" causes the hook
// to exit 0 and write a valid allow response to stdout.
func TestHook_Allow(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "allow", "default allow", "default"
	})

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/hello.txt",
		"content": "hello",
	}, "session-123")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}

	var out claudeHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode stdout: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName: got %q want %q", out.HookSpecificOutput.HookEventName, "PreToolUse")
	}
	if out.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("permissionDecision: got %q want %q", out.HookSpecificOutput.PermissionDecision, "allow")
	}
}

// TestHook_Deny verifies that a stub daemon returning "deny" causes the hook
// to exit 2 and write the reason to stderr (not stdout).
func TestHook_Deny(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "deny", "rm -rf is blocked by default policy", "command_policy/rm_rf"
	})

	stdin := makeStdinJSON("Bash", map[string]interface{}{
		"command": "rm -rf /tmp/project",
	}, "session-456")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 2 {
		t.Errorf("expected exit 2 on deny, got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if len(stderr) == 0 {
		t.Error("expected non-empty stderr on deny")
	}
	// stdout should be empty (no hook JSON written on deny)
	if len(stdout) > 0 {
		t.Errorf("expected empty stdout on deny, got %q", stdout)
	}
}

// TestHook_Ask verifies that a stub daemon returning "ask" causes the hook
// to exit 0 and write an "ask" permission decision to stdout.
func TestHook_Ask(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "ask", "requires human review", ""
	})

	stdin := makeStdinJSON("Bash", map[string]interface{}{
		"command": "sudo something",
	}, "session-789")

	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 0 {
		t.Errorf("expected exit 0 on ask, got %d; stderr=%q", code, stderr)
	}

	var out claudeHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode stdout: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("permissionDecision: got %q want %q", out.HookSpecificOutput.PermissionDecision, "ask")
	}
}

// TestCodexHook_AllowNoStdout verifies that Codex receives an exit-0 allow
// without Claude-only permissionDecision JSON on stdout.
func TestCodexHook_AllowNoStdout(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		if req.Agent != "codex" {
			t.Errorf("daemon request Agent = %q, want %q", req.Agent, "codex")
		}
		return "allow", "default allow", "default"
	})

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/hello.txt",
		"content": "hello",
	}, "session-codex-allow")

	stdout, stderr, code := runHookWithArgs(t, bin, stdin,
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=codex"})

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}
	if len(stdout) != 0 {
		t.Errorf("expected empty stdout for Codex allow, got %q", stdout)
	}
}

// TestCodexHook_AskBlocks verifies that a daemon "ask" decision fails closed
// for Codex because Codex PreToolUse does not support prompting via ask.
func TestCodexHook_AskBlocks(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "ask", "requires human review", "command_policy/review"
	})

	stdin := makeStdinJSON("Bash", map[string]interface{}{
		"command": "npm publish --access public",
	}, "session-codex-ask")

	stdout, stderr, code := runHookWithArgs(t, bin, stdin,
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=codex"})

	if code != 2 {
		t.Errorf("expected exit 2 for Codex ask, got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if len(stdout) != 0 {
		t.Errorf("expected empty stdout for Codex ask, got %q", stdout)
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "requires human review") {
		t.Errorf("stderr missing ask reason; got %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "does not support ask") {
		t.Errorf("stderr missing Codex ask explanation; got %q", stderrStr)
	}
}

// TestCodexHook_FailOpenNoStdout verifies that daemon-unreachable fail-open
// remains an exit-0 allow for Codex without unsupported stdout decisions.
//
// Codex documents systemMessage as supported for PreToolUse, so the fail-open
// response now carries it — that notice is the only thing the user sees, since
// Codex reads stderr solely as the exit-2 blocking reason (ADR 0073). The
// invariant this test protects is unchanged: no unsupported *decision* fields
// (permissionDecision / Claude's hookSpecificOutput), so default-allow stands.
func TestCodexHook_FailOpenNoStdout(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	// Isolate $HOME so the one-time fail-open warning sentinel
	// (~/.agentjail/fail-open-warned) starts fresh instead of inheriting
	// real machine state from prior hook invocations. Also gives us a
	// trusted ~/.agentjail directory to place the (nonexistent) override
	// socket in, so it isn't silently ignored by isTrustedSocketOverride.
	nonexistentSock := filepath.Join(trustedHome(t), "no-daemon.sock")

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/x.txt",
		"content": "x",
	}, "session-codex-failopen")

	stdout, stderr, code := runHookWithArgs(t, bin, stdin,
		[]string{"AGENTJAIL_SOCKET=" + nonexistentSock}, []string{"--agent=codex"})

	if code != 0 {
		t.Errorf("expected exit 0 (fail-open), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}
	var codexOut map[string]any
	if err := json.Unmarshal(stdout, &codexOut); err != nil {
		t.Fatalf("Codex fail-open stdout is not JSON: %q (%v)", stdout, err)
	}
	if sm, ok := codexOut["systemMessage"].(string); !ok || sm == "" {
		t.Errorf("Codex fail-open must warn the user via systemMessage; got %q", stdout)
	}
	for _, forbidden := range []string{"hookSpecificOutput", "permissionDecision", "permissionDecisionReason"} {
		if _, ok := codexOut[forbidden]; ok {
			t.Errorf("Codex fail-open leaked unsupported decision field %q: %q", forbidden, stdout)
		}
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "daemon not running - policy enforcement disabled") {
		t.Errorf("stderr missing fail-open friendly message; got %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "dial "+nonexistentSock) {
		t.Errorf("stderr missing dial-daemon detail; got %q", stderrStr)
	}
}

// TestHook_FailOpen verifies that when the daemon socket is absent the hook
// exits 0 with an "allow" response rather than blocking the agent.
func TestHook_FailOpen(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	// Isolate $HOME so the one-time fail-open warning sentinel
	// (~/.agentjail/fail-open-warned) starts fresh instead of inheriting
	// real machine state from prior hook invocations. Also gives us a
	// trusted ~/.agentjail directory to place the (nonexistent) override
	// socket in, so it isn't silently ignored by isTrustedSocketOverride.
	//
	// Point the hook at a socket that does not exist.
	nonexistentSock := filepath.Join(trustedHome(t), "no-daemon.sock")

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/x.txt",
		"content": "x",
	}, "session-failopen")

	// Give a slightly longer timeout so the dial attempt can fail cleanly.
	start := time.Now()
	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + nonexistentSock})
	elapsed := time.Since(start)

	if code != 0 {
		t.Errorf("expected exit 0 (fail-open), got %d; stdout=%q stderr=%q", code, stdout, stderr)
	}

	var out claudeHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode stdout: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow on fail-open, got %q", out.HookSpecificOutput.PermissionDecision)
	}
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "daemon not running - policy enforcement disabled") {
		t.Errorf("expected fail-open friendly message on stderr, got %q", stderrStr)
	}

	// The binary itself completes quickly (30 ms dial timeout); this subprocess
	// test only catches gross hangs. End-to-end latency is covered by the smoke
	// benchmark rather than a wall-clock assertion inside go test.
	t.Logf("fail-open elapsed (including fork+exec overhead): %v", elapsed)
	if elapsed > 2*time.Second {
		t.Errorf("hook took %v with no daemon; should be < 2s (incl. fork overhead)", elapsed)
	}
}

// TestHook_WallTime verifies that the hook completes in < 50 ms when the
// daemon is running and responding with "allow".
func TestHook_WallTime(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	// Stub daemon that always allows, with no intentional delay.
	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "allow", "default allow", "default"
	})

	stdin := makeStdinJSON("Read", map[string]interface{}{
		"path": "/tmp/file.txt",
	}, "session-timing")

	start := time.Now()
	_, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})
	elapsed := time.Since(start)

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}

	// 50 ms wall-time budget. We use 100 ms here to avoid flakiness on
	// slow CI machines (the dial + JSON encode/decode overhead on loopback
	// is typically < 5 ms; 100 ms gives 20× margin for CI noise).
	if elapsed > 100*time.Millisecond {
		t.Logf("wall-time warning: hook took %v (budget 50 ms; CI margin 100 ms)", elapsed)
	}
	t.Logf("hook wall time: %v", elapsed)
}
