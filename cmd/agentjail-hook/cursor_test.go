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
)

// cursorStubDaemon is like stubDaemon but serves multiple connections so that
// multiple cursor test cases can reuse it, each triggering one accept.
// For simplicity each test creates its own stub.

// NOTE: tests use runHookWithArgs directly with []string{"--agent=cursor"}.

// TestCursorHook_ShellDeny verifies that a beforeShellExecution payload that
// the daemon denies produces {"permission":"deny",...} on stdout, exit 0.
func TestCursorHook_ShellDeny(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "deny", "rm -rf outside project directory", "command_policy/rm_rf"
	})

	// Read the golden fixture.
	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, stderr, code := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0 on cursor deny, got %d; stderr=%q stdout=%q", code, stderr, stdout)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "deny" {
		t.Errorf("permission = %q, want %q", out.Permission, "deny")
	}
	if out.AgentMessage == "" && out.UserMessage == "" {
		t.Error("expected non-empty agent_message or user_message on deny")
	}
}

// TestCursorHook_ShellAllow verifies that an allowed shell command produces
// {"permission":"allow"} on stdout, exit 0.
func TestCursorHook_ShellAllow(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "allow", "", ""
	})

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, stderr, code := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "allow" {
		t.Errorf("permission = %q, want %q", out.Permission, "allow")
	}
}

// TestCursorHook_ShellAsk verifies that an "ask" daemon response produces
// {"permission":"ask","user_message":...} on stdout, exit 0.
func TestCursorHook_ShellAsk(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "ask", "this command is outside the normal project scope.", ""
	})

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, stderr, code := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0 on cursor ask, got %d; stderr=%q", code, stderr)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "ask" {
		t.Errorf("permission = %q, want %q", out.Permission, "ask")
	}
	if out.UserMessage == "" {
		t.Error("expected non-empty user_message on ask")
	}
}

// TestCursorHook_MCPDeny verifies the beforeMCPExecution path with a deny.
func TestCursorHook_MCPDeny(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		// Verify the daemon sees the right tool name.
		if req.ToolName != "github_mcp_server/create_issue" {
			t.Errorf("daemon: tool_name = %q, want %q", req.ToolName, "github_mcp_server/create_issue")
		}
		return "deny", "MCP tool blocked", "mcp_policy"
	})

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_mcp_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, _, code := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0 on cursor MCP deny, got %d", code)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "deny" {
		t.Errorf("permission = %q, want %q", out.Permission, "deny")
	}
}

// TestCursorHook_DaemonUnreachable verifies fail-open behaviour when the
// daemon socket does not exist: stdout gets {"permission":"allow"} exit 0,
// and stderr contains the structured fail-open marker.
func TestCursorHook_DaemonUnreachable(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	nonexistentSock := filepath.Join(dir, "no-daemon.sock")

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	stdout, stderr, code := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + nonexistentSock}, []string{"--agent=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0 (fail-open), got %d; stderr=%q stdout=%q", code, stderr, stdout)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "allow" {
		t.Errorf("permission = %q, want %q (fail-open)", out.Permission, "allow")
	}

	// Structured fail-open marker must appear on stderr.
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "fail-open agent=cursor") {
		t.Errorf("stderr missing fail-open marker; got: %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "reason=dial-daemon") {
		t.Errorf("stderr missing reason=dial-daemon; got: %q", stderrStr)
	}
}

// TestCursorHook_AgentEnvVar verifies that AGENTJAIL_AGENT=cursor selects the
// cursor adapter without the --agent flag.
func TestCursorHook_AgentEnvVar(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "allow", "", ""
	})

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Use AGENTJAIL_AGENT=cursor instead of --agent=cursor flag.
	stdout, stderr, code := runHook(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath, "AGENTJAIL_AGENT=cursor"})

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}

	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "allow" {
		t.Errorf("permission = %q, want %q", out.Permission, "allow")
	}
}

// TestCursorHook_ShellRequestMapping verifies that a beforeShellExecution
// payload is mapped to tool_name="Bash" with tool_input.command set.
func TestCursorHook_ShellRequestMapping(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	var capturedReq daemonRequest

	ln, err := net.Listen("unix", filepath.Join(dir, "map-test.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sockPath := ln.Addr().String()
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
		if scanner.Scan() {
			_ = json.Unmarshal(scanner.Bytes(), &capturedReq)
		}

		resp := daemonResponse{ID: capturedReq.ID, Action: "allow"}
		enc := json.NewEncoder(conn)
		_ = enc.Encode(resp)
	}()

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, _, _ = runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})

	if capturedReq.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want %q", capturedReq.ToolName, "Bash")
	}
	cmd, _ := capturedReq.ToolInput["command"].(string)
	if cmd != "rm -rf /tmp/foo" {
		t.Errorf("ToolInput.command = %q, want %q", cmd, "rm -rf /tmp/foo")
	}
	if capturedReq.HookEvent != "beforeShellExecution" {
		t.Errorf("HookEvent = %q, want %q", capturedReq.HookEvent, "beforeShellExecution")
	}
}

// TestDefaultClaudePathUnchanged verifies that the default (claude) path still
// produces the existing Claude Code hookSpecificOutput JSON on stdout.
// This is a regression guard for the T4 changes.
func TestDefaultClaudePathUnchanged(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)

	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "allow", "default allow", "default"
	})

	stdin := makeStdinJSON("Write", map[string]interface{}{
		"path":    "/tmp/hello.txt",
		"content": "hello",
	}, "session-default")

	// No --agent flag → default claude path.
	stdout, stderr, code := runHook(t, bin, stdin, []string{"AGENTJAIL_SOCKET=" + sockPath})

	if code != 0 {
		t.Errorf("expected exit 0, got %d; stderr=%q", code, stderr)
	}

	var out claudeHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode stdout: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want %q", out.HookSpecificOutput.HookEventName, "PreToolUse")
	}
	if out.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "allow")
	}
}

// TestCursorHook_FailOpenMarkerOnStderr verifies that the structured fail-open
// marker is emitted to stderr (not stdout) on daemon unreachable.
func TestCursorHook_FailOpenMarkerOnStderr(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	nonexistentSock := filepath.Join(dir, "absent.sock")

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, stderr, _ := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + nonexistentSock}, []string{"--agent=cursor"})

	stderrStr := string(stderr)
	// Must contain the fail-open marker prefix.
	if !strings.HasPrefix(stderrStr, "agentjail-hook: fail-open") {
		t.Errorf("stderr does not start with fail-open marker; got: %q", stderrStr)
	}
}

// ---- helpers -----------------------------------------------------------------

// runHookWithArgs is like runHook but also accepts extra CLI args for the
// hook binary (e.g. []string{"--agent=cursor"}).
func runHookWithArgs(t *testing.T, bin string, stdinJSON string, env []string, args []string) ([]byte, []byte, int) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmdArgs := append([]string{}, args...)
	cmd := exec.Command(bin, cmdArgs...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = bytes.NewBufferString(stdinJSON)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		type exitCoder interface{ ExitCode() int }
		if ee, ok := err.(exitCoder); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("run hook with args %v: %v", args, err)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode
}
