package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
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
		if req.ToolName != "mcp__github_mcp_server__create_issue" {
			t.Errorf("daemon: tool_name = %q, want %q", req.ToolName, "mcp__github_mcp_server__create_issue")
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

	// Isolate $HOME so the one-time fail-open warning sentinel
	// (~/.agentjail/fail-open-warned) starts fresh instead of inheriting
	// real machine state from prior hook invocations. Also gives us a
	// trusted ~/.agentjail directory to place the (nonexistent) override
	// socket in, so it isn't silently ignored by isTrustedSocketOverride.
	nonexistentSock := filepath.Join(trustedHome(t), "no-daemon.sock")

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

	// The one-time friendly fail-open message must appear on stderr.
	stderrStr := string(stderr)
	if !strings.Contains(stderrStr, "daemon not running - policy enforcement disabled") {
		t.Errorf("stderr missing fail-open friendly message; got: %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "dial "+nonexistentSock) {
		t.Errorf("stderr missing dial-daemon detail; got: %q", stderrStr)
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

	ln, err := net.Listen("unix", filepath.Join(trustedHome(t), "map-test.sock"))
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
	if capturedReq.HookEvent != canonicalPreToolUse {
		t.Errorf("HookEvent = %q, want %q", capturedReq.HookEvent, canonicalPreToolUse)
	}
}

func TestParseCursorInputNormalizesCanonicalRequest(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTool  string
		wantCWD   string
		wantEvent cursorHookEvent
	}{
		{
			name: "shell falls back to workspace root",
			input: `{
				"hook_event_name":"beforeShellExecution",
				"command":"git status",
				"cwd":"",
				"workspace_roots":["/workspace/project"]
			}`,
			wantTool:  "Bash",
			wantCWD:   "/workspace/project",
			wantEvent: cursorBeforeShellExecution,
		},
		{
			name: "read selects containing root",
			input: `{
				"hook_event_name":"beforeReadFile",
				"file_path":"/workspace/api/main.go",
				"workspace_roots":["/workspace/web","/workspace/api"]
			}`,
			wantTool:  "Read",
			wantCWD:   "/workspace/api",
			wantEvent: cursorBeforeReadFile,
		},
		{
			name: "slash MCP name carries server",
			input: `{
				"hook_event_name":"beforeMCPExecution",
				"tool_name":"github/create_issue",
				"tool_input":"{}",
				"workspace_roots":["/workspace/project"]
			}`,
			wantTool:  "mcp__github__create_issue",
			wantCWD:   "/workspace/project",
			wantEvent: cursorBeforeMCPExecution,
		},
		{
			name: "bare MCP name uses simple command identity",
			input: `{
				"hook_event_name":"beforeMCPExecution",
				"tool_name":"create_invoice",
				"tool_input":"{}",
				"command":"stripe-mcp"
			}`,
			wantTool:  "mcp__stripe-mcp__create_invoice",
			wantEvent: cursorBeforeMCPExecution,
		},
		{
			name: "URL MCP uses hostname when command is not an identifier",
			input: `{
				"hook_event_name":"beforeMCPExecution",
				"tool_name":"fetch",
				"tool_input":"{}",
				"command":"npx -y remote-mcp",
				"url":"https://mcp.example.com/rpc"
			}`,
			wantTool:  "mcp__mcp.example.com__fetch",
			wantEvent: cursorBeforeMCPExecution,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, event, err := parseCursorInput([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseCursorInput: %v", err)
			}
			if req.HookEvent != canonicalPreToolUse {
				t.Errorf("HookEvent = %q, want %q", req.HookEvent, canonicalPreToolUse)
			}
			if req.ToolName != tt.wantTool {
				t.Errorf("ToolName = %q, want %q", req.ToolName, tt.wantTool)
			}
			if req.CWD != tt.wantCWD {
				t.Errorf("CWD = %q, want %q", req.CWD, tt.wantCWD)
			}
			if event != tt.wantEvent {
				t.Errorf("source event = %q, want %q", event, tt.wantEvent)
			}
		})
	}
}

func TestCursorHook_ReadAskRendersDeny(t *testing.T) {
	dir := t.TempDir()
	bin := buildHook(t, dir)
	sockPath := stubDaemon(t, dir, func(req daemonRequest) (string, string, string) {
		return "ask", "review this file read", "file_policy/sensitive_in_project"
	})
	input := `{
		"hook_event_name":"beforeReadFile",
		"file_path":"/workspace/project/.env",
		"workspace_roots":["/workspace/project"]
	}`

	stdout, stderr, code := runHookWithArgs(t, bin, input,
		[]string{"AGENTJAIL_SOCKET=" + sockPath}, []string{"--agent=cursor"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr)
	}
	var out cursorHookOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("decode cursor stdout: %v (stdout=%q)", err, stdout)
	}
	if out.Permission != "deny" {
		t.Errorf("permission = %q, want deny", out.Permission)
	}
}

func TestCursorRequestsFireCanonicalPolicies(t *testing.T) {
	policyFiles := []string{"resolver.rego", "file_policy.rego", "command_policy.rego", "mcp_policy.rego"}
	modules := make([][2]string, 0, len(policyFiles))
	for _, name := range policyFiles {
		src, err := os.ReadFile(filepath.Join("..", "..", "agentpolicy", "policies", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		modules = append(modules, [2]string{name, string(src)})
	}
	cfg := config.Default()
	eng, err := policy.NewHookOPAEngineWithData(context.Background(), modules, map[string]interface{}{
		"config": cfg.ToOPAData(),
	})
	if err != nil {
		t.Fatalf("compile policies: %v", err)
	}

	tests := []struct {
		name       string
		input      string
		wantAction string
		wantRule   string
	}{
		{
			name:       "dangerous shell is denied",
			input:      `{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/workspace/project"}`,
			wantAction: "deny",
			wantRule:   "command_policy/no-rm-rf-absolute",
		},
		{
			name:       "in-workspace read is allowed",
			input:      `{"hook_event_name":"beforeReadFile","file_path":"/workspace/project/main.go","workspace_roots":["/workspace/project"]}`,
			wantAction: "allow",
			wantRule:   "file_policy/project_allow",
		},
		{
			name:       "blocked MCP server is denied",
			input:      `{"hook_event_name":"beforeMCPExecution","tool_name":"create_invoice","tool_input":"{}","command":"stripe-mcp"}`,
			wantAction: "deny",
			wantRule:   "mcp_policy/blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _, err := parseCursorInput([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseCursorInput: %v", err)
			}
			got, err := eng.Eval(context.Background(), policy.HookInput{
				HookEvent: req.HookEvent,
				ToolName:  req.ToolName,
				ToolInput: req.ToolInput,
				CWD:       req.CWD,
			})
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got.Action != tt.wantAction || got.RuleID != tt.wantRule {
				t.Errorf("decision = (%q, %q), want (%q, %q)", got.Action, got.RuleID, tt.wantAction, tt.wantRule)
			}
		})
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

	// Isolate $HOME so the one-time fail-open warning sentinel
	// (~/.agentjail/fail-open-warned) starts fresh instead of inheriting
	// real machine state from prior hook invocations. Also gives us a
	// trusted ~/.agentjail directory to place the (nonexistent) override
	// socket in, so it isn't silently ignored by isTrustedSocketOverride.
	nonexistentSock := filepath.Join(trustedHome(t), "absent.sock")

	stdinBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agents", "testdata", "cursor_before_shell_input.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	_, stderr, _ := runHookWithArgs(t, bin, string(stdinBytes),
		[]string{"AGENTJAIL_SOCKET=" + nonexistentSock}, []string{"--agent=cursor"})

	stderrStr := string(stderr)
	// Must contain the one-time friendly fail-open message.
	if !strings.Contains(stderrStr, "daemon not running - policy enforcement disabled") {
		t.Errorf("stderr missing fail-open friendly message; got: %q", stderrStr)
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
