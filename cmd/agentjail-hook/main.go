// Package main is the agentjail hook binary. It is invoked by Claude Code,
// Codex (default path), or Cursor (--agent=cursor) before tool calls.
//
// The binary:
//  1. Reads the hook JSON from stdin.
//  2. Connects to the agentjail-daemon Unix socket (~/.agentjail/daemon.sock).
//  3. Sends the translated request as newline-delimited JSON.
//  4. Reads the response from the daemon.
//  5. Translates the daemon action to the agent's output convention.
//  6. On any error (daemon not running, timeout, parse failure): fails open
//     (allow) and writes a structured fail-open marker to stderr so silent
//     "always allow" drift is observable.
//
// Supported agents (--agent flag or AGENTJAIL_AGENT env var):
//   - claude (default): Deny → exit 2 (stderr reason). Allow/ask → stdout
//     hookSpecificOutput JSON.
//   - codex: Deny → exit 2 (stderr reason). Allow → exit 0 with empty stdout.
//     Ask → exit 2 because Codex PreToolUse does not support prompting.
//   - cursor: Cursor stdin/stdout differ. All decisions → exit 0; stdout JSON
//     with {"permission":"allow|deny|ask",...} (snake_case, T0-confirmed).
//
// Protocol: newline-delimited JSON over Unix domain socket. Details in
// agentpolicy/docs/DECISION_RPC.md.
//
// Architecture note: stdlib-only; no external deps; <50 ms wall-time budget.
// Dial timeout is 30 ms so a missing daemon does not block the agent.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/wire"
)

// hookVersion is set via -ldflags at build time (mirrors cmd/agentjail version).
var hookVersion = ""

var (
	defaultTelemetryPaths = telemetry.DefaultPaths
	sendFailOpen          = telemetry.SendFailOpen
)

// hookInput is the JSON Claude Code/Codex writes to the hook binary's stdin.
// The field name uses "hook_event_name" (with the _name suffix) which is
// Claude Code's convention on the stdin side; the daemon expects "hook_event"
// (without suffix) on the socket side.
type hookInput struct {
	HookEventName string                 `json:"hook_event_name"`
	ToolName      string                 `json:"tool_name"`
	ToolInput     map[string]interface{} `json:"tool_input"`
	SessionID     string                 `json:"session_id"`
	CWD           string                 `json:"cwd"`
}

// cursorShellInput is the Cursor stdin payload for beforeShellExecution.
// Top-level "command" field (not nested in tool_input).
// T0 confirmed fields.
type cursorShellInput struct {
	Command        string   `json:"command"`
	CWD            string   `json:"cwd"`
	HookEventName  string   `json:"hook_event_name"`
	WorkspaceRoots []string `json:"workspace_roots"`
}

// cursorMCPInput is the Cursor stdin payload for beforeMCPExecution.
// tool_input is an escaped JSON string, not a nested object (T0 confirmed).
type cursorMCPInput struct {
	ToolName      string `json:"tool_name"`
	ToolInput     string `json:"tool_input"` // escaped JSON string
	Command       string `json:"command"`
	HookEventName string `json:"hook_event_name"`
}

// cursorReadFileInput is the Cursor stdin payload for beforeReadFile.
// Uses "file_path" at top level.
type cursorReadFileInput struct {
	FilePath      string `json:"file_path"`
	HookEventName string `json:"hook_event_name"`
}

// cursorGenericInput is used to detect the event name before full parsing.
type cursorGenericInput struct {
	HookEventName string `json:"hook_event_name"`
}

// daemonRequest is an alias for wire.Request — the shape the daemon expects on its Unix socket.
type daemonRequest = wire.Request

// daemonResponse is an alias for wire.Response — the shape the daemon returns over the Unix socket.
// The Impact field (omitempty) is included in the canonical wire shape; the hook ignores it.
type daemonResponse = wire.Response

// claudeHookOutput is the JSON Claude Code expects on stdout when the hook
// exits 0. Claude Code's PreToolUse contract:
//
//	{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"..."}}
type claudeHookOutput struct {
	HookSpecificOutput claudePermissionOutput `json:"hookSpecificOutput"`
}

type claudePermissionOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// cursorHookOutput is the JSON Cursor reads from stdout. snake_case per T0.
// Cursor always uses exit 0 and reads the JSON.
type cursorHookOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// defaultSocketPath returns ~/.agentjail/daemon.sock via wire.DefaultSocketPath.
func defaultSocketPath() string {
	return wire.DefaultSocketPath()
}

// failOpenMarker writes the structured fail-open marker to stderr and emits a
// fail_open telemetry event immediately (synchronous, short timeout — we are
// about to os.Exit(0) so blocking briefly is acceptable).
// Format: "agentjail-hook: fail-open agent=<agent> reason=<category>"
// Categories: read-stdin | parse-input | dial-daemon | read-response | parse-response
func failOpenMarker(agent, category string) {
	fmt.Fprintf(os.Stderr, "agentjail-hook: fail-open agent=%s reason=%s\n", agent, category)
	// Emit telemetry best-effort: short timeout, all errors silently discarded.
	if tp, err := defaultTelemetryPaths(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = sendFailOpen(ctx, tp, os.Getenv, hookVersion, runtime.GOOS, category)
	}
}

// failOpenClaudeLike writes a structured fail-open marker to stderr and emits
// the agent's allow response, then exits 0.
func failOpenClaudeLike(agent, category, detail string) {
	failOpenMarker(agent, category)
	fmt.Fprintf(os.Stderr, "agentjail-hook: detail: %s\n", detail)
	if agent == "codex" {
		os.Exit(0)
	}
	writeAllow("daemon unreachable — fail-open")
	os.Exit(0)
}

// failOpenCursor writes a structured fail-open marker to stderr and emits a
// Cursor "allow" response to stdout, then exits 0.
func failOpenCursor(category, detail string) {
	failOpenMarker("cursor", category)
	fmt.Fprintf(os.Stderr, "agentjail-hook: detail: %s\n", detail)
	writeCursorAllow()
	os.Exit(0)
}

// writeAllow writes a Claude Code "allow" hook response to stdout.
func writeAllow(reason string) {
	out := claudeHookOutput{
		HookSpecificOutput: claudePermissionOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

// writeAsk writes a Claude Code "ask" hook response to stdout.
func writeAsk(reason string) {
	out := claudeHookOutput{
		HookSpecificOutput: claudePermissionOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: reason,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

// writeCursorAllow writes a Cursor "allow" response to stdout.
func writeCursorAllow() {
	out := cursorHookOutput{Permission: "allow"}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

// writeCursorDeny writes a Cursor "deny" response to stdout.
func writeCursorDeny(reason string) {
	out := cursorHookOutput{
		Permission:   "deny",
		AgentMessage: reason,
		UserMessage:  reason,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

// writeCursorAsk writes a Cursor "ask" response to stdout.
func writeCursorAsk(reason string) {
	out := cursorHookOutput{
		Permission:  "ask",
		UserMessage: reason,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}

// parseCursorInput parses the raw stdin bytes for the Cursor adapter and
// returns a daemonRequest ready to send to the daemon.
// Returns an error when the input cannot be parsed.
func parseCursorInput(stdinBytes []byte) (daemonRequest, error) {
	// First detect the event name.
	var generic cursorGenericInput
	if err := json.Unmarshal(stdinBytes, &generic); err != nil {
		return daemonRequest{}, fmt.Errorf("parse hook_event_name: %w", err)
	}

	var req daemonRequest

	switch generic.HookEventName {
	case "beforeShellExecution":
		var inp cursorShellInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, fmt.Errorf("parse beforeShellExecution: %w", err)
		}
		req = daemonRequest{
			ID:        "cursor-shell",
			HookEvent: "beforeShellExecution",
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": inp.Command},
			CWD:       inp.CWD,
		}

	case "beforeReadFile":
		var inp cursorReadFileInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, fmt.Errorf("parse beforeReadFile: %w", err)
		}
		req = daemonRequest{
			ID:        "cursor-readfile",
			HookEvent: "beforeReadFile",
			ToolName:  "Read",
			ToolInput: map[string]interface{}{"file_path": inp.FilePath},
		}

	case "beforeMCPExecution":
		var inp cursorMCPInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, fmt.Errorf("parse beforeMCPExecution: %w", err)
		}
		// tool_input is an escaped JSON string in beforeMCPExecution (T0 confirmed).
		// Parse it into a map for the daemon.
		var toolInput map[string]interface{}
		if inp.ToolInput != "" {
			if err := json.Unmarshal([]byte(inp.ToolInput), &toolInput); err != nil {
				// If we can't parse the escaped JSON, wrap it as a raw string.
				toolInput = map[string]interface{}{"raw": inp.ToolInput}
			}
		}
		req = daemonRequest{
			ID:        "cursor-mcp",
			HookEvent: "beforeMCPExecution",
			ToolName:  inp.ToolName,
			ToolInput: toolInput,
		}

	default:
		return daemonRequest{}, fmt.Errorf("unknown cursor hook_event_name: %q", generic.HookEventName)
	}

	return req, nil
}

// dialDaemon connects to the daemon socket with a 30 ms timeout.
func dialDaemon(sockPath string) (net.Conn, error) {
	return net.DialTimeout("unix", sockPath, 30*time.Millisecond)
}

// sendAndReceive sends req to conn and reads the daemon response.
func sendAndReceive(conn net.Conn, req daemonRequest) (daemonResponse, error) {
	// Set an overall deadline for the daemon round-trip.
	// 45 ms leaves headroom below the 50 ms wall-time budget.
	if err := conn.SetDeadline(time.Now().Add(45 * time.Millisecond)); err != nil {
		// Non-fatal — continue without deadline.
		fmt.Fprintf(os.Stderr, "agentjail-hook: set deadline: %v\n", err)
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return daemonResponse{}, fmt.Errorf("write request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	// 1 MB line buffer matches the daemon's scanner buffer.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	if !scanner.Scan() {
		scanErr := scanner.Err()
		if scanErr == nil {
			scanErr = io.EOF
		}
		return daemonResponse{}, fmt.Errorf("read response: %w", scanErr)
	}

	var resp daemonResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return daemonResponse{}, fmt.Errorf("parse response: %w", err)
	}

	return resp, nil
}

func main() {
	// Determine which agent mode to use.
	// Priority: --agent flag > AGENTJAIL_AGENT env var > default "claude".
	agent := os.Getenv("AGENTJAIL_AGENT")
	if agent == "" {
		agent = "claude"
	}

	// Parse --agent flag from os.Args (simple linear scan; no flag package
	// import needed and avoids breaking existing callers who pass no flags).
	for i, arg := range os.Args[1:] {
		if arg == "--agent=cursor" {
			agent = "cursor"
		} else if arg == "--agent=claude" {
			agent = "claude"
		} else if arg == "--agent=codex" {
			agent = "codex"
		} else if arg == "--agent" && i+2 < len(os.Args) {
			agent = os.Args[i+2]
		}
	}

	switch agent {
	case "cursor":
		runCursor()
	default:
		// "claude", "codex", and any unrecognised value use the claude/codex path.
		runClaude(agent)
	}
}

// runClaude implements the default (Claude Code / Codex) hook path.
// The agent parameter carries the resolved agent identity string (e.g. "claude",
// "codex") and is forwarded to the daemon on the outgoing request.
func runClaude(agent string) {
	// 1. Read hook JSON from stdin.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		failOpenClaudeLike(agent, "read-stdin", err.Error())
		return
	}

	var input hookInput
	if err := json.Unmarshal(stdinBytes, &input); err != nil {
		failOpenClaudeLike(agent, "parse-input", err.Error())
		return
	}

	// 2. Determine socket path (can be overridden for tests via AGENTJAIL_SOCKET).
	sockPath := os.Getenv("AGENTJAIL_SOCKET")
	if sockPath == "" {
		sockPath = defaultSocketPath()
	}

	// 3. Connect to daemon with a short dial timeout (30 ms).
	conn, err := dialDaemon(sockPath)
	if err != nil {
		failOpenClaudeLike(agent, "dial-daemon", fmt.Sprintf("dial %s: %v", sockPath, err))
		return
	}
	defer conn.Close()

	// 4. Build and send the daemon request.
	req := daemonRequest{
		ID:        "hook-" + input.SessionID + "-" + input.ToolName,
		HookEvent: input.HookEventName,
		ToolName:  input.ToolName,
		ToolInput: input.ToolInput,
		SessionID: input.SessionID,
		CWD:       input.CWD,
		Agent:     agent,
		AgentPID:  findAgentPID(),
	}

	resp, err := sendAndReceive(conn, req)
	if err != nil {
		cat := "read-response"
		if isWriteErr(err) {
			cat = "dial-daemon"
		}
		failOpenClaudeLike(agent, cat, err.Error())
		return
	}

	// 5. Translate daemon action to Claude Code exit/output convention.
	switch resp.Action {
	case "deny":
		// Exit code 2: Claude Code's fast-block path reads stderr for the reason.
		fmt.Fprintf(os.Stderr, "agentjail: denied by policy (rule=%s): %s\n", resp.RuleID, resp.Reason)
		// For MCP unknown-server denials, add the exact remediation so the user
		// knows how to grant access without digging through docs.
		if resp.RuleID == "mcp_policy/unknown" {
			fmt.Fprintf(os.Stderr, "  run: agentjail mcp allow <server-name>   (see 'agentjail mcp list' for current state)\n")
		}
		os.Exit(2)

	case "ask":
		if agent == "codex" {
			fmt.Fprintf(os.Stderr, "agentjail: ask requires human review but Codex PreToolUse does not support ask; denied by policy (rule=%s): %s\n", resp.RuleID, resp.Reason)
			os.Exit(2)
		}
		writeAsk(resp.Reason)
		if resp.RuleID != "" && resp.RuleID != "resolver/default" {
			fmt.Fprintf(os.Stderr, "agentjail: to disable this check permanently: agentjail policy disable %s\n", resp.RuleID)
		}
		os.Exit(0)

	default:
		// "allow" or any unrecognised action → allow (fail-open semantics for
		// unknown future action values).
		if agent == "codex" {
			os.Exit(0)
		}
		writeAllow(resp.Reason)
		os.Exit(0)
	}
}

// runCursor implements the Cursor hook adapter (--agent=cursor).
// All decisions exit 0; stdout carries the Cursor JSON response.
func runCursor() {
	// 1. Read hook JSON from stdin.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		failOpenCursor("read-stdin", err.Error())
		return
	}

	// 2. Parse Cursor-format input and map to daemonRequest.
	req, err := parseCursorInput(stdinBytes)
	if err != nil {
		failOpenCursor("parse-input", err.Error())
		return
	}
	// parseCursorInput does not know the agent identity; set it here.
	req.Agent = "cursor"

	// 3. Determine socket path.
	sockPath := os.Getenv("AGENTJAIL_SOCKET")
	if sockPath == "" {
		sockPath = defaultSocketPath()
	}

	// 4. Connect to daemon.
	conn, err := dialDaemon(sockPath)
	if err != nil {
		failOpenCursor("dial-daemon", fmt.Sprintf("dial %s: %v", sockPath, err))
		return
	}
	defer conn.Close()

	// 5. Send and receive.
	resp, err := sendAndReceive(conn, req)
	if err != nil {
		cat := "read-response"
		if isWriteErr(err) {
			cat = "dial-daemon"
		}
		failOpenCursor(cat, err.Error())
		return
	}

	// 6. Translate daemon action to Cursor's stdout JSON (exit 0 always).
	switch resp.Action {
	case "deny":
		writeCursorDeny(resp.Reason)

	case "ask":
		writeCursorAsk(resp.Reason)

	default:
		// "allow" or unknown → allow.
		writeCursorAllow()
	}

	os.Exit(0)
}

// isWriteErr is a heuristic to distinguish write/send errors from read errors
// when categorising fail-open reasons. Not perfect but good enough for the
// structured marker.
func isWriteErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) >= 5 && msg[:5] == "write"
}
