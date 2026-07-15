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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/buildinfo"
	"github.com/LuD1161/agentjail/internal/telemetry"
	"github.com/LuD1161/agentjail/internal/wire"
)

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
	// SystemMessage is surfaced to the user in the normal TUI. On an exit-0
	// allow it is the ONLY channel that reaches them — Claude Code sends hook
	// stderr to the debug log only (ADR 0073).
	SystemMessage string `json:"systemMessage,omitempty"`
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

// trustedStateDir returns the trusted agentjail state directory (~/.agentjail),
// the same directory wire.DefaultSocketPath derives the daemon socket from.
func trustedStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentjail"), nil
}

// isTrustedSocketOverride reports whether path resolves under the trusted
// agentjail state directory (~/.agentjail). AGENTJAIL_SOCKET is not in the
// shield's env allowlist (internal/sandbox/env.go), so an agent's sandboxed
// bash cannot set it for the hook's parent process today. This check is
// defense-in-depth: even if AGENTJAIL_SOCKET reaches the hook's environment
// by some other path (a misconfigured wrapper script, a future allowlist
// change, a non-shielded invocation), the override is only honored when it
// points inside the directory the user already trusts the daemon to live in
// — never at an arbitrary attacker-supplied "always allow" socket elsewhere
// on disk.
func isTrustedSocketOverride(path string) bool {
	if path == "" {
		return false
	}
	trustedDir, err := trustedStateDir()
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absTrustedDir, err := filepath.Abs(trustedDir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absTrustedDir, absPath)
	if err != nil {
		return false
	}
	// rel escapes the trusted dir if it starts with ".." (covers both the
	// exact ".." case and deeper escapes like "../../evil.sock").
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// resolveSocketPath determines the daemon socket path: AGENTJAIL_SOCKET is
// honored only when it resolves under the trusted ~/.agentjail directory
// (see isTrustedSocketOverride); otherwise (unset, or pointing elsewhere)
// the default socket path is used. This keeps existing no-override behavior
// identical while closing off arbitrary-socket redirection.
func resolveSocketPath() string {
	if override := os.Getenv("AGENTJAIL_SOCKET"); isTrustedSocketOverride(override) {
		return override
	}
	return defaultSocketPath()
}

// failOpenWarnedSentinelPath returns the path to the one-time fail-open
// warning sentinel. It lives next to the daemon socket (same agentjail state
// directory), e.g. ~/.agentjail/fail-open-warned.
//
// This sentinel is intentionally not scoped to a single session or PID: the
// hook process is short-lived (one invocation per tool call), so "once per
// session" is approximated here by "once until the daemon comes back up".
// The daemon is expected to remove this sentinel on successful startup (its
// job, not the hook's) so the warning reappears the next time it goes down.
func failOpenWarnedSentinelPath() string {
	return wire.FailOpenWarnedSentinelPath()
}

// markFailOpenWarned creates the fail-open sentinel file, recording the PID
// and timestamp of the hook invocation that first observed the daemon being
// unreachable (useful for debugging how long the daemon has been down).
func markFailOpenWarned() {
	content := fmt.Sprintf("pid=%d time=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	_ = os.WriteFile(failOpenWarnedSentinelPath(), []byte(content), 0o600)
}

// failOpenFriendlyMessage is the user-facing message shown on every fail-open
// occurrence at the "allow" level (see printFailOpenBanner in
// hookfallback.go). Historically this was shown only once per session,
// gated by the fail-open-warned sentinel; ADR 0050 replaced that with a
// loud, per-occurrence notice at every daemon_unreachable level, since a
// silent one-shot warning let protection stay off indefinitely unnoticed.
const failOpenFriendlyMessage = "agentjail: daemon not running - policy enforcement disabled (run 'agentjail doctor' to diagnose)"

// failOpenMarker emits a fail_open telemetry event immediately (synchronous,
// short timeout - we are about to os.Exit(0) so blocking briefly is
// acceptable). The fail-open-warned sentinel is still recorded (useful
// forensics for `agentjail doctor` — how long has the daemon been down) but
// no longer gates the stderr banner, which failOpenClaudeLike/failOpenCursor
// print on every occurrence via printFailOpenBanner.
// Categories: read-stdin | parse-input | dial-daemon | read-response | parse-response
//
// Audit emission is intentionally skipped here: the audit store is owned by
// the daemon process, and when the daemon is down (the only time we fail
// open) there is no store to write to, nor a way to backfill it once the
// daemon returns. Telemetry and stderr are the correct capture path.
func failOpenMarker(agent, category string) {
	markFailOpenWarned()
	// Emit telemetry best-effort: short timeout, all errors silently discarded.
	// Sent on every fail-open (not just the first) so frequency is observable.
	if tp, err := defaultTelemetryPaths(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = sendFailOpen(ctx, tp, os.Getenv, buildinfo.Version, runtime.GOOS, category)
	}
}

// failOpenClaudeLike is the Claude Code/Codex fail-open path. It loads the
// daemon-written hook-fallback sidecar (ADR 0050), prints a loud
// per-occurrence banner naming the current daemon_unreachable level, and
// then renders the resolved decision in the agent's convention: "allow"
// exits 0 as before; "deny" (from level=deny, or a degraded-mode offline
// critical-rule match) exits 2 with a reason on stderr, exactly like a
// daemon-rendered deny.
//
// toolName/toolInput/cwd carry the tool call's identity for degraded-mode
// offline matching; toolName == "" (read-stdin/parse-input failures, before
// the call's identity could ever be known) always resolves to "allow" under
// degraded (nothing to match) while still failing closed under "deny".
func failOpenClaudeLike(agent, category, detail, toolName string, toolInput map[string]interface{}, cwd string) {
	fb, _ := loadHookFallback()
	failOpenMarker(agent, category)
	printFailOpenBanner(fb.Level)
	fmt.Fprintf(os.Stderr, "agentjail-hook: detail: %s\n", detail)

	decision := resolveFailOpenDecision(fb, toolName, toolInput, cwd)
	if decision.Deny {
		fmt.Fprintf(os.Stderr, "agentjail: denied by policy (rule=%s): %s\n", decision.RuleID, decision.Reason)
		os.Exit(2)
	}

	if agent == "codex" {
		os.Exit(0)
	}
	writeAllowWithSystemMessage(decision.Reason, failOpenSystemMessage(fb.Level))
	os.Exit(0)
}

// failOpenCursor is the Cursor fail-open path — the same sidecar-driven
// decision as failOpenClaudeLike, rendered in Cursor's always-exit-0
// stdout-JSON convention (permission: allow|deny).
func failOpenCursor(category, detail, toolName string, toolInput map[string]interface{}, cwd string) {
	fb, _ := loadHookFallback()
	failOpenMarker("cursor", category)
	printFailOpenBanner(fb.Level)
	fmt.Fprintf(os.Stderr, "agentjail-hook: detail: %s\n", detail)

	decision := resolveFailOpenDecision(fb, toolName, toolInput, cwd)
	if decision.Deny {
		writeCursorDeny(decision.Reason)
	} else {
		writeCursorAllowWithMessage(decision.Reason)
	}
	os.Exit(0)
}

// printPolicyEval prints a one-line policy evaluation result to stderr.
func printPolicyEval(noColor bool, toolName, action, ruleID, reason string, ms int64) {
	switch action {
	case "deny":
		if noColor {
			fmt.Fprintf(os.Stderr, "  ✗ %s denied (%dms) — %s\n", toolName, ms, reason)
		} else {
			fmt.Fprintf(os.Stderr, "  \033[31m✗\033[0m %s \033[31mdenied\033[0m (%dms) — %s\n", toolName, ms, reason)
		}
	case "ask":
		if noColor {
			fmt.Fprintf(os.Stderr, "  ? %s ask (%dms) — %s\n", toolName, ms, reason)
		} else {
			fmt.Fprintf(os.Stderr, "  \033[33m?\033[0m %s \033[33mask\033[0m (%dms) — %s\n", toolName, ms, reason)
		}
	default:
		if noColor {
			fmt.Fprintf(os.Stderr, "  ✓ %s (%dms)\n", toolName, ms)
		} else {
			fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m %s (%dms)\n", toolName, ms)
		}
	}
}

// writeAllow writes a Claude Code "allow" hook response to stdout.
func writeAllow(reason string) {
	writeAllowWithSystemMessage(reason, "")
}

// writeAllowWithSystemMessage writes an "allow" response carrying a
// user-visible systemMessage. Used by the fail-open path, where stderr would
// otherwise be swallowed (ADR 0073). An empty msg is omitted from the JSON.
func writeAllowWithSystemMessage(reason, msg string) {
	out := claudeHookOutput{
		HookSpecificOutput: claudePermissionOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
		SystemMessage: msg,
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

// writeCursorAllowWithMessage writes a Cursor "allow" response to stdout with
// an optional user_message. Used by failOpenCursor so the friendly fail-open
// message is shown only on the first fail-open in a session; an empty
// userMessage omits the field entirely.
func writeCursorAllowWithMessage(userMessage string) {
	out := cursorHookOutput{Permission: "allow", UserMessage: userMessage}
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
	// 0. One-time shield warning (non-blocking, stderr only).
	maybeEmitShieldWarning()

	// 1. Read hook JSON from stdin.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		failOpenClaudeLike(agent, "read-stdin", err.Error(), "", nil, "")
		return
	}

	var input hookInput
	if err := json.Unmarshal(stdinBytes, &input); err != nil {
		failOpenClaudeLike(agent, "parse-input", err.Error(), "", nil, "")
		return
	}

	// 2. Determine socket path. AGENTJAIL_SOCKET can override the default for
	// tests/tooling, but only when it resolves under the trusted ~/.agentjail
	// directory (see isTrustedSocketOverride) — otherwise it is ignored.
	sockPath := resolveSocketPath()

	// 3. Connect to daemon with a short dial timeout (30 ms).
	conn, err := dialDaemon(sockPath)
	if err != nil {
		failOpenClaudeLike(agent, "dial-daemon", fmt.Sprintf("dial %s: %v", sockPath, err), input.ToolName, input.ToolInput, input.CWD)
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

	evalStart := time.Now()
	resp, err := sendAndReceive(conn, req)
	evalMs := time.Since(evalStart).Milliseconds()
	if err != nil {
		cat := "read-response"
		if isWriteErr(err) {
			cat = "dial-daemon"
		}
		failOpenClaudeLike(agent, cat, err.Error(), input.ToolName, input.ToolInput, input.CWD)
		return
	}

	// 5. Print policy eval indicator to stderr.
	noColor := os.Getenv("NO_COLOR") != ""
	printPolicyEval(noColor, input.ToolName, resp.Action, resp.RuleID, resp.Reason, evalMs)

	// 6. Translate daemon action to Claude Code exit/output convention.
	switch resp.Action {
	case "deny":
		// Exit code 2: Claude Code's fast-block path reads stderr for the reason.
		fmt.Fprintf(os.Stderr, "agentjail: denied by policy (rule=%s): %s\n", resp.RuleID, resp.Reason)
		if resp.RuleID == "mcp_policy/unknown" {
			if server := mcpServerName(input.ToolName); server != "" {
				fmt.Fprintf(os.Stderr, "  run: agentjail mcp allow %s   (see 'agentjail mcp list' for current state)\n", server)
			} else {
				fmt.Fprintf(os.Stderr, "  run: agentjail mcp allow <server-name>   (see 'agentjail mcp list' for current state)\n")
			}
		}
		if hint := denyRemediationHint(resp.RuleID); hint != "" {
			fmt.Fprintln(os.Stderr, hint)
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
		// One-time ssh-agent remediation advisory (non-blocking, stderr
		// only, allow-path only - never on deny/ask).
		maybeEmitSSHAgentWarning(input.ToolName, input.ToolInput)
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
	// 0. One-time shield warning (non-blocking, stderr only).
	maybeEmitShieldWarning()

	// 1. Read hook JSON from stdin.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		failOpenCursor("read-stdin", err.Error(), "", nil, "")
		return
	}

	// 2. Parse Cursor-format input and map to daemonRequest.
	req, err := parseCursorInput(stdinBytes)
	if err != nil {
		failOpenCursor("parse-input", err.Error(), "", nil, "")
		return
	}
	// parseCursorInput does not know the agent identity; set it here.
	req.Agent = "cursor"

	// 3. Determine socket path (see resolveSocketPath: AGENTJAIL_SOCKET is
	// honored only under the trusted ~/.agentjail directory).
	sockPath := resolveSocketPath()

	// 4. Connect to daemon.
	conn, err := dialDaemon(sockPath)
	if err != nil {
		failOpenCursor("dial-daemon", fmt.Sprintf("dial %s: %v", sockPath, err), req.ToolName, req.ToolInput, req.CWD)
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
		failOpenCursor(cat, err.Error(), req.ToolName, req.ToolInput, req.CWD)
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
		// One-time ssh-agent remediation advisory (non-blocking, stderr
		// only, allow-path only - never on deny/ask).
		maybeEmitSSHAgentWarning(req.ToolName, req.ToolInput)
		writeCursorAllow()
	}

	os.Exit(0)
}

// denyRemediationHint returns a one-line "how to unblock" hint for a deny
// decision, based on the rule_id's policy namespace. file_policy/* and
// command_policy/* are the two largest deny classes and previously got no
// remediation guidance at all (unlike mcp_policy/unknown and ask denials,
// which already had hints — see the deny/ask branches in runClaude).
// Returns "" for namespaces that already have a more specific hint, or that
// have no generic override path (e.g. resolver defaults).
func denyRemediationHint(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "file_policy/"):
		return "  to allow: add the path to file.extra_allow in ~/.agentjail/policy.yaml, or run: agentjail policy disable " + ruleID
	case strings.HasPrefix(ruleID, "command_policy/"):
		return "  to allow: run: agentjail policy disable " + ruleID + "   (see 'agentjail policy' for other options)"
	default:
		return ""
	}
}

// mcpServerName extracts the server component from an MCP tool name of the
// form "mcp__<server>__<tool>" (double-underscore separated). This mirrors
// mcp_policy.rego's mcp_server_name (split on "__", take index 1) so the deny
// hint names the exact server the agent tried to reach, letting the user
// copy-paste `agentjail mcp allow <server>` verbatim. Returns "" when toolName
// is not an MCP tool call, in which case the caller falls back to the
// <server-name> placeholder.
func mcpServerName(toolName string) string {
	parts := strings.Split(toolName, "__")
	if len(parts) < 3 || parts[0] != "mcp" {
		return ""
	}
	return parts[1]
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
