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
//   - codex: SessionStart/Stop → live enforcement systemMessage. PreToolUse
//     deny → exit 2; allow → exit 0 with empty stdout; eligible Bash asks
//     → one-use approval-broker rewrite; every other ask → exit 2. Its
//     PermissionRequest event returns allow/deny or declines an ask so Codex's
//     own approval UI remains authoritative when it is already prompting.
//   - cursor: Cursor stdin/stdout differ. All decisions → exit 0; stdout JSON
//     with {"permission":"allow|deny|ask",...}; beforeReadFile supports only
//     allow/deny, so an ask is rendered as deny.
//
// Protocol: newline-delimited JSON over Unix domain socket. Details in
// agentpolicy/docs/DECISION_RPC.md.
//
// Architecture note: stdlib-only; no external deps; typical p95 target <50 ms.
// Dial timeout is 30 ms; healthy-response ceilings are request-specific.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/agentpolicy"
	"github.com/LuD1161/agentjail/internal/approvalexec"
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
	TurnID        string                 `json:"turn_id,omitempty"`
	CWD           string                 `json:"cwd"`
	// PermissionMode is Codex's current mode and is retained in adapter input.
	PermissionMode string `json:"permission_mode,omitempty"`
	// ToolUseID is the per-tool-call id on current Claude Code and Codex
	// PreToolUse/PostToolUse events. Older agents fall back to a stable hash.
	ToolUseID string `json:"tool_use_id"`
	// ToolResponse is Claude Code's PostToolUse-only payload carrying the
	// tool's result. Codex also uses this field, but its value is tool-specific.
	// Outcome handling decodes the agent-specific evidence into typed structs.
	ToolResponse json.RawMessage `json:"tool_response,omitempty"`
	// Error and IsInterrupt are Claude Code's PostToolUseFailure fields.
	// PostToolUse is success-only as of Claude Code 2.1.216.
	Error       string `json:"error,omitempty"`
	IsInterrupt bool   `json:"is_interrupt,omitempty"`
}

type cursorHookEvent string

const (
	cursorBeforeShellExecution cursorHookEvent = "beforeShellExecution"
	cursorBeforeMCPExecution   cursorHookEvent = "beforeMCPExecution"
	cursorBeforeReadFile       cursorHookEvent = "beforeReadFile"
	canonicalPreToolUse                        = "PreToolUse"
	codexPermissionRequest                     = "PermissionRequest"
	codexSessionStart                          = "SessionStart"
	codexStop                                  = "Stop"
	claudePostToolUseFailure                   = "PostToolUseFailure"
)

// cursorShellInput is the Cursor stdin payload for beforeShellExecution.
// Top-level "command" field (not nested in tool_input).
// T0 confirmed fields.
type cursorShellInput struct {
	Command        string          `json:"command"`
	CWD            string          `json:"cwd"`
	HookEventName  cursorHookEvent `json:"hook_event_name"`
	WorkspaceRoots []string        `json:"workspace_roots"`
}

// cursorMCPInput is the Cursor stdin payload for beforeMCPExecution.
// tool_input is an escaped JSON string, not a nested object (T0 confirmed).
type cursorMCPInput struct {
	ToolName       string          `json:"tool_name"`
	ToolInput      string          `json:"tool_input"` // escaped JSON string
	Command        string          `json:"command"`
	URL            string          `json:"url"`
	HookEventName  cursorHookEvent `json:"hook_event_name"`
	WorkspaceRoots []string        `json:"workspace_roots"`
}

// cursorReadFileInput is the Cursor stdin payload for beforeReadFile.
// Uses "file_path" at top level.
type cursorReadFileInput struct {
	FilePath       string          `json:"file_path"`
	HookEventName  cursorHookEvent `json:"hook_event_name"`
	WorkspaceRoots []string        `json:"workspace_roots"`
}

// cursorGenericInput is used to detect the event name before full parsing.
type cursorGenericInput struct {
	HookEventName cursorHookEvent `json:"hook_event_name"`
}

// daemonRequest is an alias for wire.Request — the shape the daemon expects on its Unix socket.
type daemonRequest = wire.Request

// daemonResponse is an alias for wire.Response — the shape the daemon returns over the Unix socket.
// The Impact field (omitempty) is included in the canonical wire shape; the hook ignores it.
type daemonResponse = wire.Response

// renderedAction uses the daemon's agent-specific response translation when
// present. The fallback keeps hooks compatible with a daemon from before ADR
// 0114 while preserving the wire protocol's canonical Action field.
func renderedAction(resp daemonResponse, agent, hookEvent string) string {
	if resp.EffectiveAction != "" {
		return resp.EffectiveAction
	}
	policyAction := resp.Action
	if resp.WouldAction != "" {
		policyAction = resp.WouldAction
	}
	return string(agentpolicy.Normalize(agentpolicy.Request{
		Agent:          agent,
		HookEvent:      hookEvent,
		PolicyAction:   agentpolicy.Action(policyAction),
		EnforcedAction: agentpolicy.Action(resp.Action),
	}).EffectiveAction)
}

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
		writeCodexSystemMessage(failOpenSystemMessage(fb.Level))
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
		// decision.Reason already carries restartInstructions on every deny path.
		writeCursorDeny(decision.Reason)
	} else {
		// Not decision.Reason: it omits restartInstructions at levelAllow, and
		// Cursor has no status line to carry the notice instead (ADR 0073).
		writeCursorAllowWithMessage(failOpenSystemMessage(fb.Level))
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

// codexSystemMessageOutput is the minimal Codex PreToolUse response: a
// systemMessage and nothing else. Codex's allow convention is an empty
// stdout, so omitting permissionDecision keeps the default-allow semantics
// and adds only the warning (ADR 0073).
type codexSystemMessageOutput struct {
	SystemMessage string `json:"systemMessage"`
}

type codexApprovalRewriteOutput struct {
	SystemMessage      string                             `json:"systemMessage"`
	HookSpecificOutput codexApprovalRewriteSpecificOutput `json:"hookSpecificOutput"`
}

type codexApprovalRewriteSpecificOutput struct {
	HookEventName      string                 `json:"hookEventName"`
	PermissionDecision string                 `json:"permissionDecision"`
	UpdatedInput       map[string]interface{} `json:"updatedInput"`
}

type codexLifecycleOutput struct {
	Continue      bool   `json:"continue"`
	SystemMessage string `json:"systemMessage"`
}

// codexPermissionRequestOutput is the current Codex PermissionRequest schema.
// Its decision is deliberately distinct from PreToolUse's permissionDecision.
// See ADR 0114-codex-permission-request.
type codexPermissionRequestOutput struct {
	HookSpecificOutput codexPermissionSpecificOutput `json:"hookSpecificOutput"`
}

type codexPermissionSpecificOutput struct {
	HookEventName string                  `json:"hookEventName"`
	Decision      codexPermissionDecision `json:"decision"`
}

type codexPermissionDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

// writeCodexSystemMessage emits a user-visible warning on Codex's allow path.
// Codex documents systemMessage as supported for PreToolUse and surfaces it as
// a warning; stderr is only read as the blocking reason on exit 2, so this is
// the fail-open path's only channel to the user (ADR 0073).
func writeCodexSystemMessage(msg string) {
	if msg == "" {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(codexSystemMessageOutput{SystemMessage: msg})
}

func writeCodexApprovalRewrite(operation string, challenge approvalexec.ChallengeID, display string) bool {
	command, ok := codexApprovalBrokerCommand(operation, challenge)
	if !ok {
		return false
	}
	_ = json.NewEncoder(os.Stdout).Encode(codexApprovalRewriteOutput{
		SystemMessage: "🔐 AgentJail approval required for:\n$ " + display,
		HookSpecificOutput: codexApprovalRewriteSpecificOutput{
			HookEventName:      canonicalPreToolUse,
			PermissionDecision: "allow",
			UpdatedInput: map[string]interface{}{
				"command": command,
			},
		},
	})
	return true
}

func codexApprovalOperation(resp daemonResponse) string {
	if validCodexApprovalOperation(resp.ApprovalOperation) {
		return resp.ApprovalOperation
	}
	if legacyCodexGitApprovalRule(resp.RuleID) {
		return string(approvalexec.GitPushOperation)
	}
	return ""
}

func legacyCodexGitApprovalRule(ruleID string) bool {
	switch ruleID {
	case "command_policy/confirm-git-push", "command_policy/confirm-git-push-force":
		return true
	default:
		return false
	}
}

func codexApprovalBrokerCommand(operation string, challenge approvalexec.ChallengeID) (string, bool) {
	invocation := approvalexec.BrokerInvocation{
		Operation:   approvalexec.Operation(operation),
		ChallengeID: challenge,
	}
	if !approvalexec.ValidOperation(invocation.Operation) {
		return "", false
	}
	command := approvalexec.BrokerCommand(invocation)
	parsed, ok := approvalexec.ParseBrokerCommand(command)
	if !ok || parsed != invocation {
		return "", false
	}
	return command, true
}

func validCodexApprovalOperation(operation string) bool {
	return approvalexec.ValidOperation(approvalexec.Operation(operation))
}

func codexApprovalCapabilities() []string {
	return []string{
		wire.CapabilityCodexShellApprovalV1,
		wire.CapabilityCodexApprovalBridgeV1,
	}
}

func writeCodexLifecycleAttestation() {
	shielded := os.Getenv("AGENTJAIL_SHIELDED") == "1"
	daemonActive := false
	if conn, err := dialDaemon(resolveSocketPath()); err == nil {
		daemonActive = true
		_ = conn.Close()
	}

	message := "⚠ AgentJail: OS sandbox inactive"
	if shielded && daemonActive {
		message = "🔒 AgentJail: sandbox + policy active"
	} else if shielded {
		message = "⚠ AgentJail: sandbox active, policy daemon offline"
	}
	_ = json.NewEncoder(os.Stdout).Encode(codexLifecycleOutput{
		Continue:      true,
		SystemMessage: message,
	})
}

// writeCodexPermissionDecision answers a Codex-native approval request. An
// ask deliberately writes nothing: Codex then shows its ordinary approval UI.
func writeCodexPermissionDecision(behavior, message string) {
	out := codexPermissionRequestOutput{
		HookSpecificOutput: codexPermissionSpecificOutput{
			HookEventName: codexPermissionRequest,
			Decision: codexPermissionDecision{
				Behavior: behavior,
				Message:  message,
			},
		},
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
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

// monitorNotice renders the user-visible text for a verdict monitor mode
// declined to act on. Empty when wouldAction is empty (enforce mode) — the
// common path, where the hook must stay silent.
//
// It names the rule and says the call was allowed anyway, because the whole
// point of monitor mode is deciding what to enforce later: a notice that only
// said "policy matched" would not tell the user what changes if they switch.
// See ADR 0091-monitor-mode-tools.
func monitorNotice(wouldAction, ruleID, reason string) string {
	if wouldAction == "" {
		return ""
	}
	verb := "blocked"
	if wouldAction == "ask" {
		verb = "asked for approval on"
	}
	msg := fmt.Sprintf("agentjail (monitor mode): would have %s this — allowed because enforcement is off", verb)
	if ruleID != "" {
		msg += fmt.Sprintf(" [rule=%s]", ruleID)
	}
	if reason != "" {
		msg += ": " + reason
	}
	return msg + "\nSet `enforcement: enforce` in ~/.agentjail/policy.yaml to act on this. Report so far: agentjail monitor"
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
// an optional user_message (empty omits the field). user_message, not
// agent_message: the fail-open notice is for the human, and an allowed call
// gives the agent nothing to act on.
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
// returns a canonical daemon request plus the source event needed to render
// Cursor's event-specific response schema.
// Returns an error when the input cannot be parsed.
func parseCursorInput(stdinBytes []byte) (daemonRequest, cursorHookEvent, error) {
	// First detect the event name.
	var generic cursorGenericInput
	if err := json.Unmarshal(stdinBytes, &generic); err != nil {
		return daemonRequest{}, "", fmt.Errorf("parse hook_event_name: %w", err)
	}

	var req daemonRequest

	switch generic.HookEventName {
	case cursorBeforeShellExecution:
		var inp cursorShellInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, "", fmt.Errorf("parse beforeShellExecution: %w", err)
		}
		cwd := inp.CWD
		if cwd == "" {
			cwd = cursorWorkspaceCWD("", inp.WorkspaceRoots)
		}
		req = daemonRequest{
			ID:        "cursor-shell",
			HookEvent: canonicalPreToolUse,
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": inp.Command},
			CWD:       cwd,
		}

	case cursorBeforeReadFile:
		var inp cursorReadFileInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, "", fmt.Errorf("parse beforeReadFile: %w", err)
		}
		req = daemonRequest{
			ID:        "cursor-readfile",
			HookEvent: canonicalPreToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{"file_path": inp.FilePath},
			CWD:       cursorWorkspaceCWD(inp.FilePath, inp.WorkspaceRoots),
		}

	case cursorBeforeMCPExecution:
		var inp cursorMCPInput
		if err := json.Unmarshal(stdinBytes, &inp); err != nil {
			return daemonRequest{}, "", fmt.Errorf("parse beforeMCPExecution: %w", err)
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
			HookEvent: canonicalPreToolUse,
			ToolName:  cursorMCPToolName(inp),
			ToolInput: toolInput,
			CWD:       cursorWorkspaceCWD("", inp.WorkspaceRoots),
		}

	default:
		return daemonRequest{}, "", fmt.Errorf("unknown cursor hook_event_name: %q", generic.HookEventName)
	}

	return req, generic.HookEventName, nil
}

func cursorWorkspaceCWD(filePath string, roots []string) string {
	if len(roots) == 0 {
		return ""
	}
	if filePath == "" {
		return roots[0]
	}

	best := ""
	for _, root := range roots {
		rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(filePath))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if len(root) > len(best) {
			best = root
		}
	}
	return best
}

func cursorMCPToolName(inp cursorMCPInput) string {
	toolName := strings.TrimSpace(inp.ToolName)
	if strings.HasPrefix(toolName, "mcp__") {
		return toolName
	}
	if server, tool, ok := strings.Cut(toolName, "/"); ok {
		return "mcp__" + cursorMCPComponent(server) + "__" + cursorMCPComponent(tool)
	}

	server := cursorSimpleMCPServer(inp.Command)
	if server == "" && inp.URL != "" {
		if parsed, err := url.Parse(inp.URL); err == nil {
			server = parsed.Hostname()
		}
	}
	if server == "" {
		server = "unknown"
	}
	return "mcp__" + cursorMCPComponent(server) + "__" + cursorMCPComponent(toolName)
}

func cursorSimpleMCPServer(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	for _, r := range command {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return ""
	}
	return command
}

func cursorMCPComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return strings.ReplaceAll(value, "__", "_")
}

// dialDaemon connects to the daemon socket with a 30 ms timeout.
func dialDaemon(sockPath string) (net.Conn, error) {
	return net.DialTimeout("unix", sockPath, 30*time.Millisecond)
}

const (
	defaultRoundTripDeadline       = 45 * time.Millisecond
	codexApprovalRoundTripDeadline = 250 * time.Millisecond
)

func roundTripDeadline(req daemonRequest) time.Duration {
	if req.Agent == "codex" {
		for _, capability := range req.Capabilities {
			if capability == wire.CapabilityCodexApprovalBridgeV1 || capability == wire.CapabilityCodexShellApprovalV1 {
				return codexApprovalRoundTripDeadline
			}
		}
	}
	return defaultRoundTripDeadline
}

// sendAndReceive sends req to conn and reads the daemon response.
func sendAndReceive(conn net.Conn, req daemonRequest) (daemonResponse, error) {
	// Cold approval evaluation includes policy plus process attestation.
	// Keep its availability ceiling distinct from the latency target. See ADR 0118-codex-approval-broker.
	if err := conn.SetDeadline(time.Now().Add(roundTripDeadline(req))); err != nil {
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
	if agent == "codex" &&
		(input.HookEventName == codexSessionStart || input.HookEventName == codexStop) {
		writeCodexLifecycleAttestation()
		return
	}

	// These outcome events are non-blocking: the tool already ran, so the hook
	// reports the observation and always exits 0. Claude separates success
	// (PostToolUse) from failure (PostToolUseFailure); Codex reports both
	// through PostToolUse. See ADR 0112-final-action-outcome.
	if input.HookEventName == "PostToolUse" ||
		(agent == "claude" && input.HookEventName == claudePostToolUseFailure) {
		handlePostToolUse(agent, input)
		return
	}
	if agent == "codex" && input.HookEventName == codexPermissionRequest {
		runCodexPermissionRequest(input)
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
		ID:             "hook-" + input.SessionID + "-" + input.ToolName,
		HookEvent:      input.HookEventName,
		ToolName:       input.ToolName,
		ToolInput:      input.ToolInput,
		SessionID:      input.SessionID,
		TurnID:         input.TurnID,
		CWD:            input.CWD,
		Agent:          agent,
		AgentPID:       findAgentPID(),
		PermissionMode: input.PermissionMode,
		// ADR 0112: correlation id PostToolUse will report the outcome under.
		ToolUseID:    correlationID(input.ToolUseID, input.SessionID, input.ToolName, input.ToolInput),
		Capabilities: codexApprovalCapabilities(),
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
	if agent == "codex" && resp.CodexApprovalBridge && resp.PolicyAction == "ask" {
		operation := codexApprovalOperation(resp)
		if resp.ApprovalChallenge != "" && resp.ApprovalDisplay != "" &&
			writeCodexApprovalRewrite(operation, approvalexec.ChallengeID(resp.ApprovalChallenge), resp.ApprovalDisplay) {
			return
		}
		resp.EffectiveAction = "deny"
		resp.TranslationReason = "Codex approval broker response was incomplete or invalid; fail closed"
	}
	if agent == "codex" && resp.DeferToNativePermission {
		return
	}

	// 6. Translate daemon action to Claude Code exit/output convention.
	switch renderedAction(resp, agent, input.HookEventName) {
	case "deny":
		if agent == "codex" && (resp.PolicyAction == "ask" || resp.Action == "ask") {
			fmt.Fprintf(os.Stderr, "agentjail: ask requires human review but Codex PreToolUse cannot initiate an approval request; denied by policy (rule=%s): %s\n", resp.RuleID, resp.Reason)
			os.Exit(2)
		}
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
			fmt.Fprintf(os.Stderr, "agentjail: ask requires human review but Codex PreToolUse cannot initiate an approval request; denied by policy (rule=%s): %s\n", resp.RuleID, resp.Reason)
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
		// Monitor mode: the daemon downgraded a real verdict. Say so, or the run
		// is indistinguishable from a clean one. Must ride systemMessage --
		// Claude Code discards hook stderr on exit 0 (ADR 0073).
		if notice := monitorNotice(resp.WouldAction, resp.RuleID, resp.Reason); notice != "" {
			if agent == "codex" {
				writeCodexSystemMessage(notice)
				os.Exit(0)
			}
			writeAllowWithSystemMessage(resp.Reason, notice)
			os.Exit(0)
		}
		if agent == "codex" {
			os.Exit(0)
		}
		writeAllow(resp.Reason)
		os.Exit(0)
	}
}

// runCodexPermissionRequest applies the canonical policy to an approval Codex
// has already decided to request. A policy ask declines to decide so Codex
// retains its native approval UI. A managed broker request records prompt
// observation; redemption still requires fresh process ancestry.
// See ADR 0118-codex-approval-broker.
func runCodexPermissionRequest(input hookInput) {
	sockPath := resolveSocketPath()
	conn, err := dialDaemon(sockPath)
	if err != nil {
		failOpenCodexPermissionRequest("dial-daemon", fmt.Sprintf("dial %s: %v", sockPath, err))
		return
	}
	defer conn.Close()

	// PermissionRequest has the same canonical tool payload as PreToolUse, but
	// needs its own rendering capability: policy ask defers to Codex's native
	// approval UI instead of becoming the pre-tool fail-closed denial.
	req := daemonRequest{
		ID:             "hook-" + input.SessionID + "-" + input.ToolName,
		HookEvent:      codexPermissionRequest,
		ToolName:       input.ToolName,
		ToolInput:      input.ToolInput,
		SessionID:      input.SessionID,
		TurnID:         input.TurnID,
		CWD:            input.CWD,
		Agent:          "codex",
		AgentPID:       findAgentPID(),
		PermissionMode: input.PermissionMode,
		Capabilities:   codexApprovalCapabilities(),
	}

	evalStart := time.Now()
	resp, err := sendAndReceive(conn, req)
	evalMs := time.Since(evalStart).Milliseconds()
	if err != nil {
		category := "read-response"
		if isWriteErr(err) {
			category = "dial-daemon"
		}
		failOpenCodexPermissionRequest(category, err.Error())
		return
	}

	printPolicyEval(os.Getenv("NO_COLOR") != "", input.ToolName, resp.Action, resp.RuleID, resp.Reason, evalMs)
	switch resp.Action {
	case "deny":
		writeCodexPermissionDecision("deny", fmt.Sprintf("Blocked by AgentJail policy (rule=%s): %s", resp.RuleID, resp.Reason))
	case "allow":
		writeCodexPermissionDecision("allow", "")
	case "ask":
		// No stdout is Codex's documented "decline to decide" result. The
		// daemon persists the canonical ask; Codex owns the ensuing human UI.
		return
	default:
		// The daemon protocol is expected to return only allow|ask|deny. An
		// unknown value must not approve a pending native request.
		writeCodexPermissionDecision("deny", "Blocked by AgentJail: unrecognized policy decision.")
	}
}

// failOpenCodexPermissionRequest preserves AgentJail's hook fail-open
// availability posture without manufacturing an approval. PermissionRequest
// is already on Codex's native approval path, so an empty decision lets its
// existing prompt continue and a system message makes degradation visible.
func failOpenCodexPermissionRequest(category, detail string) {
	failOpenMarker("codex", category)
	fb, _ := loadHookFallback()
	printFailOpenBanner(fb.Level)
	fmt.Fprintf(os.Stderr, "agentjail-hook: detail: %s\n", detail)
	writeCodexSystemMessage(failOpenSystemMessage(fb.Level))
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
	req, cursorEvent, err := parseCursorInput(stdinBytes)
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
	switch renderedAction(resp, "cursor", string(cursorEvent)) {
	case "deny":
		writeCursorDeny(resp.Reason)

	case "ask":
		if cursorEvent == cursorBeforeReadFile {
			writeCursorDeny(resp.Reason)
		} else {
			writeCursorAsk(resp.Reason)
		}

	default:
		// "allow" or unknown → allow.
		// One-time ssh-agent remediation advisory (non-blocking, stderr
		// only, allow-path only - never on deny/ask).
		maybeEmitSSHAgentWarning(req.ToolName, req.ToolInput)
		// Monitor mode: surface the verdict the daemon declined to act on
		// (ADR 0091-monitor-mode-tools).
		if notice := monitorNotice(resp.WouldAction, resp.RuleID, resp.Reason); notice != "" {
			writeCursorAllowWithMessage(notice)
			break
		}
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
