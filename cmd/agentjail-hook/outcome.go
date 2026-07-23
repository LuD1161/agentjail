// ADR 0112: final per-action outcome with the responsible enforcer.
//
// PreToolUse sees only the policy verdict; the OS sandbox (seatbelt/Landlock)
// can still deny a call the daemon allowed. This file implements the
// PostToolUse half: correlate the call to its PreToolUse decision via a
// stable ToolUseID, detect the sandbox's own denial signature in the tool
// result, and report that observed outcome to the daemon — the daemon (never
// the hook) is the single writer of the final verdict.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/LuD1161/agentjail/internal/wire"
)

// correlationID computes the stable per-tool-call id ADR 0112 correlates a
// PreToolUse decision with its PostToolUse outcome on. Claude Code's
// tool_use_id is used when present; otherwise a hash of
// session+tool+input stands in (Codex/Cursor, or any Claude Code version
// that omits tool_use_id) so both hook phases still key on the same value
// for the same call. encoding/json sorts map keys, so the input hash is
// stable across separate marshal calls for the same map.
func correlationID(toolUseID, sessionID, toolName string, toolInput map[string]interface{}) string {
	if toolUseID != "" {
		return toolUseID
	}
	b, _ := json.Marshal(toolInput)
	sum := sha256.Sum256([]byte(sessionID + "|" + toolName + "|" + string(b)))
	return "h-" + hex.EncodeToString(sum[:])[:16]
}

// sandboxDenialSignature reports whether s (the stringified tool_response)
// carries the OS sandbox's denial tell. EPERM / "Operation not permitted" is
// the same signature on macOS seatbelt and Linux Landlock (ADR 0112), so this
// check is cross-platform with no kernel-log tailing. excerpt is a short,
// human-readable window around the match for Outcome.Detail.
func sandboxDenialSignature(s string) (matched bool, excerpt string) {
	lower := strings.ToLower(s)
	idx := -1
	switch {
	case strings.Contains(lower, "operation not permitted"):
		idx = strings.Index(lower, "operation not permitted")
	case strings.Contains(lower, "eperm"):
		idx = strings.Index(lower, "eperm")
	case strings.Contains(lower, "sandbox") && strings.Contains(lower, "deny"):
		idx = strings.Index(lower, "sandbox")
	default:
		return false, ""
	}

	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + 80
	if end > len(s) {
		end = len(s)
	}
	excerpt = strings.TrimSpace(s[start:end])
	if len(excerpt) > 120 {
		excerpt = excerpt[:120]
	}
	return true, excerpt
}

// extractExitCode best-effort pulls an integer exit/status code out of a
// parsed tool_response. The shape varies by tool (ADR 0112: "shape varies, so
// parse it as a map"), so this only checks the handful of common key names
// used across Claude Code's built-in tools; ok is false when none are found,
// in which case the caller reports ExitCode 0.
func extractExitCode(resp map[string]interface{}) (code int, ok bool) {
	for _, key := range []string{"exit_code", "exitCode", "exit_status", "code", "status"} {
		v, present := resp[key]
		if !present {
			continue
		}
		if f, isNum := v.(float64); isNum {
			return int(f), true
		}
	}
	return 0, false
}

// handlePostToolUse implements the PostToolUse half of ADR 0112. It never
// blocks — the tool call already ran, so nothing the daemon says here can
// change what happened — every path ends in os.Exit(0), including a
// malformed tool_response or an unreachable daemon.
func handlePostToolUse(agent string, input hookInput) {
	defer os.Exit(0)

	var respMap map[string]interface{}
	stringified := string(input.ToolResponse)
	if len(input.ToolResponse) > 0 {
		if err := json.Unmarshal(input.ToolResponse, &respMap); err == nil {
			if b, err := json.Marshal(respMap); err == nil {
				stringified = string(b)
			}
		}
	}

	denied, excerpt := sandboxDenialSignature(stringified)
	exitCode, _ := extractExitCode(respMap)

	req := daemonRequest{
		ID:        "hook-" + input.SessionID + "-" + input.ToolName,
		HookEvent: "PostToolUse",
		ToolName:  input.ToolName,
		SessionID: input.SessionID,
		Agent:     agent,
		AgentPID:  findAgentPID(),
		ToolUseID: correlationID(input.ToolUseID, input.SessionID, input.ToolName, input.ToolInput),
		Outcome: &wire.Outcome{
			SandboxDenied: denied,
			ExitCode:      exitCode,
			Detail:        excerpt,
		},
	}

	conn, err := dialDaemon(resolveSocketPath())
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = sendAndReceive(conn, req)
}
