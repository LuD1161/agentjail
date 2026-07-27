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

// sandboxDenialSignature reports whether s carries the OS sandbox's denial
// tell. Callers must first establish that the tool failed; output text alone
// is not evidence of enforcement. See ADR 0112-final-action-outcome.
func sandboxDenialSignature(s string) (matched bool, excerpt string) {
	lower := strings.ToLower(s)
	idx := -1
	switch {
	case strings.Contains(lower, "operation not permitted"):
		idx = strings.Index(lower, "operation not permitted")
	case strings.Contains(lower, "eperm"):
		idx = strings.Index(lower, "eperm")
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

// codexToolResponse is the structured subset that can prove a Codex tool
// failed. Codex 0.145.0 documents tool_response as tool-specific and emits
// plain output for current Bash implementations, so an unstructured string
// cannot establish failure even if it contains denial words.
type codexToolResponse struct {
	ExitCode     *int                       `json:"exit_code,omitempty"`
	LegacyCode   *int                       `json:"exitCode,omitempty"`
	LegacyStatus *int                       `json:"exit_status,omitempty"`
	Metadata     *codexToolResponseMetadata `json:"metadata,omitempty"`
	Output       string                     `json:"output,omitempty"`
	Stdout       string                     `json:"stdout,omitempty"`
	Stderr       string                     `json:"stderr,omitempty"`
	Error        string                     `json:"error,omitempty"`
}

type codexToolResponseMetadata struct {
	ExitCode *int `json:"exit_code,omitempty"`
}

func (r codexToolResponse) failure() (exitCode int, failed bool) {
	for _, code := range []*int{r.ExitCode, r.LegacyCode, r.LegacyStatus} {
		if code != nil {
			return *code, *code != 0
		}
	}
	if r.Metadata != nil && r.Metadata.ExitCode != nil {
		return *r.Metadata.ExitCode, *r.Metadata.ExitCode != 0
	}
	return 0, false
}

func (r codexToolResponse) denialText() string {
	return strings.Join([]string{r.Output, r.Stdout, r.Stderr, r.Error}, "\n")
}

// classifyOutcome converts agent-specific hook payloads into the canonical
// observation. A sandbox denial requires two independent facts: the tool
// failed and its failure detail carries a sandbox signature.
func classifyOutcome(agent string, input hookInput) wire.Outcome {
	var (
		exitCode int
		failed   bool
		detail   string
	)

	switch agent {
	case "claude":
		if input.HookEventName != claudePostToolUseFailure {
			return wire.Outcome{}
		}
		// Claude Code 2.1.216 emits PostToolUseFailure only for failed tools
		// and carries the failure in the typed top-level error field.
		failed = input.Error != ""
		detail = input.Error
	case "codex":
		if input.HookEventName != "PostToolUse" || len(input.ToolResponse) == 0 {
			return wire.Outcome{}
		}
		var response codexToolResponse
		if err := json.Unmarshal(input.ToolResponse, &response); err != nil {
			// Codex 0.145.0 Bash output is commonly a JSON string. It carries
			// no structured status, so treating its prose as failure evidence
			// would recreate the false-positive bug.
			return wire.Outcome{}
		}
		exitCode, failed = response.failure()
		detail = response.denialText()
	default:
		return wire.Outcome{}
	}

	outcome := wire.Outcome{ExitCode: exitCode}
	if !failed {
		return outcome
	}
	outcome.SandboxDenied, outcome.Detail = sandboxDenialSignature(detail)
	return outcome
}

// handlePostToolUse implements the PostToolUse half of ADR 0112. It never
// blocks — the tool call already ran, so nothing the daemon says here can
// change what happened — every path ends in os.Exit(0), including a
// malformed tool_response or an unreachable daemon.
func handlePostToolUse(agent string, input hookInput) {
	defer os.Exit(0)

	outcome := classifyOutcome(agent, input)

	req := daemonRequest{
		ID:        "hook-" + input.SessionID + "-" + input.ToolName,
		HookEvent: "PostToolUse",
		ToolName:  input.ToolName,
		SessionID: input.SessionID,
		Agent:     agent,
		AgentPID:  findAgentPID(),
		ToolUseID: correlationID(input.ToolUseID, input.SessionID, input.ToolName, input.ToolInput),
		Outcome:   &outcome,
	}

	conn, err := dialDaemon(resolveSocketPath())
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = sendAndReceive(conn, req)
}
