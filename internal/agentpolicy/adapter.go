// Package agentpolicy translates canonical policy verdicts into each agent's
// hook protocol without changing the policy engine's source-of-truth verdict.
package agentpolicy

import (
	"strings"

	"github.com/LuD1161/agentjail/internal/wire"
)

// Action is a policy or hook-response action.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAsk   Action = "ask"
	ActionDeny  Action = "deny"
)

// Request is the boundary input for an agent-specific response translation.
// PolicyAction is immutable: it is the canonical verdict returned by policy.
// EnforcedAction includes a daemon-level enforcement-mode downgrade, when one
// applies, before an agent protocol has rendered the response.
type Request struct {
	Agent          string
	HookEvent      string
	ToolName       string
	RuleID         string
	PermissionMode string
	PolicyAction   Action
	EnforcedAction Action
	Capabilities   []string
}

// Translation records how an agent protocol renders a canonical policy
// decision. It deliberately keeps PolicyAction separate from EffectiveAction.
type Translation struct {
	PolicyAction            Action
	EffectiveAction         Action
	Adapter                 string
	TranslationReason       string
	DeferToNativePermission bool
	CodexApprovalBridge     bool
}

// Adapter is the consumer-owned seam for an agent hook protocol.
type Adapter interface {
	ID() string
	Translate(Request) Translation
}

// Normalize finds the agent adapter and translates a policy result. Unknown
// agents retain the daemon-enforced action rather than guessing a protocol.
func Normalize(req Request) Translation {
	adapter := adapterFor(req.Agent)
	return adapter.Translate(req)
}

func adapterFor(agent string) Adapter {
	switch strings.ToLower(agent) {
	case "claude", "claude-code":
		return claudeAdapter{}
	case "codex":
		return codexAdapter{}
	case "cursor":
		return cursorAdapter{}
	default:
		return genericAdapter{}
	}
}

func base(req Request, adapter string) Translation {
	effective := req.EnforcedAction
	if effective == "" {
		effective = req.PolicyAction
	}
	translation := Translation{
		PolicyAction:    req.PolicyAction,
		EffectiveAction: effective,
		Adapter:         adapter,
	}
	if effective != req.PolicyAction {
		translation.TranslationReason = "daemon enforcement mode rendered the canonical policy verdict as " + string(effective)
	}
	return translation
}

type genericAdapter struct{}

func (genericAdapter) ID() string { return "generic" }
func (a genericAdapter) Translate(req Request) Translation {
	return base(req, a.ID())
}

type claudeAdapter struct{}

func (claudeAdapter) ID() string { return "claude" }
func (a claudeAdapter) Translate(req Request) Translation {
	return base(req, a.ID())
}

type codexAdapter struct{}

func (codexAdapter) ID() string { return "codex" }
func (a codexAdapter) Translate(req Request) Translation {
	translation := base(req, a.ID())
	if strings.EqualFold(req.HookEvent, "PreToolUse") && translation.EffectiveAction == ActionAsk {
		if req.ToolName == "Bash" && supportsCodexShellApproval(req) {
			translation.CodexApprovalBridge = true
			translation.TranslationReason = "Codex ask routed through one-use native approval broker"
			return translation
		}
		translation.EffectiveAction = ActionDeny
		translation.TranslationReason = "Codex PreToolUse cannot initiate an interactive approval; fail closed"
	}
	return translation
}

func supportsCodexShellApproval(req Request) bool {
	legacy := false
	for _, capability := range req.Capabilities {
		switch capability {
		case wire.CapabilityCodexShellApprovalV1:
			return true
		case wire.CapabilityCodexApprovalBridgeV1:
			legacy = true
		}
	}
	return legacy && legacyCodexGitApprovalRule(req.RuleID)
}

func legacyCodexGitApprovalRule(ruleID string) bool {
	switch ruleID {
	case "command_policy/confirm-git-push", "command_policy/confirm-git-push-force":
		return true
	default:
		return false
	}
}

type cursorAdapter struct{}

func (cursorAdapter) ID() string { return "cursor" }
func (a cursorAdapter) Translate(req Request) Translation {
	translation := base(req, a.ID())
	if strings.EqualFold(req.HookEvent, "beforeReadFile") && translation.EffectiveAction == ActionAsk {
		translation.EffectiveAction = ActionDeny
		translation.TranslationReason = "Cursor beforeReadFile supports allow or deny only; fail closed"
	}
	return translation
}
