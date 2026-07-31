package agentpolicy

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/wire"
)

func TestCrossAgentConformancePreservesCanonicalPolicyAction(t *testing.T) {
	tests := []struct {
		name        string
		req         Request
		effective   Action
		reason      bool
		deferNative bool
	}{
		{"claude ask", Request{Agent: "claude", HookEvent: "PreToolUse", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionAsk, false, false},
		{"codex ask", Request{Agent: "codex", HookEvent: "PreToolUse", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionDeny, true, false},
		{"codex default git push", Request{Agent: "codex", HookEvent: "PreToolUse", RuleID: "command_policy/confirm-git-push", PermissionMode: "default", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionDeny, true, false},
		{"codex bypass git push", Request{Agent: "codex", HookEvent: "PreToolUse", RuleID: "command_policy/confirm-git-push", PermissionMode: "bypassPermissions", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionDeny, true, false},
		{"codex permission request ask", Request{Agent: "codex", HookEvent: "PermissionRequest", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionAsk, false, false},
		{"cursor shell ask", Request{Agent: "cursor", HookEvent: "beforeShellExecution", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionAsk, false, false},
		{"cursor read ask", Request{Agent: "cursor", HookEvent: "beforeReadFile", PolicyAction: ActionAsk, EnforcedAction: ActionAsk}, ActionDeny, true, false},
		{"monitor downgrade", Request{Agent: "codex", HookEvent: "PreToolUse", PolicyAction: ActionDeny, EnforcedAction: ActionAllow}, ActionAllow, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.req)
			if got.PolicyAction != tt.req.PolicyAction {
				t.Fatalf("policy action = %q, want immutable %q", got.PolicyAction, tt.req.PolicyAction)
			}
			if got.EffectiveAction != tt.effective {
				t.Fatalf("effective action = %q, want %q", got.EffectiveAction, tt.effective)
			}
			if (got.TranslationReason != "") != tt.reason {
				t.Fatalf("translation reason = %q, want present=%v", got.TranslationReason, tt.reason)
			}
			if got.DeferToNativePermission != tt.deferNative {
				t.Fatalf("defer native permission = %v, want %v", got.DeferToNativePermission, tt.deferNative)
			}
		})
	}
}

func TestCodexApprovalBridgeRequiresBashAndCapability(t *testing.T) {
	tests := []struct {
		name   string
		req    Request
		bridge bool
	}{
		{
			name:   "Bash with shell capability bridges every rule namespace",
			req:    Request{Agent: "codex", HookEvent: "PreToolUse", ToolName: "Bash", RuleID: "custom/requires-review", PolicyAction: ActionAsk, EnforcedAction: ActionAsk, Capabilities: []string{wire.CapabilityCodexShellApprovalV1}},
			bridge: true,
		},
		{
			name:   "legacy capability preserves Git bridge",
			req:    Request{Agent: "codex", HookEvent: "PreToolUse", ToolName: "Bash", RuleID: "command_policy/confirm-git-push", PolicyAction: ActionAsk, EnforcedAction: ActionAsk, Capabilities: []string{wire.CapabilityCodexApprovalBridgeV1}},
			bridge: true,
		},
		{
			name: "legacy capability rejects non Git ask",
			req:  Request{Agent: "codex", HookEvent: "PreToolUse", ToolName: "Bash", RuleID: "command_policy/confirm-publish", PolicyAction: ActionAsk, EnforcedAction: ActionAsk, Capabilities: []string{wire.CapabilityCodexApprovalBridgeV1}},
		},
		{
			name: "Bash without capability",
			req:  Request{Agent: "codex", HookEvent: "PreToolUse", ToolName: "Bash", PolicyAction: ActionAsk, EnforcedAction: ActionAsk},
		},
		{
			name: "non-Bash with shell capability",
			req:  Request{Agent: "codex", HookEvent: "PreToolUse", ToolName: "Write", PolicyAction: ActionAsk, EnforcedAction: ActionAsk, Capabilities: []string{wire.CapabilityCodexShellApprovalV1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.req)
			if got.CodexApprovalBridge != tt.bridge {
				t.Fatalf("bridge = %v, want %v", got.CodexApprovalBridge, tt.bridge)
			}
			if tt.bridge && got.EffectiveAction != ActionAsk {
				t.Fatalf("effective action = %q, want ask", got.EffectiveAction)
			}
			if !tt.bridge && got.EffectiveAction != ActionDeny {
				t.Fatalf("effective action = %q, want deny", got.EffectiveAction)
			}
		})
	}
}

func TestCodexShellApprovalDoesNotEnumerateRuleNamespaces(t *testing.T) {
	ruleIDs := []string{
		"command_policy/confirm-publish",
		"command_policy/confirm-curl-download",
		"aws_policy/posture",
		"resolver/default",
		"project/team/review-deploy",
		"custom/operator/confirm-deploy",
	}
	for _, ruleID := range ruleIDs {
		t.Run(ruleID, func(t *testing.T) {
			got := Normalize(Request{
				Agent:          "codex",
				HookEvent:      "PreToolUse",
				ToolName:       "Bash",
				RuleID:         ruleID,
				PolicyAction:   ActionAsk,
				EnforcedAction: ActionAsk,
				Capabilities:   []string{wire.CapabilityCodexShellApprovalV1},
			})
			if !got.CodexApprovalBridge || got.EffectiveAction != ActionAsk {
				t.Fatalf("Normalize(%q) = %#v, want native approval bridge", ruleID, got)
			}
		})
	}
}
