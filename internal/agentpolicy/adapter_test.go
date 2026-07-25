package agentpolicy

import "testing"

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
