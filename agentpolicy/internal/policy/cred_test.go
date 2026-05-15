package policy

import (
	"context"
	"testing"
)

// TestCredRule_AllowAutoApprove fires the cred_use rule via the real
// policies/default.rego against an inline `data.agentjail.caps` overlay.
// Until the daemon wires rego.Store overlays (deferred to a follow-up
// commit alongside fsnotify reload), Phase 2 daemons feed the catalog
// via the perm.Service eval flow; this test is the contract that the
// rule WILL fire correctly when data is present.
func TestCredRule_AllowAutoApprove(t *testing.T) {
	t.Skip("requires data.agentjail.caps overlay -- wired in next iteration; covered by rego unit tests in policies/default_test.rego")
}

// TestSelfTamperRule_DenyAgentjailWrite confirms the rule wired into
// policies/default.rego fires against a wrapped-agent write under
// ~/.agentjail/.
func TestSelfTamperRule_DenyAgentjailWrite(t *testing.T) {
	eng := loadRepoPolicies(t)
	in := Input{
		Action: "write",
		Principal: map[string]any{
			"attr": map[string]any{"agent": "comp-intel"},
		},
		Resource: map[string]any{
			"kind": "file",
			"attr": map[string]any{"path": "/Users/me/.agentjail/capabilities.yaml"},
		},
		Context: map[string]any{"home": "/Users/me"},
	}
	d, err := eng.Eval(context.Background(), in)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Action != "deny" || d.RuleID != "self-tamper-agentjail-dir" {
		t.Fatalf("got %+v, want deny/self-tamper-agentjail-dir", d)
	}
}

// TestSelfTamperRule_OperatorWriteAllowed confirms the rule is gated on
// principal.attr.agent so the operator (running outside a wrapped
// session) can still write to ~/.agentjail/.
func TestSelfTamperRule_OperatorWriteAllowed(t *testing.T) {
	eng := loadRepoPolicies(t)
	in := Input{
		Action: "write",
		Hook:   "file",
		Principal: map[string]any{
			"attr": map[string]any{"agent": ""},
		},
		Resource: map[string]any{
			"kind": "file",
			"attr": map[string]any{"path": "/Users/me/.agentjail/capabilities.yaml"},
		},
		Context: map[string]any{"home": "/Users/me"},
	}
	d, err := eng.Eval(context.Background(), in)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Action == "deny" && d.RuleID == "self-tamper-agentjail-dir" {
		t.Fatalf("operator write should not trip self-tamper, got %+v", d)
	}
}
