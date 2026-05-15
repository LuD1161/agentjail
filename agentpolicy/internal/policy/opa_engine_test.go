package policy

import (
	"context"
	"testing"
)

// testRegoPolicy is the inline Rego used for all hookOPAEngine tests. It
// demonstrates both the default-allow path and a conditional deny path so
// all three Engine behaviours (allow, deny, unknown-rule → default) can be
// exercised without touching the filesystem.
//
// Pattern: default rule fires when no other rule matches. The deny rule fires
// only when tool_name is "Bash" AND tool_input.command contains "rm -rf".
const testRegoPolicy = `
package agentjail
default decision = {"action": "allow", "reason": "default allow", "rule_id": "default"}
decision = {"action": "deny", "reason": "test deny", "rule_id": "test"} {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf")
}
`

// newTestEngine builds a hookOPAEngine from the inline test policy.
func newTestEngine(t *testing.T) Engine {
	t.Helper()
	eng, err := NewHookOPAEngine(context.Background(), [][2]string{
		{"test_policy.rego", testRegoPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}
	return eng
}

// TestHookOPAEngine_Allow: a Write tool call should not match the deny rule
// and should fall through to the default allow.
func TestHookOPAEngine_Allow(t *testing.T) {
	eng := newTestEngine(t)
	input := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Write",
		ToolInput: map[string]interface{}{
			"path":    "/tmp/safe.txt",
			"content": "hello",
		},
		SessionID: "test-session",
		CWD:       "/tmp",
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("Write tool should allow, got action=%q reason=%q rule_id=%q", d.Action, d.Reason, d.RuleID)
	}
}

// TestHookOPAEngine_Deny: a Bash call with "rm -rf" in the command should
// match the deny rule and return action="deny".
func TestHookOPAEngine_Deny(t *testing.T) {
	eng := newTestEngine(t)
	input := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "rm -rf /foo",
		},
		SessionID: "test-session",
		CWD:       "/home/user",
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("rm -rf Bash call should deny, got action=%q reason=%q rule_id=%q", d.Action, d.Reason, d.RuleID)
	}
	if d.RuleID != "test" {
		t.Errorf("expected rule_id=%q, got %q", "test", d.RuleID)
	}
}

// TestHookOPAEngine_NoRuleFires: an engine with no rules loaded (empty
// module list) should return the default-ask decision and no error.
func TestHookOPAEngine_NoRuleFires(t *testing.T) {
	// Engine with an empty policy — no "decision" rule defined.
	// The package declaration is required for Rego to compile; the rule is absent.
	const emptyPolicy = `package agentjail`
	eng, err := NewHookOPAEngine(context.Background(), [][2]string{
		{"empty.rego", emptyPolicy},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine (empty): %v", err)
	}
	input := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
		SessionID: "s",
		CWD:       "/",
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval (empty engine): %v", err)
	}
	// The default-ask decision must be returned when no rule fires.
	if d.Action != "ask" {
		t.Errorf("empty engine should return ask, got action=%q", d.Action)
	}
}

// TestHookOPAEngine_ImpactExtracted verifies that the engine extracts the
// "impact" field from the Rego decision object and populates Decision.Impact.
// This tests that user-authored policies declare impact
// in Rego; the engine surfaces it without any Go code changes.
func TestHookOPAEngine_ImpactExtracted(t *testing.T) {
	const policyWithImpact = `
package agentjail
import future.keywords.if
default decision = {"action": "allow", "reason": "allow", "rule_id": "default"}
decision = {
    "action":  "deny",
    "reason":  "demo deny",
    "rule_id": "test/impact",
    "impact":  "would do something dangerous",
} if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf")
}
`
	eng, err := NewHookOPAEngine(context.Background(), [][2]string{
		{"impact_test.rego", policyWithImpact},
	})
	if err != nil {
		t.Fatalf("NewHookOPAEngine: %v", err)
	}
	input := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /foo"},
		SessionID: "test-session",
		CWD:       "/home/user",
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected action=deny, got %q", d.Action)
	}
	if d.Impact != "would do something dangerous" {
		t.Errorf("expected Impact=%q, got %q", "would do something dangerous", d.Impact)
	}
}

// TestHookOPAEngine_NoImpactFieldIsEmpty verifies that rules without an impact
// field leave Decision.Impact as the empty string (not an error).
func TestHookOPAEngine_NoImpactFieldIsEmpty(t *testing.T) {
	eng := newTestEngine(t) // uses testRegoPolicy which has no impact field
	input := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /bar"},
	}
	d, err := eng.Eval(context.Background(), input)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Impact != "" {
		t.Errorf("expected empty Impact for rule without impact field, got %q", d.Impact)
	}
}

// ---------------------------------------------------------------------------
// NewHookOPAEngineWithData — data injection tests
// ---------------------------------------------------------------------------

// mcpPolicyRego is an inline copy of the MCP policy for unit tests.
// It reads data.agentjail.config.mcp.allowed / blocked.
const mcpPolicyRego = `
package agentjail

import future.keywords.if
import future.keywords.contains
import future.keywords.in

mcp_server_name := server if {
    parts := split(input.tool_name, "__")
    count(parts) >= 3
    parts[0] == "mcp"
    server := parts[1]
}

is_mcp_call if {
    startswith(input.tool_name, "mcp__")
}

allowed_patterns := data.agentjail.config.mcp.allowed if {
    data.agentjail.config.mcp.allowed
} else := []

blocked_patterns := data.agentjail.config.mcp.blocked if {
    data.agentjail.config.mcp.blocked
} else := ["*stripe*", "*payment*", "*billing*", "*twilio*", "*sendgrid*"]

any_blocked if {
    some pattern in blocked_patterns
    glob.match(pattern, [], mcp_server_name)
}

any_allowed if {
    some pattern in allowed_patterns
    glob.match(pattern, [], mcp_server_name)
}

candidate contains r if {
    is_mcp_call
    any_blocked
    r := {"action": "deny", "rule_id": "mcp_policy/blocked", "reason": "blocked"}
}

candidate contains r if {
    is_mcp_call
    not any_blocked
    any_allowed
    r := {"action": "allow", "rule_id": "mcp_policy/allowed", "reason": "allowed"}
}

candidate contains r if {
    is_mcp_call
    not any_blocked
    not any_allowed
    r := {"action": "deny", "rule_id": "mcp_policy/unknown", "reason": "not in allowlist"}
}

# Resolver: deny > ask > allow.
decision := d if {
    d := candidate[_]
    d.action == "deny"
} else := d if {
    d := candidate[_]
    d.action == "ask"
} else := d if {
    d := candidate[_]
    d.action == "allow"
}

# For non-MCP tool calls, fall through to allow.
default decision = {"action": "allow", "reason": "non-mcp default", "rule_id": "default"}
`

// TestNewHookOPAEngineWithData_MCPAllowed verifies that when data.agentjail.config.mcp.allowed
// contains "filesystem", mcp__filesystem__read_file is allowed; an unlisted
// server is denied (proves data injection works — AC5.1).
//
// Data nesting: agentjailData = {"config": {"mcp": {...}}} so Rego reads
// data.agentjail.config.mcp.allowed.
func TestNewHookOPAEngineWithData_MCPAllowed(t *testing.T) {
	ctx := context.Background()
	// The "config" wrapper is required to match data.agentjail.config.* Rego paths.
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"mcp": map[string]interface{}{
				"allowed": []string{"filesystem"},
				"blocked": []string{"*stripe*", "*payment*"},
				"servers": map[string]interface{}{},
			},
		},
	}

	eng, err := NewHookOPAEngineWithData(ctx, [][2]string{{"mcp.rego", mcpPolicyRego}}, data)
	if err != nil {
		t.Fatalf("NewHookOPAEngineWithData: %v", err)
	}

	// Listed server → allow.
	allowedInput := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "mcp__filesystem__read_file",
		ToolInput: map[string]interface{}{"path": "/tmp/foo"},
		SessionID: "s1",
		CWD:       "/home/user",
	}
	d, err := eng.Eval(ctx, allowedInput)
	if err != nil {
		t.Fatalf("Eval allow: %v", err)
	}
	if d.Action != "allow" {
		t.Errorf("mcp__filesystem__read_file should allow; got action=%q rule_id=%q", d.Action, d.RuleID)
	}

	// Unlisted server → deny.
	deniedInput := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "mcp__github__create_pr",
		ToolInput: map[string]interface{}{},
		SessionID: "s1",
		CWD:       "/home/user",
	}
	d2, err := eng.Eval(ctx, deniedInput)
	if err != nil {
		t.Fatalf("Eval deny: %v", err)
	}
	if d2.Action != "deny" {
		t.Errorf("mcp__github__create_pr should deny (not in allowlist); got action=%q rule_id=%q", d2.Action, d2.RuleID)
	}
}

// TestNewHookOPAEngineWithData_DefaultBlockedPreserved verifies that a partial
// config (only mcp.allowed set) still denies blocked patterns because the Rego
// else clause provides the defaults when config key absent (AC5.6-adjacent).
func TestNewHookOPAEngineWithData_DefaultBlockedPreserved(t *testing.T) {
	ctx := context.Background()
	// Only mcp.allowed provided; mcp.blocked absent → Rego else clause fires default.
	// The "config" wrapper is required to match data.agentjail.config.* Rego paths.
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"mcp": map[string]interface{}{
				"allowed": []string{"foo"},
				// "blocked" intentionally absent — Rego else := ["*stripe*",...]
				"servers": map[string]interface{}{},
			},
		},
	}

	eng, err := NewHookOPAEngineWithData(ctx, [][2]string{{"mcp.rego", mcpPolicyRego}}, data)
	if err != nil {
		t.Fatalf("NewHookOPAEngineWithData: %v", err)
	}

	// stripe-related server should be denied by the else-clause default.
	stripeInput := HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "mcp__my-stripe-bot__charge",
		ToolInput: map[string]interface{}{},
		SessionID: "s1",
		CWD:       "/proj",
	}
	d, err := eng.Eval(ctx, stripeInput)
	if err != nil {
		t.Fatalf("Eval stripe: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("stripe server should deny via default blocked; got action=%q rule_id=%q", d.Action, d.RuleID)
	}
}

// TestNewHookOPAEngineWithData_NilData verifies that nil data is equivalent to
// NewHookOPAEngine (back-compat).
func TestNewHookOPAEngineWithData_NilData(t *testing.T) {
	ctx := context.Background()
	eng, err := NewHookOPAEngineWithData(ctx, [][2]string{
		{"test.rego", testRegoPolicy},
	}, nil)
	if err != nil {
		t.Fatalf("NewHookOPAEngineWithData(nil): %v", err)
	}
	d, err := eng.Eval(ctx, HookInput{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /danger"},
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("expected deny, got %q", d.Action)
	}
}

// TestHookOPAEngine_ConcurrentEval verifies the engine is safe for
// concurrent use (race detector will catch violations).
func TestHookOPAEngine_ConcurrentEval(t *testing.T) {
	eng := newTestEngine(t)
	ctx := context.Background()

	const goroutines = 20
	errc := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			var inp HookInput
			if i%2 == 0 {
				inp = HookInput{
					HookEvent: "PreToolUse",
					ToolName:  "Bash",
					ToolInput: map[string]interface{}{"command": "rm -rf /danger"},
				}
			} else {
				inp = HookInput{
					HookEvent: "PreToolUse",
					ToolName:  "Read",
					ToolInput: map[string]interface{}{"path": "/safe"},
				}
			}
			_, err := eng.Eval(ctx, inp)
			errc <- err
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		if err := <-errc; err != nil {
			t.Errorf("concurrent Eval error: %v", err)
		}
	}
}
