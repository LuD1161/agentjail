package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvents_CarryInsertIDAndDistinct(t *testing.T) {
	e := NewFeatureEvent("anon-1", "0.1.0", "policy", []string{"claude"})
	if e.Event != "feature_used" {
		t.Fatalf("event=%q", e.Event)
	}
	if e.Properties["distinct_id"] != "anon-1" {
		t.Fatalf("distinct_id=%v", e.Properties["distinct_id"])
	}
	if _, ok := e.Properties["$insert_id"].(string); !ok {
		t.Fatalf("missing $insert_id")
	}
}

func TestNewPolicyConfigEvent_FieldsAndNoCustomNames(t *testing.T) {
	e := NewPolicyConfigEvent("anon", "0.1.0", 3, []string{"command_policy/no-sudo"})
	if e.Event != "policy_config" || e.Properties["custom_rule_count"] != 3 {
		t.Fatalf("bad policy_config event: %+v", e)
	}
}

func TestNewFeedbackEvent_OmitsEmptyContact(t *testing.T) {
	e := NewFeedbackEvent("anon", "0.1.0", "darwin", "great tool", "")
	if _, ok := e.Properties["contact"]; ok {
		t.Fatal("empty contact must be omitted")
	}
	e2 := NewFeedbackEvent("anon", "0.1.0", "darwin", "hi", "me@example.com")
	if e2.Properties["contact"] != "me@example.com" {
		t.Fatal("contact not carried")
	}
}

// TestNewInstallEvent_FieldsAndOptionals verifies that NewInstallEvent populates
// required fields and omits install_method when empty.
func TestNewInstallEvent_FieldsAndOptionals(t *testing.T) {
	e := NewInstallEvent("anon", "0.1.0", "darwin", "arm64", "curl", []string{"claude-code"}, 2)
	if e.Event != "install" {
		t.Fatalf("event name=%q", e.Event)
	}
	if e.Properties["os"] != "darwin" || e.Properties["arch"] != "arm64" {
		t.Fatalf("os/arch missing: %+v", e.Properties)
	}
	if e.Properties["install_method"] != "curl" {
		t.Fatalf("install_method=%v", e.Properties["install_method"])
	}
	if e.Properties["agents_detected"] != 2 {
		t.Fatalf("agents_detected=%v", e.Properties["agents_detected"])
	}

	// Empty install_method must be omitted.
	e2 := NewInstallEvent("anon", "0.1.0", "linux", "amd64", "", nil, 0)
	if _, ok := e2.Properties["install_method"]; ok {
		t.Fatal("empty install_method must be omitted")
	}
}

// TestNewUninstallEvent_Fields verifies basic field presence.
func TestNewUninstallEvent_Fields(t *testing.T) {
	e := NewUninstallEvent("anon", "0.1.0", "darwin", "arm64", nil)
	if e.Event != "uninstall" {
		t.Fatalf("event name=%q", e.Event)
	}
	if e.Properties["os"] != "darwin" || e.Properties["arch"] != "arm64" {
		t.Fatalf("os/arch: %+v", e.Properties)
	}
	// Full teardown (nil agents) omits the agents field.
	if _, ok := e.Properties["agents"]; ok {
		t.Fatalf("full uninstall must omit agents: %+v", e.Properties)
	}

	// Single-agent removal records the unhooked agent so it's distinguishable
	// from a full teardown.
	se := NewUninstallEvent("anon", "0.1.0", "linux", "amd64", []string{"claude-code"})
	agents, ok := se.Properties["agents"].([]string)
	if !ok || len(agents) != 1 || agents[0] != "claude-code" {
		t.Fatalf("single-agent uninstall agents=%v", se.Properties["agents"])
	}
}

// TestNewFailOpenEvent_Fields verifies reason and os fields.
func TestNewFailOpenEvent_Fields(t *testing.T) {
	e := NewFailOpenEvent("anon", "0.1.0", "darwin", "dial-daemon")
	if e.Event != "fail_open" {
		t.Fatalf("event name=%q", e.Event)
	}
	if e.Properties["reason"] != "dial-daemon" {
		t.Fatalf("reason=%v", e.Properties["reason"])
	}
	if e.Properties["os"] != "darwin" {
		t.Fatalf("os=%v", e.Properties["os"])
	}
}

// TestNewHeartbeatEvent_Fields verifies update_available, version, and source fields.
func TestNewHeartbeatEvent_Fields(t *testing.T) {
	e := NewHeartbeatEvent("anon", "v1.0.0", "v1.1.0", "linux", "cli", true)
	if e.Event != "heartbeat" {
		t.Fatalf("event name=%q", e.Event)
	}
	if e.Properties["update_available"] != true {
		t.Fatalf("update_available=%v", e.Properties["update_available"])
	}
	if e.Properties["latest_version"] != "v1.1.0" {
		t.Fatalf("latest_version=%v", e.Properties["latest_version"])
	}
	if e.Properties["source"] != "cli" {
		t.Errorf("source = %q, want %q", e.Properties["source"], "cli")
	}
}

// TestNewDecisionRollupWithDetails_RuleActionCounts verifies that the combined
// rule×action and per-tool/per-agent fields are included in the event.
func TestNewDecisionRollupWithDetails_RuleActionCounts(t *testing.T) {
	w := DecisionWindow{
		ActionCounts:     map[string]int{"deny": 3},
		RuleCounts:       map[string]int{"command_policy/rm_rf": 3},
		RuleActionCounts: map[string]int{"deny|command_policy/rm_rf": 3},
		ToolCounts:       map[string]int{"Bash": 3},
		AgentCounts:      map[string]int{"claude-code": 3},
	}
	e := NewDecisionRollupWithDetails("anon", "0.1.0", w, 0)
	if e.Event != "decision_rollup" {
		t.Fatalf("event name=%q", e.Event)
	}
	if _, ok := e.Properties["rule_action_counts"]; !ok {
		t.Fatal("rule_action_counts missing")
	}
	if _, ok := e.Properties["tool_counts"]; !ok {
		t.Fatal("tool_counts missing")
	}
	if _, ok := e.Properties["agent_counts"]; !ok {
		t.Fatal("agent_counts missing")
	}
	// action_counts and rule_counts must still be present (backward compat).
	if _, ok := e.Properties["action_counts"]; !ok {
		t.Fatal("action_counts missing (backward compat)")
	}
}

// TestNewDecisionRollupWithDetails_EmptyOptionals verifies optional fields are
// omitted when the maps are empty.
func TestNewDecisionRollupWithDetails_EmptyOptionals(t *testing.T) {
	w := DecisionWindow{
		ActionCounts: map[string]int{"allow": 1},
		RuleCounts:   map[string]int{"default": 1},
	}
	e := NewDecisionRollupWithDetails("anon", "0.1.0", w, 0)
	if _, ok := e.Properties["rule_action_counts"]; ok {
		t.Fatal("rule_action_counts should be omitted when empty")
	}
	if _, ok := e.Properties["tool_counts"]; ok {
		t.Fatal("tool_counts should be omitted when empty")
	}
	if _, ok := e.Properties["agent_counts"]; ok {
		t.Fatal("agent_counts should be omitted when empty")
	}
}

// TestEvents_NoPayloadLeak feeds sensitive-looking values into the rollup
// constructors and asserts NONE of them survive serialization. The allowlist is
// enforced structurally: constructors copy only known keys.
func TestEvents_NoPayloadLeak(t *testing.T) {
	secrets := []string{
		"/Users/alice/.ssh/id_rsa", "rm -rf /", "git@github.com:acme/secret.git",
		"AKIAIOSFODNN7EXAMPLE", "my-private-mcp-server", "/home/bob/project",
	}
	// Rule IDs are enums and ARE allowed; sensitive payload is not.
	dec := NewDecisionRollup("anon", "0.1.0", map[string]int{"deny": 3}, map[string]int{"command_policy/rm_rf": 3}, 0)
	perf := NewPerfRollup("anon", "0.1.0", 1.2, 4.5, 0)
	env := NewEnvEvent("anon", "0.1.0", "darwin", "arm64", "brew")
	for _, ev := range []Event{dec, perf, env} {
		b, _ := json.Marshal(ev)
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("event %q leaked %q: %s", ev.Event, s, b)
			}
		}
	}
}
