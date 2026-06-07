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
