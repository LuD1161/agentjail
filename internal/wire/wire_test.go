package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestHookFallbackPathContainsHome sanity-checks the sidecar path lives
// alongside the daemon socket (same ~/.agentjail state directory).
func TestHookFallbackPathContainsHome(t *testing.T) {
	p := HookFallbackPath()
	if !strings.HasSuffix(p, "/.agentjail/hook-fallback.json") && !strings.HasSuffix(p, "agentjail-hook-fallback.json") {
		t.Errorf("HookFallbackPath() = %q, want a path ending in .agentjail/hook-fallback.json (or the /tmp fallback)", p)
	}
}

// TestHookFallbackJSONRoundTrip verifies the daemon-authored shape survives
// a JSON encode/decode cycle byte-for-byte on the fields that matter, since
// the daemon and hook are compiled from the same struct but must never drift
// on wire shape.
func TestHookFallbackJSONRoundTrip(t *testing.T) {
	in := HookFallback{
		Version: HookFallbackVersion,
		Level:   "degraded",
		OfflineRules: []OfflineRule{
			{
				Kind:         OfflineRuleKindPathPrefixWrite,
				RuleID:       "file_policy/agentjail_self",
				Reason:       "self-protection",
				PathPrefixes: []string{"/home/dev/.agentjail"},
			},
			{
				Kind:         OfflineRuleKindPathRead,
				RuleID:       "file_policy/agentjail_secrets",
				Reason:       "secrets protection",
				PathPrefixes: []string{"/home/dev/.agentjail/secrets.key", "/home/dev/.agentjail/secrets"},
			},
			{
				Kind:     OfflineRuleKindCommandMutation,
				RuleID:   "command_policy/no-policy-mutation",
				Reason:   "no self-mutation",
				Binaries: []string{"agentjail"},
				Patterns: []string{`\bpolicy\s+(disable|enable|add|remove)\b`},
			},
		},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var out HookFallback
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if out.Version != in.Version {
		t.Errorf("Version: got %d, want %d", out.Version, in.Version)
	}
	if out.Level != in.Level {
		t.Errorf("Level: got %q, want %q", out.Level, in.Level)
	}
	if len(out.OfflineRules) != len(in.OfflineRules) {
		t.Fatalf("OfflineRules length: got %d, want %d", len(out.OfflineRules), len(in.OfflineRules))
	}
	for i := range in.OfflineRules {
		wantRule := in.OfflineRules[i]
		gotRule := out.OfflineRules[i]
		if gotRule.Kind != wantRule.Kind || gotRule.RuleID != wantRule.RuleID || gotRule.Reason != wantRule.Reason {
			t.Errorf("rule %d: got %+v, want %+v", i, gotRule, wantRule)
		}
		if len(gotRule.PathPrefixes) != len(wantRule.PathPrefixes) {
			t.Errorf("rule %d PathPrefixes: got %v, want %v", i, gotRule.PathPrefixes, wantRule.PathPrefixes)
		}
		if len(gotRule.Binaries) != len(wantRule.Binaries) {
			t.Errorf("rule %d Binaries: got %v, want %v", i, gotRule.Binaries, wantRule.Binaries)
		}
		if len(gotRule.Patterns) != len(wantRule.Patterns) {
			t.Errorf("rule %d Patterns: got %v, want %v", i, gotRule.Patterns, wantRule.Patterns)
		}
	}
}

// TestHookFallbackEmptyOfflineRulesSerializesAsArray guards against nil
// slices serializing as JSON null, which a naive hook-side decoder could
// mishandle (want [] on the wire for Phase 1's stub sidecar).
func TestHookFallbackEmptyOfflineRulesSerializesAsArray(t *testing.T) {
	in := HookFallback{Version: HookFallbackVersion, Level: "allow", OfflineRules: []OfflineRule{}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"offline_rules":[]`) {
		t.Errorf("expected offline_rules to serialize as [], got: %s", b)
	}
}
