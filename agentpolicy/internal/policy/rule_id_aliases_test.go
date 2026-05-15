// rule_id_aliases_test.go — invariant tests for the backward-compat alias map.
package policy

import (
	"strings"
	"testing"
)

// TestRuleIDAliasesExactly16 asserts the map has exactly 16 entries — one per
// rule renamed in ADR 0014 §0a.  Any addition or deletion is a test failure so
// future maintainers notice the boundary.
func TestRuleIDAliasesExactly16(t *testing.T) {
	const wantCount = 16
	if got := len(RuleIDAliases); got != wantCount {
		t.Errorf("RuleIDAliases has %d entries, want exactly %d", got, wantCount)
	}
}

// TestRuleIDAliasesMapping asserts that every old id maps to exactly
// "command_policy/<old>" and that the prefix is "command_policy/".
func TestRuleIDAliasesMapping(t *testing.T) {
	for old, canonical := range RuleIDAliases {
		want := "command_policy/" + old
		if canonical != want {
			t.Errorf("RuleIDAliases[%q] = %q, want %q", old, canonical, want)
		}
		if !strings.HasPrefix(canonical, "command_policy/") {
			t.Errorf("RuleIDAliases[%q] = %q: missing command_policy/ prefix", old, canonical)
		}
	}
}

// TestResolveRuleID_Known verifies that all 16 known old ids are resolved to
// their canonical form.
func TestResolveRuleID_Known(t *testing.T) {
	for old, want := range RuleIDAliases {
		got := ResolveRuleID(old)
		if got != want {
			t.Errorf("ResolveRuleID(%q) = %q, want %q", old, got, want)
		}
	}
}

// TestResolveRuleID_PassThrough verifies that already-namespaced ids and
// unrecognized ids are returned unchanged.
func TestResolveRuleID_PassThrough(t *testing.T) {
	cases := []string{
		"command_policy/no-sudo",
		"command_policy/confirm-git-push",
		"command_policy/default-allow",
		"file_policy/sensitive_credential",
		"mcp_policy/blocked",
		"custom/myrule/deny-x",
		"unknown-rule",
		"",
	}
	for _, id := range cases {
		got := ResolveRuleID(id)
		if got != id {
			t.Errorf("ResolveRuleID(%q) = %q, want pass-through %q", id, got, id)
		}
	}
}
