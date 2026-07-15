package main

import (
	"strings"
	"testing"
)

// TestShieldBadge_Shielded: a shielded session is attested by name.
func TestShieldBadge_Shielded(t *testing.T) {
	t.Setenv("AGENTJAIL_SHIELDED", "1")

	got := shieldBadge()
	if !strings.Contains(got, "secured by") || !strings.Contains(got, "agentjail") {
		t.Errorf("expected a secured badge, got %q", got)
	}
	if strings.Contains(got, "UNSECURED") {
		t.Errorf("shielded session must not render UNSECURED, got %q", got)
	}
}

// TestShieldBadge_Unshielded is the regression this badge exists for: an
// unprotected session used to render nothing, which is indistinguishable from a
// protected one once the stderr warnings scroll away (ADR 0064).
func TestShieldBadge_Unshielded(t *testing.T) {
	t.Setenv("AGENTJAIL_SHIELDED", "")

	got := shieldBadge()
	if got == "" {
		t.Fatal("an unshielded session must never render an empty badge")
	}
	if !strings.Contains(got, "UNSECURED") {
		t.Errorf("expected UNSECURED, got %q", got)
	}
	if strings.Contains(got, "secured by") {
		t.Errorf("unshielded session must not claim to be secured, got %q", got)
	}
}

// TestShieldBadge_OnlyExactValueCounts: AGENTJAIL_SHIELDED is set to exactly
// "1" by the shield. Any other value is not an activation record and must not
// be read as one.
func TestShieldBadge_OnlyExactValueCounts(t *testing.T) {
	for _, v := range []string{"0", "true", "yes", "2"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("AGENTJAIL_SHIELDED", v)
			if got := shieldBadge(); !strings.Contains(got, "UNSECURED") {
				t.Errorf("AGENTJAIL_SHIELDED=%q must not read as shielded, got %q", v, got)
			}
		})
	}
}
