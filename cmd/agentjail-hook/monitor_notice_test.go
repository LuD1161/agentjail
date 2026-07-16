package main

import (
	"strings"
	"testing"
)

// Guards the monitor-mode notice (AGE-242, ADR 0091-monitor-mode-tools).
// The channel matters as much as the text: Claude Code discards hook stderr on
// exit 0, so a notice that is not on systemMessage is invisible (ADR 0073) --
// that is what hid the fail-open banner for three days.

// TestMonitorNoticeSilentInEnforceMode is the important one: every ordinary
// allow goes through this, and a stray notice would fire on every tool call.
func TestMonitorNoticeSilentInEnforceMode(t *testing.T) {
	if got := monitorNotice("", "file_policy/x", "some reason"); got != "" {
		t.Errorf("monitorNotice with empty wouldAction = %q, want empty", got)
	}
}

func TestMonitorNoticeNamesTheRuleAndTheVerdict(t *testing.T) {
	got := monitorNotice("deny", "file_policy/sensitive_path", "reads ~/.ssh/id_rsa")

	for _, want := range []string{
		"monitor mode",
		"would have blocked",
		"file_policy/sensitive_path", // which rule fired — the point of the report
		"reads ~/.ssh/id_rsa",
		"enforcement: enforce", // how to act on it
		"agentjail monitor",    // where to see the rest
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notice missing %q\ngot: %s", want, got)
		}
	}
}

// An ask reads differently from a block; saying "would have blocked" for an ask
// would overstate what enforcing actually changes.
func TestMonitorNoticeDistinguishesAskFromDeny(t *testing.T) {
	ask := monitorNotice("ask", "r", "")
	if !strings.Contains(ask, "asked for approval") {
		t.Errorf("ask notice should not claim a block, got: %s", ask)
	}
	if strings.Contains(ask, "would have blocked") {
		t.Errorf("ask notice claims a block: %s", ask)
	}
	if deny := monitorNotice("deny", "r", ""); !strings.Contains(deny, "would have blocked") {
		t.Errorf("deny notice should say blocked, got: %s", deny)
	}
}

// A verdict with no rule id or reason still has to render — the notice is the
// only signal the user gets that enforcement is off.
func TestMonitorNoticeRendersWithoutRuleOrReason(t *testing.T) {
	got := monitorNotice("deny", "", "")
	if got == "" {
		t.Fatal("notice empty for a bare deny verdict")
	}
	if strings.Contains(got, "[rule=]") || strings.HasSuffix(got, ": ") {
		t.Errorf("notice has empty placeholders: %q", got)
	}
}
