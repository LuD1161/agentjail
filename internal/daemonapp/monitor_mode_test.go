package daemonapp

import (
	"testing"

	"github.com/LuD1161/agentjail/internal/policyeval"
)

// Guards the monitor-mode downgrade (AGE-242, ADR 0091-monitor-mode-tools):
// the verdict is recorded, nothing is enforced, and Action never claims a block
// that did not happen.

func TestApplyMonitorMode_EnforceModeIsUntouched(t *testing.T) {
	for _, action := range []string{"deny", "ask", "allow"} {
		in := policyeval.Response{Action: action, RuleID: "r", Reason: "because"}
		got := applyMonitorMode(in, false)
		if got != in {
			t.Errorf("applyMonitorMode(%q, monitoring=false) = %+v, want unchanged %+v", action, got, in)
		}
	}
}

func TestApplyMonitorMode_DowngradesAndPreservesVerdict(t *testing.T) {
	for _, action := range []string{"deny", "ask"} {
		t.Run(action, func(t *testing.T) {
			got := applyMonitorMode(policyeval.Response{
				Action: action, RuleID: "file_policy/x", Reason: "nope", Impact: "bad",
			}, true)

			if got.Action != actionAllow {
				t.Errorf("Action = %q, want %q — monitor mode must enforce nothing", got.Action, actionAllow)
			}
			if got.WouldAction != action {
				t.Errorf("WouldAction = %q, want %q — the verdict must survive the downgrade", got.WouldAction, action)
			}
			// The rule that fired is the whole point of the report.
			if got.RuleID != "file_policy/x" || got.Reason != "nope" || got.Impact != "bad" {
				t.Errorf("downgrade dropped verdict context: %+v", got)
			}
		})
	}
}

// An allow is already what monitor mode would produce; it must not be marked as
// a would-have-blocked, or the report counts calls policy was fine with.
func TestApplyMonitorMode_AllowIsNotMarked(t *testing.T) {
	got := applyMonitorMode(policyeval.Response{Action: "allow", RuleID: "r"}, true)
	if got.WouldAction != "" {
		t.Errorf("WouldAction = %q on an allow, want empty", got.WouldAction)
	}
	if got.Action != actionAllow {
		t.Errorf("Action = %q, want allow", got.Action)
	}
}

// An empty action is the shape an eval error leaves behind; it must not be
// rewritten into a confident allow.
func TestApplyMonitorMode_EmptyActionUntouched(t *testing.T) {
	got := applyMonitorMode(policyeval.Response{}, true)
	if got.Action != "" || got.WouldAction != "" {
		t.Errorf("empty response mutated: %+v", got)
	}
}

// setMonitoring is the audit seam; the flag must actually flip so handleConn
// reads the new mode after a reload.
func TestSetMonitoringFlips(t *testing.T) {
	s := &server{} // nil eventStore: setMonitoring must stay nil-safe
	if s.monitoring.Load() {
		t.Fatal("zero-value server must default to enforce")
	}
	s.setMonitoring(true)
	if !s.monitoring.Load() {
		t.Error("setMonitoring(true) did not take effect")
	}
	s.setMonitoring(true) // idempotent, must not panic on the nil store
	s.setMonitoring(false)
	if s.monitoring.Load() {
		t.Error("setMonitoring(false) did not take effect")
	}
}
