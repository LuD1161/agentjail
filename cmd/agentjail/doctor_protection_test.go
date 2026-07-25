package main

import (
	"strings"
	"testing"
	"time"
)

var protoNow = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

// The exact shape of the incident this check exists to catch: the shield kept
// activating for days while the daemon recorded nothing.
func TestEnforcementGapCatchesTheSilentWindow(t *testing.T) {
	got := enforcementGapCheck(protectionSignals{
		LastShield:   protoNow.Add(-2 * time.Hour),  // shield ran recently
		LastDecision: protoNow.Add(-72 * time.Hour), // nothing recorded for 3 days
	}, protoNow)

	if got.status != "fail" {
		t.Fatalf("status = %q, want fail — a 3-day recording gap must not read as healthy\n%s", got.status, got.detail)
	}
	if !strings.Contains(got.detail, "restart") && !strings.Contains(got.detail, "Restart") {
		t.Errorf("detail gives no recovery action: %q", got.detail)
	}
}

// Shield running but no decision EVER is the same failure, harder: no baseline.
func TestEnforcementGapNoDecisionsEver(t *testing.T) {
	got := enforcementGapCheck(protectionSignals{
		LastShield: protoNow.Add(-10 * time.Minute),
	}, protoNow)
	if got.status != "fail" {
		t.Errorf("status = %q, want fail; detail=%q", got.status, got.detail)
	}
}

// A healthy session records decisions alongside shield activity.
func TestEnforcementGapHealthy(t *testing.T) {
	got := enforcementGapCheck(protectionSignals{
		LastShield:   protoNow.Add(-5 * time.Minute),
		LastDecision: protoNow.Add(-4 * time.Minute),
	}, protoNow)
	if got.status != "ok" {
		t.Errorf("status = %q, want ok; detail=%q", got.status, got.detail)
	}
}

// A short shielded session with no tool calls must not cry wolf: the margin
// exists so a brief quiet session is not reported as a protection failure.
func TestEnforcementGapToleratesQuietSession(t *testing.T) {
	got := enforcementGapCheck(protectionSignals{
		LastShield:   protoNow.Add(-10 * time.Minute),
		LastDecision: protoNow.Add(-40 * time.Minute), // 30m lead, under the 1h margin
	}, protoNow)
	if got.status == "fail" {
		t.Errorf("a quiet session must not report failure; detail=%q", got.detail)
	}
}

// An idle machine is not a broken one.
func TestEnforcementGapIdleMachineSkips(t *testing.T) {
	got := enforcementGapCheck(protectionSignals{
		LastShield:   protoNow.Add(-30 * 24 * time.Hour),
		LastDecision: protoNow.Add(-30 * 24 * time.Hour),
	}, protoNow)
	if got.status != "skip" {
		t.Errorf("status = %q, want skip for an idle machine; detail=%q", got.status, got.detail)
	}
}

func TestDaemonDowntimeCheck(t *testing.T) {
	clean := daemonDowntimeCheck(protectionSignals{}, protoNow)
	if clean.status != "ok" {
		t.Errorf("no sentinel should be ok, got %q", clean.status)
	}

	t.Run("unresolved", func(t *testing.T) {
		down := daemonDowntimeCheck(protectionSignals{
			DaemonDownSince: protoNow.Add(-72 * time.Hour),
			LastDecision:    protoNow.Add(-73 * time.Hour),
		}, protoNow)
		if down.status != "warn" {
			t.Errorf("status = %q, want warn", down.status)
		}
		if !strings.Contains(down.detail, "3d") {
			t.Errorf("detail should quantify the outage, got %q", down.detail)
		}
	})

	t.Run("later decision resolves warning", func(t *testing.T) {
		recovered := daemonDowntimeCheck(protectionSignals{
			DaemonDownSince: protoNow.Add(-10 * time.Minute),
			LastDecision:    protoNow.Add(-9 * time.Minute),
		}, protoNow)
		if recovered.status != "ok" {
			t.Errorf("status = %q, want ok; detail=%q", recovered.status, recovered.detail)
		}
		if !strings.Contains(recovered.detail, "resumed") {
			t.Errorf("detail should describe recovery, got %q", recovered.detail)
		}
	})

	t.Run("equal timestamp is not proof of recovery", func(t *testing.T) {
		atFailure := protoNow.Add(-time.Hour)
		got := daemonDowntimeCheck(protectionSignals{
			DaemonDownSince: atFailure,
			LastDecision:    atFailure,
		}, protoNow)
		if got.status != "warn" {
			t.Errorf("status = %q, want warn; detail=%q", got.status, got.detail)
		}
	})
}

func TestDroppedDecisionsCheck(t *testing.T) {
	if got := droppedDecisionsCheck(protectionSignals{}); got.status != "ok" {
		t.Errorf("zero dropped should be ok, got %q", got.status)
	}
	got := droppedDecisionsCheck(protectionSignals{Dropped: 412})
	if got.status != "warn" || !strings.Contains(got.detail, "412") {
		t.Errorf("status=%q detail=%q, want warn naming 412", got.status, got.detail)
	}
}

func TestDroppedCountFromDetail(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{`{"count":"12"}`, 12},
		{`{"count":"0"}`, 0},
		{"", 0},
		{"not json", 0},
		{`{"other":"1"}`, 0},
		{`{"count":"-5"}`, 0},
		{`{"count":"abc"}`, 0},
	}
	for _, c := range cases {
		if got := droppedCountFromDetail(c.in); got != c.want {
			t.Errorf("droppedCountFromDetail(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// A machine with no DB (fresh install) must not panic or fail the section.
func TestReadProtectionSignalsMissingDB(t *testing.T) {
	sig := readProtectionSignals(t.TempDir())
	if !sig.LastDecision.IsZero() || !sig.LastShield.IsZero() {
		t.Errorf("expected zero signals for a missing DB, got %+v", sig)
	}
}
