package telemetry

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	p := Paths{Base: t.TempDir()}
	r, err := New(p, func(string) string { return "" }, "0.1.0", "darwin", "arm64", &Client{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestRecorder_FlushSpoolsRollupWhenNoBackend(t *testing.T) {
	r := newTestRecorder(t)
	r.RecordDecision("deny", "command_policy/rm_rf", 2*time.Millisecond)
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// No backend ⇒ events stay in the spool (not lost, not sent).
	evs, _ := r.spool.ReadAll()
	var sawRollup bool
	for _, e := range evs {
		if e.Event == "decision_rollup" {
			sawRollup = true
		}
	}
	if !sawRollup {
		t.Fatalf("expected decision_rollup spooled, got %+v", evs)
	}
	// Counters reset after flush.
	if w := r.stats.Snapshot(); len(w.ActionCounts) != 0 {
		t.Fatalf("stats not reset: %+v", w)
	}
}

func TestRecorder_StartupPromotesOrphanCheckpoint(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	// Simulate a crash: a .partial checkpoint left on disk.
	w := DecisionWindow{ActionCounts: map[string]int{"deny": 5}, RuleCounts: map[string]int{"command_policy/rm_rf": 5}}
	b, _ := json.Marshal(w)
	_ = os.MkdirAll(p.Base, 0o700)
	_ = os.WriteFile(p.Checkpoint(), b, 0o600)

	r, err := New(p, func(string) string { return "" }, "0.1.0", "darwin", "arm64", &Client{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Recovery promotes the orphan into the spool as a decision_rollup.
	evs, _ := r.spool.ReadAll()
	found := false
	for _, e := range evs {
		if e.Event == "decision_rollup" {
			found = true
		}
	}
	if !found {
		t.Fatalf("orphan checkpoint not promoted: %+v", evs)
	}
	// Checkpoint file removed after promotion.
	if _, err := os.Stat(p.Checkpoint()); !os.IsNotExist(err) {
		t.Fatalf("checkpoint not removed")
	}
}

// Rule IDs are recorded verbatim, including custom rules' user-chosen names — a
// deliberate product decision (disclosed in docs/TELEMETRY.md) so we can see what
// custom rules people write.
func TestRecordDecision_RecordsRuleIDVerbatim(t *testing.T) {
	r := newTestRecorder(t)
	r.RecordDecision("deny", "custom/acme-secrets/block", time.Millisecond)
	r.RecordDecision("deny", "command_policy/no-sudo", time.Millisecond)
	w := r.stats.Snapshot()
	if w.RuleCounts["custom/acme-secrets/block"] != 1 {
		t.Fatalf("custom rule id not recorded verbatim: %+v", w.RuleCounts)
	}
	if w.RuleCounts["command_policy/no-sudo"] != 1 {
		t.Fatalf("built-in rule id not recorded: %+v", w.RuleCounts)
	}
}

func TestRecorder_DisabledRecordsNothing(t *testing.T) {
	p := Paths{Base: t.TempDir()}
	r, _ := New(p, func(k string) string {
		if k == EnvVar {
			return "false"
		}
		return ""
	}, "0.1.0", "darwin", "arm64", &Client{})
	if r.Enabled() {
		t.Fatal("should be disabled via env")
	}
	r.RecordDecision("deny", "r", time.Millisecond)
	_ = r.flush(context.Background())
	evs, _ := r.spool.ReadAll()
	if len(evs) != 0 {
		t.Fatalf("disabled recorder wrote %d events", len(evs))
	}
}
