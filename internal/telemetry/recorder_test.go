package telemetry

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestRecorder_InitialFlushHappensEarly verifies that RunWithIntervals fires an
// early flush using the injected initInterval — without waiting for the full 6h
// steady-state period. The test drives the recorder with a 10 ms initial
// interval and a 1h steady interval, confirming that the spool is flushed
// (rolled up) well before the steady-state period would elapse.
func TestRecorder_InitialFlushHappensEarly(t *testing.T) {
	r := newTestRecorder(t)
	r.RecordDecision("deny", "command_policy/rm_rf", 2*time.Millisecond)

	// Before any flush the decision is only in the in-memory stats.
	if w := r.stats.Snapshot(); len(w.ActionCounts) == 0 {
		t.Fatal("expected at least one recorded decision before flush")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		// Use a very short initInterval (10 ms) and a long steady interval (1 h)
		// so only the initial flush fires within the test window.
		r.RunWithIntervals(ctx, 10*time.Millisecond, time.Hour)
		close(done)
	}()

	// Wait for the context to be cancelled (2s timeout is plenty for a 10 ms initTimer).
	<-done

	// After Run exits (ctx cancelled → final graceful flush), the spool must
	// contain at least a decision_rollup from the early flush.
	evs, err := r.spool.ReadAll()
	if err != nil {
		t.Fatalf("spool.ReadAll: %v", err)
	}
	var sawRollup bool
	for _, e := range evs {
		if e.Event == "decision_rollup" {
			sawRollup = true
			break
		}
	}
	if !sawRollup {
		t.Fatalf("expected decision_rollup in spool after early flush; got events: %+v", evs)
	}
}

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
