package telemetry

import (
	"testing"
	"time"
)

func TestStats_RecordAndSnapshot(t *testing.T) {
	st := NewStats()
	st.RecordDecision("deny", "command_policy/rm_rf", 2*time.Millisecond)
	st.RecordDecision("allow", "default", 1*time.Millisecond)
	st.RecordDecision("deny", "command_policy/rm_rf", 3*time.Millisecond)
	w := st.Snapshot()
	if w.ActionCounts["deny"] != 2 || w.ActionCounts["allow"] != 1 {
		t.Fatalf("action counts: %+v", w.ActionCounts)
	}
	if w.RuleCounts["command_policy/rm_rf"] != 2 {
		t.Fatalf("rule counts: %+v", w.RuleCounts)
	}
	p50, p95 := st.LatencyPercentiles()
	if p50 <= 0 || p95 <= 0 {
		t.Fatalf("percentiles p50=%v p95=%v", p50, p95)
	}
}

func TestStats_ResetClears(t *testing.T) {
	st := NewStats()
	st.RecordDecision("deny", "r", time.Millisecond)
	st.Reset()
	w := st.Snapshot()
	if len(w.ActionCounts) != 0 || len(w.RuleCounts) != 0 {
		t.Fatalf("not cleared: %+v", w)
	}
}

func TestStats_CheckpointRoundTrip(t *testing.T) {
	st := NewStats()
	st.RecordDecision("ask", "mcp_policy/block", time.Millisecond)
	b, err := st.MarshalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	w, err := LoadCheckpoint(b)
	if err != nil {
		t.Fatal(err)
	}
	if w.ActionCounts["ask"] != 1 || w.RuleCounts["mcp_policy/block"] != 1 {
		t.Fatalf("checkpoint lost counts: %+v", w)
	}
}
