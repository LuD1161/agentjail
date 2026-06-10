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

// TestStats_RecordDecisionFull verifies that RecordDecisionFull accumulates
// combined rule×action, tool, and agent counts alongside the base counts.
func TestStats_RecordDecisionFull(t *testing.T) {
	st := NewStats()
	st.RecordDecisionFull("deny", "command_policy/rm_rf", "Bash", "claude-code", 2*time.Millisecond)
	st.RecordDecisionFull("deny", "command_policy/rm_rf", "Bash", "claude-code", 1*time.Millisecond)
	st.RecordDecisionFull("allow", "default", "Read", "codex", time.Millisecond)

	w := st.Snapshot()

	// Base counts still work.
	if w.ActionCounts["deny"] != 2 || w.ActionCounts["allow"] != 1 {
		t.Fatalf("action counts: %+v", w.ActionCounts)
	}
	if w.RuleCounts["command_policy/rm_rf"] != 2 {
		t.Fatalf("rule counts: %+v", w.RuleCounts)
	}

	// Combined rule×action counts.
	if w.RuleActionCounts["deny|command_policy/rm_rf"] != 2 {
		t.Fatalf("rule_action deny|rm_rf=%d, want 2", w.RuleActionCounts["deny|command_policy/rm_rf"])
	}
	if w.RuleActionCounts["allow|default"] != 1 {
		t.Fatalf("rule_action allow|default=%d, want 1", w.RuleActionCounts["allow|default"])
	}

	// Per-tool counts.
	if w.ToolCounts["Bash"] != 2 || w.ToolCounts["Read"] != 1 {
		t.Fatalf("tool counts: %+v", w.ToolCounts)
	}

	// Per-agent counts.
	if w.AgentCounts["claude-code"] != 2 || w.AgentCounts["codex"] != 1 {
		t.Fatalf("agent counts: %+v", w.AgentCounts)
	}
}

// TestStats_RecordDecision_EmptyToolAgentOmitted verifies that RecordDecision
// (the old signature) does not create empty-key entries in tool/agent maps.
func TestStats_RecordDecision_EmptyToolAgentOmitted(t *testing.T) {
	st := NewStats()
	st.RecordDecision("deny", "command_policy/rm_rf", time.Millisecond)
	w := st.Snapshot()
	if len(w.ToolCounts) != 0 {
		t.Fatalf("ToolCounts should be empty when tool not provided: %+v", w.ToolCounts)
	}
	if len(w.AgentCounts) != 0 {
		t.Fatalf("AgentCounts should be empty when agent not provided: %+v", w.AgentCounts)
	}
}
