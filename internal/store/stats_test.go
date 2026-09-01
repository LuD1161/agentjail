package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestPercentiles guards the nearest-rank math over an ASC-sorted slice.
func TestPercentiles(t *testing.T) {
	if got := percentiles(nil); got != (LatencyStats{}) {
		t.Fatalf("empty: want zero LatencyStats, got %+v", got)
	}

	// 1..100 sorted; nearest-rank p50 = value at ceil(.5*100)=50 -> index 49 -> 50.
	vals := make([]sql.NullInt64, 100)
	for i := range vals {
		vals[i] = sql.NullInt64{Int64: int64(i + 1), Valid: true}
	}
	got := percentiles(vals)
	for _, tc := range []struct {
		name string
		got  int64
		want int64
	}{
		{"count", got.Count, 100},
		{"p50", got.P50, 50},
		{"p90", got.P90, 90},
		{"p95", got.P95, 95},
		{"p99", got.P99, 99},
		{"max", got.Max, 100},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// Single element: every percentile is that element.
	one := percentiles([]sql.NullInt64{{Int64: 7, Valid: true}})
	if one.P50 != 7 || one.P99 != 7 || one.Max != 7 || one.Count != 1 {
		t.Errorf("single element: got %+v", one)
	}
}

// TestRecordDecisionNormalizesEmptyAgent guards store-boundary attribution.
// See AGE-213.
func TestRecordDecisionNormalizesEmptyAgent(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "norm.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ts := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	if err := s.RecordDecision(ctx, DecisionRecord{Ts: ts, SessionID: "blank", ToolName: "Bash", Action: "allow"}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	got, err := s.ListDecisions(ctx, Filter{SessionID: "blank"})
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(got) != 1 || got[0].Agent != AgentUnknown {
		t.Fatalf("agent = %q (n=%d), want %q", func() string {
			if len(got) > 0 {
				return got[0].Agent
			}
			return ""
		}(), len(got), AgentUnknown)
	}
}

// TestComputeStats exercises the full aggregate over a real temp DB.
func TestComputeStats(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "stats.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ts := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	recs := []DecisionRecord{
		{Ts: ts, SessionID: "s1", Agent: "claude", ToolName: "Bash", Action: "allow", PolicyAction: "allow", FinalAction: "allowed", ElapsedUs: 1000},
		{Ts: ts, SessionID: "s1", Agent: "claude", ToolName: "Bash", Action: "deny", PolicyAction: "deny", FinalAction: "blocked", RuleID: "command_policy/no-sudo", ElapsedUs: 2000},
		{Ts: ts, SessionID: "s2", Agent: "cursor", ToolName: "Read", Action: "allow", PolicyAction: "allow", FinalAction: "blocked", ElapsedUs: 3000},
		{Ts: ts, SessionID: "s2", Agent: "cursor", ToolName: "Read", Action: "ask", RuleID: "file_policy/sensitive", ElapsedUs: 4000},
	}
	for _, r := range recs {
		if err := s.RecordDecision(ctx, r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}

	// Read read-only (report methods live only on ReadOnlyStore) with the
	// writer still open -- exercises the un-checkpointed-WAL path (AGE-213).
	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer ro.Close()
	defer s.Close()

	rep, err := ro.ComputeStats(ctx, time.Time{})
	if err != nil {
		t.Fatalf("ComputeStats: %v", err)
	}

	if rep.Total != 4 {
		t.Errorf("Total = %d, want 4", rep.Total)
	}
	if rep.Sessions != 2 {
		t.Errorf("Sessions = %d, want 2", rep.Sessions)
	}
	if rep.Allow != 1 || rep.Deny != 2 || rep.Ask != 1 {
		t.Errorf("allow/deny/ask = %d/%d/%d, want 1/2/1", rep.Allow, rep.Deny, rep.Ask)
	}
	if rep.ActiveDays != 1 || rep.FirstDay != "2026-07-20" || rep.LastDay != "2026-07-20" {
		t.Errorf("days = %d %q..%q, want 1 2026-07-20..2026-07-20", rep.ActiveDays, rep.FirstDay, rep.LastDay)
	}
	// Sandbox blocks affect the final totals but are not reported as policy deny rules.
	if len(rep.DenyRules) != 1 || rep.DenyRules[0].Label != "command_policy/no-sudo" || rep.DenyRules[0].Count != 1 {
		t.Errorf("DenyRules = %+v, want [no-sudo=1]", rep.DenyRules)
	}
	if rep.Latency.Count != 4 || rep.Latency.Max != 4000 {
		t.Errorf("Latency = %+v, want count=4 max=4000", rep.Latency)
	}
}

func TestPolicyMatchAggregatesPreserveTotalsAndAttribution(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "policy-matches.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ts := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	for _, record := range []DecisionRecord{
		{Ts: ts, SessionID: "session-a", Agent: "codex", CWD: "/work/alpha", ToolName: "Bash", Action: "deny", RuleID: "command_policy/no-sudo"},
		{Ts: ts, SessionID: "session-a", Agent: "codex", CWD: "/work/alpha", ToolName: "Bash", Action: "deny", RuleID: "command_policy/no-sudo"},
		{Ts: ts, SessionID: "session-b", Agent: "claude", CWD: "/work/beta", ToolName: "Read", Action: "ask", RuleID: "file_policy/default"},
		{Ts: ts, SessionID: "session-c", Agent: "codex", CWD: "/work/gamma", ToolName: "Read", Action: "allow"},
	} {
		if err := s.RecordDecision(ctx, record); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}

	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer ro.Close()
	policyReader, ok := ro.(interface {
		CountPolicyMatches(context.Context) ([]PolicyMatchCount, error)
		CountPolicyMatchesBySession(context.Context, int) ([]PolicySessionMatch, error)
	})
	if !ok {
		t.Fatal("read-only store does not expose policy match projection")
	}

	totals, err := policyReader.CountPolicyMatches(ctx)
	if err != nil {
		t.Fatalf("CountPolicyMatches: %v", err)
	}
	if len(totals) != 2 || totals[0] != (PolicyMatchCount{
		RuleID: "command_policy/no-sudo", Count: 2, AgentCount: 1, SessionCount: 1,
	}) {
		t.Fatalf("totals = %+v", totals)
	}

	breakdown, err := policyReader.CountPolicyMatchesBySession(ctx, 10)
	if err != nil {
		t.Fatalf("CountPolicyMatchesBySession: %v", err)
	}
	if len(breakdown) != 2 || breakdown[0] != (PolicySessionMatch{
		RuleID: "command_policy/no-sudo", Agent: "codex", SessionID: "session-a", CWD: "/work/alpha", Count: 2,
	}) {
		t.Fatalf("breakdown = %+v", breakdown)
	}
}
