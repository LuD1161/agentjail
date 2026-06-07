package telemetry

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// DecisionWindow is one window's aggregated decision counts. It is the unit the
// v2 SQLite-backed source will also produce — keep this struct stable.
type DecisionWindow struct {
	ActionCounts map[string]int `json:"action_counts"`
	RuleCounts   map[string]int `json:"rule_counts"`
}

// DecisionSource is the seam for the future SQLite-derived implementation.
// v1 is the in-memory Stats below; v2 swaps the impl with no schema change.
type DecisionSource interface {
	Snapshot() DecisionWindow
	Reset()
}

const maxLatencySamples = 10000

// Stats is the in-memory v1 DecisionSource plus best-effort latency samples.
// Decision counts are checkpointed; latency samples are NOT (perf is least
// critical and lossy-on-crash is acceptable).
type Stats struct {
	mu        sync.Mutex
	action    map[string]int
	rule      map[string]int
	latencies []float64 // milliseconds, capped
}

func NewStats() *Stats {
	return &Stats{action: map[string]int{}, rule: map[string]int{}}
}

func (s *Stats) RecordDecision(action, ruleID string, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if action != "" {
		s.action[action]++
	}
	if ruleID != "" {
		s.rule[ruleID]++
	}
	if len(s.latencies) < maxLatencySamples {
		s.latencies = append(s.latencies, float64(elapsed.Microseconds())/1000.0)
	}
}

func (s *Stats) Snapshot() DecisionWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DecisionWindow{ActionCounts: copyMap(s.action), RuleCounts: copyMap(s.rule)}
}

func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.action = map[string]int{}
	s.rule = map[string]int{}
	s.latencies = nil
}

func (s *Stats) LatencyPercentiles() (p50, p95 float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.latencies) == 0 {
		return 0, 0
	}
	xs := append([]float64(nil), s.latencies...)
	sort.Float64s(xs)
	return pct(xs, 0.50), pct(xs, 0.95)
}

func pct(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q * float64(len(sorted)-1))
	return sorted[idx]
}

// MarshalCheckpoint serializes the decision counts (not latencies) for the
// ~60s on-disk checkpoint.
func (s *Stats) MarshalCheckpoint() ([]byte, error) {
	return json.Marshal(s.Snapshot())
}

// LoadCheckpoint parses a checkpoint into a DecisionWindow.
func LoadCheckpoint(b []byte) (DecisionWindow, error) {
	var w DecisionWindow
	if err := json.Unmarshal(b, &w); err != nil {
		return DecisionWindow{}, err
	}
	if w.ActionCounts == nil {
		w.ActionCounts = map[string]int{}
	}
	if w.RuleCounts == nil {
		w.RuleCounts = map[string]int{}
	}
	return w, nil
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
