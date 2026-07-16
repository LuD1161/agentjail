//go:build soak

// Soak harness for the async decision path (ADR 0018): a real store, the real
// 1024-entry buffer, and the real drainDecisions writer. Answers "does a long
// session lose decisions, and at what rate does it start?"
//
// go test ./internal/daemonapp/ -tags soak -run TestSoak -v -timeout 30m
package daemonapp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
)

func newSoakServer(t *testing.T) *server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "soak.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Same buffer the daemon builds at main.go:908.
	return &server{eventStore: st, decCh: make(chan store.DecisionRecord, 1024)}
}

// soakDropped sums the decisions.dropped audit events. The in-memory counter
// is Swap(0)'d into these events by every flush (incl. the shutdown flush at
// main.go:231), so after Wait() the events are the only complete record.
func soakDropped(t *testing.T, s *server) int64 {
	t.Helper()
	got, err := s.eventStore.ListAuditLog(context.Background(), store.AuditLogFilter{
		EventType: audit.DecisionsDropped, Limit: 10000,
	})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var total int64
	for _, e := range got {
		var d struct {
			Count string `json:"count"`
		}
		if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
			t.Fatalf("detail %q: %v", e.Detail, err)
		}
		n, err := strconv.ParseInt(d.Count, 10, 64)
		if err != nil {
			t.Fatalf("count %q: %v", d.Count, err)
		}
		total += n
	}
	return total + s.decDropped.Load()
}

func soakDecision(n int) store.DecisionRecord {
	return store.DecisionRecord{
		Ts:        time.Now(),
		SessionID: "soak-session",
		Agent:     "claude-code",
		ToolName:  "Bash",
		Summary:   fmt.Sprintf("go build ./pkg%d", n%50),
		Action:    "allow",
		RuleID:    "default-allow",
		Reason:    "no rule matched",
		ElapsedUs: 1200,
		CWD:       "/home/agent/repo",
		ToolInput: map[string]interface{}{
			"command": fmt.Sprintf("go build ./pkg%d/... --verbose", n%50),
		},
	}
}

// TestSoakUnthrottledFlood is the worst case: a producer with no think-time,
// which is what a runaway agent or a replayed transcript looks like.
func TestSoakUnthrottledFlood(t *testing.T) {
	const total = 50000

	s := newSoakServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.decWg.Add(1)
	go s.drainDecisions(ctx)

	start := time.Now()
	for i := 0; i < total; i++ {
		s.enqueueDecision(soakDecision(i))
	}
	enqueued := time.Since(start)

	cancel() // drainDecisions drains what is left, then exits
	s.decWg.Wait()

	dropped := soakDropped(t, s)
	persisted, err := s.eventStore.DecisionCount(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	t.Logf("enqueued %d in %s (%.0f/sec)", total, enqueued, float64(total)/enqueued.Seconds())
	t.Logf("persisted=%d dropped=%d (%.1f%% lost)",
		persisted, dropped, 100*float64(dropped)/float64(total))

	if persisted+dropped != total {
		t.Errorf("unaccounted: persisted=%d + dropped=%d != %d", persisted, dropped, total)
	}
}

// TestSoakRealisticSession models a long session: a sustained tool-call rate
// with think-time, run long enough to cross several dropped-decision flush
// ticks. This is the case that must not lose anything.
func TestSoakRealisticSession(t *testing.T) {
	const (
		callsPerSec = 20 // far above a real agent's sustained rate
		duration    = 90 * time.Second
	)

	s := newSoakServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.decWg.Add(1)
	go s.drainDecisions(ctx)

	tick := time.NewTicker(time.Second / callsPerSec)
	defer tick.Stop()
	deadline := time.After(duration)
	sent := 0

loop:
	for {
		select {
		case <-tick.C:
			s.enqueueDecision(soakDecision(sent))
			sent++
		case <-deadline:
			break loop
		}
	}

	cancel()
	s.decWg.Wait()

	dropped := soakDropped(t, s)
	persisted, err := s.eventStore.DecisionCount(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	t.Logf("sustained %d calls/sec for %s: sent=%d persisted=%d dropped=%d",
		callsPerSec, duration, sent, persisted, dropped)

	if dropped != 0 {
		t.Errorf("dropped %d decisions at a realistic rate", dropped)
	}
	if persisted != int64(sent) {
		t.Errorf("persisted %d, sent %d — silent loss", persisted, sent)
	}
}
