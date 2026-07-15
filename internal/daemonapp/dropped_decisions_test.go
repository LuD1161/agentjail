package daemonapp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
)

func newDropTestServer(t *testing.T) *server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &server{eventStore: st, decCh: make(chan store.DecisionRecord, 1)}
}

func droppedEvents(t *testing.T, s *server) []store.AuditLogEntry {
	t.Helper()
	got, err := s.eventStore.ListAuditLog(context.Background(), store.AuditLogFilter{
		EventType: audit.DecisionsDropped, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	return got
}

// A full buffer must leave a durable trace, not just an slog.Warn (ADR 0072).
func TestDroppedDecisionsAreAudited(t *testing.T) {
	s := newDropTestServer(t)
	ctx := context.Background()

	// Buffer holds 1; nothing drains it, so the rest are dropped.
	for i := 0; i < 4; i++ {
		s.enqueueDecision(store.DecisionRecord{SessionID: "s1", Action: "allow"})
	}
	if got := s.decDropped.Load(); got != 3 {
		t.Fatalf("decDropped = %d, want 3", got)
	}

	s.flushDroppedDecisions(ctx)

	got := droppedEvents(t, s)
	if len(got) != 1 {
		t.Fatalf("got %d decisions.dropped events, want 1", len(got))
	}
	if detail := got[0].Detail; detail == "" || !strings.Contains(detail, `"count":"3"`) {
		t.Errorf("event detail %q does not report count=3", detail)
	}
	if left := s.decDropped.Load(); left != 0 {
		t.Errorf("counter not reset after flush: %d", left)
	}
}

// No drops must not emit a noise event every tick.
func TestFlushDroppedDecisionsNoopWhenNothingDropped(t *testing.T) {
	s := newDropTestServer(t)
	s.flushDroppedDecisions(context.Background())
	if got := droppedEvents(t, s); len(got) != 0 {
		t.Errorf("emitted %d events with zero drops, want 0", len(got))
	}
}
