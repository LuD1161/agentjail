package main

import (
	"context"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

// mockReadOnlyStore implements store.ReadOnlyStore for testing.
type mockReadOnlyStore struct {
	sessions  []store.Session
	decisions []store.DecisionRecord
}

func (m *mockReadOnlyStore) DecisionCount(_ context.Context) (int64, error) {
	return int64(len(m.decisions)), nil
}

func (m *mockReadOnlyStore) ListDecisions(_ context.Context, f store.Filter) ([]store.DecisionRecord, error) {
	var result []store.DecisionRecord
	for _, d := range m.decisions {
		if f.SessionID != "" && d.SessionID != f.SessionID {
			continue
		}
		if f.AfterID > 0 && d.ID <= f.AfterID {
			continue
		}
		result = append(result, d)
		if f.Limit > 0 && len(result) >= f.Limit {
			break
		}
	}
	return result, nil
}

func (m *mockReadOnlyStore) ListAuditEvents(_ context.Context, _ store.AuditFilter) ([]store.AuditRecord, error) {
	return nil, nil
}

func (m *mockReadOnlyStore) ListSessions(_ context.Context) ([]store.Session, error) {
	return m.sessions, nil
}

func (m *mockReadOnlyStore) CountActionsBySession(_ context.Context) ([]store.ActionCount, error) {
	return nil, nil
}

func (m *mockReadOnlyStore) ListDiscoveredTools(_ context.Context, _ string) ([]store.DiscoveredTool, error) {
	return nil, nil
}

func (m *mockReadOnlyStore) ListDiscoveredSkills(_ context.Context) ([]store.DiscoveredSkill, error) {
	return nil, nil
}

func (m *mockReadOnlyStore) Close() error { return nil }

func TestResolveSessionPrefix_ExactMatch(t *testing.T) {
	st := &mockReadOnlyStore{
		sessions: []store.Session{
			{SessionID: "abc12345-6789-abcd-ef01-234567890abc"},
			{SessionID: "abc12345-xxxx-yyyy-zzzz-111111111111"},
		},
	}
	got, err := resolveSessionPrefix(context.Background(), st, "abc12345-6789-abcd-ef01-234567890abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc12345-6789-abcd-ef01-234567890abc" {
		t.Fatalf("expected exact match, got %q", got)
	}
}

func TestResolveSessionPrefix_PrefixMatch(t *testing.T) {
	st := &mockReadOnlyStore{
		sessions: []store.Session{
			{SessionID: "abc12345-6789-abcd-ef01-234567890abc"},
			{SessionID: "def67890-1234-5678-9012-abcdef012345"},
		},
	}
	got, err := resolveSessionPrefix(context.Background(), st, "abc12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc12345-6789-abcd-ef01-234567890abc" {
		t.Fatalf("expected prefix match, got %q", got)
	}
}

func TestResolveSessionPrefix_Ambiguous(t *testing.T) {
	st := &mockReadOnlyStore{
		sessions: []store.Session{
			{SessionID: "abc12345-6789-abcd-ef01-234567890abc"},
			{SessionID: "abc12345-xxxx-yyyy-zzzz-111111111111"},
		},
	}
	_, err := resolveSessionPrefix(context.Background(), st, "abc12345")
	if err == nil {
		t.Fatal("expected error for ambiguous prefix")
	}
}

func TestResolveSessionPrefix_NoMatch(t *testing.T) {
	st := &mockReadOnlyStore{
		sessions: []store.Session{
			{SessionID: "abc12345-6789-abcd-ef01-234567890abc"},
		},
	}
	_, err := resolveSessionPrefix(context.Background(), st, "zzz")
	if err == nil {
		t.Fatal("expected error for no match")
	}
}

func TestResolveSessionPrefix_ExactWinsOverPrefix(t *testing.T) {
	st := &mockReadOnlyStore{
		sessions: []store.Session{
			{SessionID: "bench"},
			{SessionID: "benchmark-extended"},
		},
	}
	got, err := resolveSessionPrefix(context.Background(), st, "bench")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bench" {
		t.Fatalf("exact match should win, got %q", got)
	}
}

func TestLoadAllDecisions_SinglePage(t *testing.T) {
	st := &mockReadOnlyStore{
		decisions: []store.DecisionRecord{
			{ID: 1, SessionID: "s1", Action: "allow"},
			{ID: 2, SessionID: "s1", Action: "deny"},
			{ID: 3, SessionID: "s1", Action: "allow"},
		},
	}
	rows, err := loadAllDecisions(context.Background(), st, "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
}

func TestLoadAllDecisions_MultiPage(t *testing.T) {
	var decs []store.DecisionRecord
	for i := 1; i <= 2500; i++ {
		decs = append(decs, store.DecisionRecord{
			ID:        int64(i),
			SessionID: "s1",
			Action:    "allow",
			Ts:        time.Now(),
		})
	}
	st := &mockReadOnlyStore{decisions: decs}
	rows, err := loadAllDecisions(context.Background(), st, "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 2500 {
		t.Fatalf("expected 2500 rows, got %d", len(rows))
	}
}

func TestLoadAllDecisions_EmptySession(t *testing.T) {
	st := &mockReadOnlyStore{decisions: nil}
	rows, err := loadAllDecisions(context.Background(), st, "s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(rows))
	}
}
