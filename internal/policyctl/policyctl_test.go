package policyctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/store"
)

// failEmitter always returns an error on Emit.
type failEmitter struct{}

func (failEmitter) Emit(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}

// seedPolicyFile writes a minimal policy.yaml so LoadOrDefault can find it.
func seedPolicyFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Empty file is valid -- LoadOrDefault returns Default().
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func openTestStore(t *testing.T) store.EventStore {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// auditEntries returns all audit_log entries from the store.
func auditEntries(t *testing.T, st store.EventStore) []store.AuditLogEntry {
	t.Helper()
	entries, err := st.ListAuditLog(context.Background(), store.AuditLogFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestApply_TwoPhaseAudit(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)
	st := openTestStore(t)

	ctrl := New(policyPath, st, nil)

	detail := map[string]string{"server": "test-server", "action": "allow"}
	err := ctrl.Apply(context.Background(), "mcp:test-server", "cli:mcp-allow", detail, func(cfg *config.PolicyConfig) error {
		cfg.MCP.Allowed = append(cfg.MCP.Allowed, "test-server")
		return nil
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}

	// Verify both audit events were emitted.
	entries := auditEntries(t, st)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(entries))
	}

	var foundRequested, foundChanged bool
	for _, e := range entries {
		if e.EventType == audit.PolicyChangeRequested {
			foundRequested = true
		}
		if e.EventType == audit.PolicyChanged {
			foundChanged = true
		}
	}
	if !foundRequested {
		t.Error("missing policy.change_requested audit entry")
	}
	if !foundChanged {
		t.Error("missing policy.changed audit entry")
	}

	// Verify the config was saved.
	saved, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	found := false
	for _, a := range saved.MCP.Allowed {
		if a == "test-server" {
			found = true
		}
	}
	if !found {
		t.Error("mutation was not persisted to policy.yaml")
	}
}

func TestApply_AbortsOnAuditFailure(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)

	ctrl := New(policyPath, failEmitter{}, nil)

	mutationCalled := false
	err := ctrl.Apply(context.Background(), "mcp:x", "cli:test", nil, func(cfg *config.PolicyConfig) error {
		mutationCalled = true
		cfg.MCP.Allowed = append(cfg.MCP.Allowed, "x")
		return nil
	})
	if err == nil {
		t.Fatal("expected error when emitter fails")
	}
	if mutationCalled {
		t.Error("mutation should NOT have been called when audit fails")
	}

	// Config file should be unchanged (still the default empty config).
	saved, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	for _, a := range saved.MCP.Allowed {
		if a == "x" {
			t.Error("config was mutated despite audit failure")
		}
	}
}

func TestApply_MutationError(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)
	st := openTestStore(t)

	ctrl := New(policyPath, st, nil)

	err := ctrl.Apply(context.Background(), "mcp:x", "cli:test", nil, func(cfg *config.PolicyConfig) error {
		return errors.New("mutation refused")
	})
	if err == nil {
		t.Fatal("expected error from mutation")
	}

	entries := auditEntries(t, st)
	var foundRequested, foundChanged bool
	for _, e := range entries {
		if e.EventType == audit.PolicyChangeRequested {
			foundRequested = true
		}
		if e.EventType == audit.PolicyChanged {
			foundChanged = true
		}
	}
	if !foundRequested {
		t.Error("change_requested should still be emitted before mutation")
	}
	if foundChanged {
		t.Error("policy.changed should NOT be emitted when mutation fails")
	}
}

func TestApply_SighupCalled(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)
	st := openTestStore(t)

	sighupCalled := false
	ctrl := New(policyPath, st, func() { sighupCalled = true })

	err := ctrl.Apply(context.Background(), "mcp:x", "cli:test", nil, func(cfg *config.PolicyConfig) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if !sighupCalled {
		t.Error("sighup callback was not called after successful mutation")
	}
}

func TestApply_SighupNotCalledOnError(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)

	sighupCalled := false
	ctrl := New(policyPath, failEmitter{}, func() { sighupCalled = true })

	_ = ctrl.Apply(context.Background(), "mcp:x", "cli:test", nil, func(cfg *config.PolicyConfig) error {
		return nil
	})
	if sighupCalled {
		t.Error("sighup should NOT be called when audit fails")
	}
}

func TestApplyWithConfig_PreLoadedConfig(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)
	st := openTestStore(t)

	ctrl := New(policyPath, st, nil)

	// Pre-load config.
	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	detail := map[string]string{"server": "preloaded", "action": "allow"}
	err = ctrl.ApplyWithConfig(context.Background(), cfg, "mcp:preloaded", "cli:test", detail, func(cfg *config.PolicyConfig) error {
		cfg.MCP.Allowed = append(cfg.MCP.Allowed, "preloaded")
		return nil
	})
	if err != nil {
		t.Fatalf("ApplyWithConfig returned error: %v", err)
	}

	// Verify both audit events and persisted config.
	entries := auditEntries(t, st)
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(entries))
	}

	saved, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range saved.MCP.Allowed {
		if a == "preloaded" {
			found = true
		}
	}
	if !found {
		t.Error("ApplyWithConfig did not persist the mutation")
	}
}

func TestNewFromDBPath(t *testing.T) {
	dir := t.TempDir()
	policyPath := seedPolicyFile(t, dir)
	dbPath := filepath.Join(t.TempDir(), "fromdb.db")

	ctrl, st, err := NewFromDBPath(policyPath, dbPath, nil)
	if err != nil {
		t.Fatalf("NewFromDBPath: %v", err)
	}
	defer st.Close()

	if ctrl == nil {
		t.Fatal("NewFromDBPath returned nil Controller")
	}

	// Verify the store works by doing a simple Apply.
	err = ctrl.Apply(context.Background(), "test:entity", "cli:test", nil, func(cfg *config.PolicyConfig) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Apply via NewFromDBPath controller: %v", err)
	}
}

func TestNewFromDBPath_BadPath(t *testing.T) {
	_, _, err := NewFromDBPath("/nonexistent/policy.yaml", "/nonexistent/dir/bad.db", nil)
	if err == nil {
		t.Fatal("expected error for bad DB path")
	}
}
