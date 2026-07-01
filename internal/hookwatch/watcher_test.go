package hookwatch

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
)

// spyEmitter records emitted audit events for test assertions.
type spyEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *spyEmitter) Emit(_ context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *spyEmitter) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]audit.Event, len(s.events))
	copy(cp, s.events)
	return cp
}

func TestHookEntriesForAgent_ClaudeCode(t *testing.T) {
	entries := HookEntriesForAgent("claude-code", "/usr/bin/agentjail-hook")
	ptu, ok := entries["PreToolUse"]
	if !ok {
		t.Fatal("expected PreToolUse key for claude-code")
	}
	if len(ptu) != 1 {
		t.Fatalf("expected 1 PreToolUse entry, got %d", len(ptu))
	}
	entry, ok := ptu[0].(map[string]interface{})
	if !ok {
		t.Fatal("entry is not a map")
	}
	if entry["matcher"] != "*" {
		t.Errorf("expected matcher '*', got %v", entry["matcher"])
	}
	hooks, ok := entry["hooks"].([]interface{})
	if !ok || len(hooks) != 1 {
		t.Fatal("expected one hook entry")
	}
	hook := hooks[0].(map[string]interface{})
	if hook["command"] != "/usr/bin/agentjail-hook" {
		t.Errorf("unexpected command: %v", hook["command"])
	}
}

func TestHookEntriesForAgent_Codex(t *testing.T) {
	entries := HookEntriesForAgent("codex", "/bin/hook")
	ptu, ok := entries["PreToolUse"]
	if !ok {
		t.Fatal("expected PreToolUse key for codex")
	}
	if len(ptu) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ptu))
	}
	entry := ptu[0].(map[string]interface{})
	if entry["matcher"] != ".*" {
		t.Errorf("expected matcher '.*', got %v", entry["matcher"])
	}
	hooks := entry["hooks"].([]interface{})
	hook := hooks[0].(map[string]interface{})
	if hook["command"] != "/bin/hook --agent=codex" {
		t.Errorf("unexpected command: %v", hook["command"])
	}
}

func TestHookEntriesForAgent_Cursor(t *testing.T) {
	entries := HookEntriesForAgent("cursor", "/bin/hook")
	for _, key := range []string{"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"} {
		arr, ok := entries[key]
		if !ok {
			t.Errorf("expected key %s for cursor", key)
			continue
		}
		if len(arr) != 1 {
			t.Errorf("expected 1 entry for %s, got %d", key, len(arr))
		}
		entry := arr[0].(map[string]interface{})
		if entry["command"] != "/bin/hook --agent=cursor" {
			t.Errorf("unexpected command for %s: %v", key, entry["command"])
		}
	}
	if _, ok := entries["PreToolUse"]; ok {
		t.Error("cursor should not have PreToolUse key")
	}
}

func TestWatcher_ReinjectEmitsEvents(t *testing.T) {
	// Create a temp dir with a fake config that does NOT contain agentjail-hook.
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "settings.json")
	doc := map[string]interface{}{"hooks": map[string]interface{}{}}
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	spy := &spyEmitter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	w := &Watcher{
		targets: []Target{
			{path: cfgPath, agentID: "claude-code", lastMod: time.Time{}},
		},
		logger:  logger,
		emitter: spy,
	}

	// Manually update lastMod to before file mtime so check() sees a change.
	info, _ := os.Stat(cfgPath)
	w.targets[0].lastMod = info.ModTime().Add(-1 * time.Second)

	w.check()

	events := spy.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events (tampered + reinjected), got %d", len(events))
	}
	if events[0].EventType != audit.HookTampered {
		t.Errorf("first event should be HookTampered, got %s", events[0].EventType)
	}
	if events[0].Entity != cfgPath {
		t.Errorf("entity should be config path, got %s", events[0].Entity)
	}
	if events[1].EventType != audit.HookReinjected {
		t.Errorf("second event should be HookReinjected, got %s", events[1].EventType)
	}

	// Verify the hook was actually re-injected.
	reread, _ := os.ReadFile(cfgPath)
	if got := string(reread); !contains(got, "agentjail-hook") {
		t.Error("config should contain agentjail-hook after reinject")
	}
}

func TestWatcher_NoChangeNoEvents(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "settings.json")
	doc := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "/path/to/agentjail-hook",
						},
					},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	spy := &spyEmitter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	info, _ := os.Stat(cfgPath)
	w := &Watcher{
		targets: []Target{
			{path: cfgPath, agentID: "claude-code", lastMod: info.ModTime()},
		},
		logger:  logger,
		emitter: spy,
	}

	w.check()

	if len(spy.Events()) != 0 {
		t.Errorf("expected 0 events when file unchanged, got %d", len(spy.Events()))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
