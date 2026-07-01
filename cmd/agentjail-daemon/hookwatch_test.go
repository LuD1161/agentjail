package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/hookwatch"
)

// discardLogger returns a slog.Logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

// writeJSON writes v as indented JSON to path, creating parent dirs as needed.
func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// settingsWithHook returns a settings.json-shaped map that contains the hook entry.
func settingsWithHook(hookBin string) map[string]interface{} {
	return map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": hookBin,
				},
			},
		},
	}
}

// settingsWithoutHook returns a settings.json-shaped map with no hook entry.
func settingsWithoutHook() map[string]interface{} {
	return map[string]interface{}{
		"theme": "dark",
	}
}

// TestHookEntriesForAgent_ClaudeCode verifies the Claude Code shape via the
// exported hookwatch.HookEntriesForAgent function.
func TestHookEntriesForAgent_ClaudeCode(t *testing.T) {
	entries := hookwatch.HookEntriesForAgent("claude-code", "/usr/bin/agentjail-hook")
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
}

// TestHookEntriesForAgent_Codex verifies the Codex shape.
func TestHookEntriesForAgent_Codex(t *testing.T) {
	entries := hookwatch.HookEntriesForAgent("codex", "/bin/hook")
	ptu, ok := entries["PreToolUse"]
	if !ok {
		t.Fatal("expected PreToolUse key for codex")
	}
	if len(ptu) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ptu))
	}
	group, _ := ptu[0].(map[string]interface{})
	if group["matcher"] != ".*" {
		t.Fatalf("expected Codex matcher group, got: %#v", group)
	}
	nested, _ := group["hooks"].([]interface{})
	if len(nested) != 1 {
		t.Fatalf("expected one nested Codex hook, got %#v", group["hooks"])
	}
	entry, _ := nested[0].(map[string]interface{})
	cmd, _ := entry["command"].(string)
	if !strings.Contains(cmd, "--agent=codex") {
		t.Fatalf("expected Codex hook command with --agent=codex, got %q", cmd)
	}
}

// TestHookwatchNew_Integration is a basic smoke test that New() does not
// crash. The actual target discovery depends on the user's home directory
// and installed agents, so we just verify it returns a non-nil Watcher.
func TestHookwatchNew_Integration(t *testing.T) {
	w := hookwatch.New(discardLogger(), audit.NopEmitter{})
	if w == nil {
		t.Fatal("New returned nil")
	}
}

// TestHookwatchRun_CancelsPromptly verifies Run exits when ctx is cancelled.
func TestHookwatchRun_CancelsPromptly(t *testing.T) {
	w := hookwatch.New(discardLogger(), audit.NopEmitter{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit within 2s after context cancellation")
	}
}
