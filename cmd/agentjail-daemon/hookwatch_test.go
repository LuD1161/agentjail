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

// TestHookWatcher_DetectsRemoval verifies that when the hook entry is removed
// from a config file, check() re-injects it and fires the audit callback.
func TestHookWatcher_DetectsRemoval(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	hookBin := filepath.Join(dir, "agentjail-hook") // canonical path doesn't need to exist for the test

	// Write initial config WITH the hook entry so the watcher starts "clean".
	writeJSON(t, cfgPath, settingsWithHook(hookBin))

	info, _ := os.Stat(cfgPath)
	target := &hookWatchTarget{
		path:    cfgPath,
		agentID: "claude-code",
		lastMod: info.ModTime(),
	}

	var auditAction, auditDetail string
	w := &hookWatcher{
		targets: []hookWatchTarget{*target},
		logger:  discardLogger(),
		auditFn: func(action, detail string) {
			auditAction = action
			auditDetail = detail
		},
	}

	// Now overwrite with a config that has NO hook entry.
	// Sleep briefly so the mtime changes (filesystem resolution is usually 1s on
	// most platforms; use 10ms with a forced mtime tweak via chtimes instead).
	writeJSON(t, cfgPath, settingsWithoutHook())
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, future, future)

	// Run check — should detect the change and re-inject.
	w.check()

	// Verify the config now contains "agentjail-hook".
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after reinject: %v", err)
	}
	if !strings.Contains(string(data), "agentjail-hook") {
		t.Errorf("expected agentjail-hook to be present in config after reinject, got:\n%s", data)
	}

	// Verify audit callback fired.
	if auditAction != "hook_reinject" {
		t.Errorf("expected audit action 'hook_reinject', got %q", auditAction)
	}
	if !strings.Contains(auditDetail, "claude-code") {
		t.Errorf("expected audit detail to mention 'claude-code', got %q", auditDetail)
	}

	// Verify PreToolUse array is present and valid JSON.
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("re-injected config is not valid JSON: %v", err)
	}
	hooks, _ := doc["hooks"].(map[string]interface{})
	if hooks == nil {
		t.Fatal("hooks key missing after reinject")
	}
	pre, _ := hooks["PreToolUse"].([]interface{})
	if len(pre) == 0 {
		t.Fatal("PreToolUse is empty after reinject")
	}
}

// TestHookWatcher_ReinjectsCodexAgentSpecificHook verifies that Codex config
// repair uses the Codex matcher-group shape and invokes the hook with
// --agent=codex instead of reintroducing a bare Claude-style hook command.
func TestHookWatcher_ReinjectsCodexAgentSpecificHook(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	writeJSON(t, cfgPath, settingsWithoutHook())

	info, _ := os.Stat(cfgPath)
	w := &hookWatcher{
		targets: []hookWatchTarget{
			{path: cfgPath, agentID: "codex", lastMod: info.ModTime()},
		},
		logger:  discardLogger(),
		auditFn: nil,
	}

	writeJSON(t, cfgPath, settingsWithoutHook())
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, future, future)

	w.check()

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after reinject: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("re-injected config is not valid JSON: %v", err)
	}
	hooks, _ := doc["hooks"].(map[string]interface{})
	pre, _ := hooks["PreToolUse"].([]interface{})
	if len(pre) != 1 {
		t.Fatalf("expected one PreToolUse entry, got %d: %s", len(pre), data)
	}
	group, _ := pre[0].(map[string]interface{})
	if group["matcher"] != ".*" {
		t.Fatalf("expected Codex matcher group, got: %#v", group)
	}
	nested, _ := group["hooks"].([]interface{})
	if len(nested) != 1 {
		t.Fatalf("expected one nested Codex hook, got %#v", group["hooks"])
	}
	entry, _ := nested[0].(map[string]interface{})
	cmd, _ := entry["command"].(string)
	if !strings.Contains(cmd, "agentjail-hook --agent=codex") {
		t.Fatalf("expected Codex hook command, got %q", cmd)
	}
	if entry["type"] != "command" {
		t.Fatalf("expected command hook type, got %#v", entry["type"])
	}
	if entry["timeout"] != float64(30) {
		t.Fatalf("expected timeout 30, got %#v", entry["timeout"])
	}
}

// TestHookWatcher_NoActionOnSafeEdit verifies that when the file changes but
// the hook entry is still present, check() does NOT re-inject or fire audit.
func TestHookWatcher_NoActionOnSafeEdit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	hookBin := filepath.Join(dir, "agentjail-hook")

	writeJSON(t, cfgPath, settingsWithHook(hookBin))
	info, _ := os.Stat(cfgPath)
	target := &hookWatchTarget{
		path:    cfgPath,
		agentID: "claude-code",
		lastMod: info.ModTime(),
	}

	auditCalled := false
	w := &hookWatcher{
		targets: []hookWatchTarget{*target},
		logger:  discardLogger(),
		auditFn: func(action, detail string) {
			auditCalled = true
		},
	}

	// Modify the file but keep the hook entry (add an unrelated key).
	updated := settingsWithHook(hookBin)
	updated["theme"] = "light"
	writeJSON(t, cfgPath, updated)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, future, future)

	w.check()

	if auditCalled {
		t.Error("audit callback should NOT fire when hook entry is still present")
	}

	// File content should be unchanged (no reinject appended a second entry).
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("config not valid JSON: %v", err)
	}
	hooks, _ := doc["hooks"].(map[string]interface{})
	pre, _ := hooks["PreToolUse"].([]interface{})
	if len(pre) != 1 {
		t.Errorf("expected exactly 1 PreToolUse entry, got %d", len(pre))
	}
}

// TestHookWatcher_SkipsMissingFiles verifies that a watcher whose target file
// has been deleted does not crash, and does not re-inject into a non-existent file.
func TestHookWatcher_SkipsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nonexistent.json")

	// Target file never created.
	w := &hookWatcher{
		targets: []hookWatchTarget{
			{path: cfgPath, agentID: "claude-code", lastMod: time.Time{}},
		},
		logger:  discardLogger(),
		auditFn: nil,
	}

	// Should not panic.
	w.check()

	// File should still not exist.
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Error("expected file to remain absent, but it exists")
	}
}

// TestHookWatcher_RunCancels verifies Run exits promptly when ctx is cancelled.
func TestHookWatcher_RunCancels(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	writeJSON(t, cfgPath, settingsWithHook(filepath.Join(dir, "agentjail-hook")))
	info, _ := os.Stat(cfgPath)

	w := &hookWatcher{
		targets: []hookWatchTarget{
			{path: cfgPath, agentID: "claude-code", lastMod: info.ModTime()},
		},
		logger:  discardLogger(),
		auditFn: nil,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// Good: Run exited promptly.
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit within 2s after context cancellation")
	}
}

// TestHookWatcher_EmptyTargets verifies Run returns immediately when there are
// no targets (e.g. no agents installed).
func TestHookWatcher_EmptyTargets(t *testing.T) {
	w := &hookWatcher{
		targets: nil,
		logger:  discardLogger(),
		auditFn: nil,
	}

	done := make(chan struct{})
	go func() {
		w.Run(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(1 * time.Second):
		t.Error("Run with no targets should return immediately")
	}
}

// TestHasAgentjailHook verifies the hook-presence check.
func TestHasAgentjailHook(t *testing.T) {
	dir := t.TempDir()
	w := &hookWatcher{logger: discardLogger()}

	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "has agentjail-hook",
			content: `{"hooks":{"PreToolUse":[{"type":"command","command":"/home/user/.agentjail/bin/agentjail-hook"}]}}`,
			want:    true,
		},
		{
			name:    "word agentjail only — no match",
			content: `{"description":"agentjail is a policy guardrail"}`,
			want:    false,
		},
		{
			name:    "empty file",
			content: `{}`,
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := w.hasAgentjailHook(p)
			if got != tc.want {
				t.Errorf("hasAgentjailHook = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHookWatcher_BrokenJSONSkipsReinject ensures a config file with invalid
// JSON is left untouched rather than being silently corrupted.
func TestHookWatcher_BrokenJSONSkipsReinject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")

	broken := []byte(`{ "hooks": { THIS IS NOT JSON }`)
	if err := os.WriteFile(cfgPath, broken, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := &hookWatcher{
		targets: []hookWatchTarget{
			{path: cfgPath, agentID: "claude-code", lastMod: time.Time{}},
		},
		logger:  discardLogger(),
		auditFn: nil,
	}

	// Force mtime into the "changed" window.
	info, _ := os.Stat(cfgPath)
	w.targets[0].lastMod = info.ModTime().Add(-1 * time.Second)

	// check() should detect the file changed, try to parse it, fail, and leave it alone.
	w.check()

	got, _ := os.ReadFile(cfgPath)
	if string(got) != string(broken) {
		t.Error("broken JSON config was modified; expected it to be left untouched")
	}
}
