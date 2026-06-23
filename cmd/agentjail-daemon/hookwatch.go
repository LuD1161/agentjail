package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hookWatchTarget describes one hook config file to monitor.
type hookWatchTarget struct {
	path    string // absolute path to the config file
	agentID string // "claude-code", "codex", "cursor"
	lastMod time.Time
}

// hookWatcher monitors hook configuration files for tampering.
type hookWatcher struct {
	targets []hookWatchTarget
	logger  *slog.Logger
	auditFn func(action, detail string) // callback to record audit events
}

// newHookWatcher discovers which hook config files exist and returns a watcher.
func newHookWatcher(logger *slog.Logger, auditFn func(action, detail string)) *hookWatcher {
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Warn("hookwatch: cannot determine home dir", "error", err)
		return &hookWatcher{logger: logger, auditFn: auditFn}
	}

	candidates := []struct {
		path    string
		agentID string
	}{
		{filepath.Join(home, ".claude", "settings.json"), "claude-code"},
		{filepath.Join(home, ".codex", "hooks.json"), "codex"},
		{filepath.Join(home, ".cursor", "hooks.json"), "cursor"},
	}

	var targets []hookWatchTarget
	for _, c := range candidates {
		info, err := os.Stat(c.path)
		if err != nil {
			continue // file doesn't exist — agent not installed
		}
		targets = append(targets, hookWatchTarget{
			path:    c.path,
			agentID: c.agentID,
			lastMod: info.ModTime(),
		})
	}

	logger.Info("hookwatch: monitoring hook configs", "count", len(targets))
	return &hookWatcher{targets: targets, logger: logger, auditFn: auditFn}
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (w *hookWatcher) Run(ctx context.Context) {
	if len(w.targets) == 0 {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *hookWatcher) check() {
	for i := range w.targets {
		t := &w.targets[i]
		info, err := os.Stat(t.path)
		if err != nil {
			// File was deleted entirely.
			w.logger.Warn("hookwatch: config file missing", "path", t.path, "agent", t.agentID)
			continue
		}

		if !info.ModTime().After(t.lastMod) {
			continue // no change
		}
		t.lastMod = info.ModTime()

		// File changed — verify hook entry is still present.
		if !w.hasAgentjailHook(t.path) {
			w.logger.Warn("hookwatch: agentjail hook removed from config", "path", t.path, "agent", t.agentID)
			w.reinjectHook(t)
		}
	}
}

// hasAgentjailHook returns true if path contains the canonical hook binary name.
// "agentjail-hook" is unique enough to avoid false matches on the word "agentjail"
// appearing elsewhere in the config (e.g. in comments or tool descriptions).
func (w *hookWatcher) hasAgentjailHook(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "agentjail-hook")
}

// reinjectHook reads the config at t.path, inserts the agentjail-hook entry
// under hooks.PreToolUse (Claude Code format), and atomically writes it back.
func (w *hookWatcher) reinjectHook(t *hookWatchTarget) {
	data, err := os.ReadFile(t.path)
	if err != nil {
		w.logger.Error("hookwatch: cannot read config for reinject", "path", t.path, "error", err)
		return
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		w.logger.Error("hookwatch: cannot parse config for reinject (broken JSON — skipping)", "path", t.path, "error", err)
		return
	}

	// Resolve the hook binary path.
	home, err := os.UserHomeDir()
	if err != nil {
		w.logger.Error("hookwatch: cannot determine home dir for reinject", "error", err)
		return
	}
	hookBin := filepath.Join(home, ".agentjail", "bin", "agentjail-hook")

	// Build the hook entry (Claude Code PreToolUse format).
	hookEntry := map[string]interface{}{
		"type":    "command",
		"command": hookBin,
	}

	// Ensure hooks map exists.
	hooks, _ := doc["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
		doc["hooks"] = hooks
	}

	// Append to PreToolUse list.
	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	preToolUse = append(preToolUse, hookEntry)
	hooks["PreToolUse"] = preToolUse

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		w.logger.Error("hookwatch: cannot marshal config", "path", t.path, "error", err)
		return
	}

	// Atomic write via temp file + rename.
	tmp := t.path + ".agentjail-tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		w.logger.Error("hookwatch: cannot write temp file", "path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, t.path); err != nil {
		w.logger.Error("hookwatch: cannot rename temp file", "path", t.path, "error", err)
		_ = os.Remove(tmp)
		return
	}

	// Update lastMod so the rename's mtime change doesn't re-trigger.
	if info, err := os.Stat(t.path); err == nil {
		t.lastMod = info.ModTime()
	}

	w.logger.Warn("hookwatch: re-injected agentjail hook",
		"path", t.path,
		"agent", t.agentID,
		"hook_bin", hookBin,
	)

	if w.auditFn != nil {
		w.auditFn("hook_reinject",
			fmt.Sprintf("re-injected agentjail hook into %s (%s)", t.path, t.agentID))
	}
}
