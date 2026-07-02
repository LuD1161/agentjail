// Package hookwatch monitors agent hook configuration files for tampering
// and re-injects the agentjail-hook entry when it is removed (ADR 0026).
package hookwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/fsnotify/fsnotify"
)

// Target describes one hook config file to monitor.
type Target struct {
	path    string // absolute path to the config file
	agentID string // "claude-code", "codex", "cursor"
	lastMod time.Time
}

// Watcher monitors hook configuration files for tampering.
type Watcher struct {
	targets []Target
	logger  *slog.Logger
	emitter audit.Emitter
}

// New discovers which hook config files exist and returns a Watcher.
func New(logger *slog.Logger, emitter audit.Emitter) *Watcher {
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Warn("hookwatch: cannot determine home dir", "error", err)
		return &Watcher{logger: logger, emitter: emitter}
	}

	candidates := []struct {
		path    string
		agentID string
	}{
		{filepath.Join(home, ".claude", "settings.json"), "claude-code"},
		{filepath.Join(home, ".codex", "hooks.json"), "codex"},
		{filepath.Join(home, ".cursor", "hooks.json"), "cursor"},
	}

	var targets []Target
	for _, c := range candidates {
		info, err := os.Stat(c.path)
		if err != nil {
			continue // file doesn't exist -- agent not installed
		}
		targets = append(targets, Target{
			path:    c.path,
			agentID: c.agentID,
			lastMod: info.ModTime(),
		})
	}

	logger.Info("hookwatch: monitoring hook configs", "count", len(targets))
	return &Watcher{targets: targets, logger: logger, emitter: emitter}
}

// Run watches target config files for changes using fsnotify with a 30-second
// fallback poll for filesystems that lack inotify support (e.g. NFS).
// Blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	if len(w.targets) == 0 {
		return
	}

	// Build a set of target paths for fast event matching.
	targetSet := make(map[string]struct{}, len(w.targets))
	for _, t := range w.targets {
		targetSet[t.path] = struct{}{}
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		w.logger.Warn("hookwatch: fsnotify unavailable, falling back to polling only", "error", err)
		w.runPollingOnly(ctx)
		return
	}
	defer fsw.Close()

	// Watch parent directories (fsnotify watches dirs, not individual files,
	// which also handles atomic rename patterns).
	watched := make(map[string]struct{})
	for _, t := range w.targets {
		dir := filepath.Dir(t.path)
		if _, ok := watched[dir]; ok {
			continue
		}
		if err := fsw.Add(dir); err != nil {
			w.logger.Warn("hookwatch: cannot watch directory", "dir", dir, "error", err)
		} else {
			watched[dir] = struct{}{}
		}
	}

	// Fallback poll every 30 seconds for NFS and similar.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-fsw.Events:
			if !ok {
				return
			}
			// Only act on Write or Create for a target file.
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			abs, err := filepath.Abs(event.Name)
			if err != nil {
				abs = event.Name
			}
			if _, isTarget := targetSet[abs]; !isTarget {
				continue
			}
			w.checkTarget(abs)

		case err, ok := <-fsw.Errors:
			if !ok {
				return
			}
			w.logger.Warn("hookwatch: fsnotify error", "error", err)

		case <-ticker.C:
			w.check()
		}
	}
}

// runPollingOnly is the fallback when fsnotify cannot be initialised.
func (w *Watcher) runPollingOnly(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
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

// checkTarget runs the check logic for a single target identified by path.
func (w *Watcher) checkTarget(path string) {
	for i := range w.targets {
		if w.targets[i].path == path {
			t := &w.targets[i]
			info, err := os.Stat(t.path)
			if err != nil {
				w.logger.Warn("hookwatch: config file missing", "path", t.path, "agent", t.agentID)
				return
			}

			if !info.ModTime().After(t.lastMod) {
				return // no actual change (duplicate event)
			}
			t.lastMod = info.ModTime()

			if !w.hasAgentjailHook(t.path) {
				w.logger.Warn("hookwatch: agentjail hook removed from config", "path", t.path, "agent", t.agentID)
				_ = w.emitter.Emit(context.Background(), audit.Event{
					EventType: audit.HookTampered,
					Entity:    t.path,
					Detail:    map[string]string{"agent": t.agentID},
					Actor:     "daemon:hookwatch",
				})
				w.reinjectHook(t)
			}
			return
		}
	}
}

func (w *Watcher) check() {
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

		// File changed -- verify hook entry is still present.
		if !w.hasAgentjailHook(t.path) {
			w.logger.Warn("hookwatch: agentjail hook removed from config", "path", t.path, "agent", t.agentID)
			_ = w.emitter.Emit(context.Background(), audit.Event{
				EventType: audit.HookTampered,
				Entity:    t.path,
				Detail:    map[string]string{"agent": t.agentID},
				Actor:     "daemon:hookwatch",
			})
			w.reinjectHook(t)
		}
	}
}

// hasAgentjailHook returns true if path contains the canonical hook binary name.
// "agentjail-hook" is unique enough to avoid false matches on the word "agentjail"
// appearing elsewhere in the config (e.g. in comments or tool descriptions).
func (w *Watcher) hasAgentjailHook(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "agentjail-hook")
}

// reinjectHook reads the config at t.path, inserts the agent-specific
// agentjail-hook entries, and atomically writes it back.
func (w *Watcher) reinjectHook(t *Target) {
	data, err := os.ReadFile(t.path)
	if err != nil {
		w.logger.Error("hookwatch: cannot read config for reinject", "path", t.path, "error", err)
		return
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		w.logger.Error("hookwatch: cannot parse config for reinject (broken JSON -- skipping)", "path", t.path, "error", err)
		return
	}

	// Resolve the hook binary path.
	home, err := os.UserHomeDir()
	if err != nil {
		w.logger.Error("hookwatch: cannot determine home dir for reinject", "error", err)
		return
	}
	hookBin := filepath.Join(home, ".agentjail", "bin", "agentjail-hook")

	// Ensure hooks map exists.
	hooks, _ := doc["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
		doc["hooks"] = hooks
	}

	if t.agentID == "cursor" {
		if _, ok := doc["version"]; !ok {
			doc["version"] = 1
		}
	}

	for event, entries := range hookEntriesForAgent(t.agentID, hookBin) {
		existing, _ := hooks[event].([]interface{})
		existing = append(existing, entries...)
		hooks[event] = existing
	}

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

	_ = w.emitter.Emit(context.Background(), audit.Event{
		EventType: audit.HookReinjected,
		Entity:    t.path,
		Detail:    map[string]string{"agent": t.agentID},
		Actor:     "daemon:hookwatch",
	})
}

func hookEntriesForAgent(agentID, hookBin string) map[string][]interface{} {
	switch agentID {
	case "codex":
		return map[string][]interface{}{
			"PreToolUse": {
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": hookBin + " --agent=codex",
							"timeout": 30,
						},
					},
				},
			},
		}
	case "cursor":
		entry := map[string]interface{}{"command": hookBin + " --agent=cursor"}
		return map[string][]interface{}{
			"beforeShellExecution": {entry},
			"beforeMCPExecution":   {entry},
			"beforeReadFile":       {entry},
		}
	default:
		return map[string][]interface{}{
			"PreToolUse": {
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": hookBin,
						},
					},
				},
			},
		}
	}
}

// HookEntriesForAgent returns the hook configuration entries for a given agent
// and hook binary path. Exported for testing.
func HookEntriesForAgent(agentID, hookBin string) map[string][]interface{} {
	return hookEntriesForAgent(agentID, hookBin)
}

// EmitTampered is a convenience for external callers that need to emit a
// tamper event with the same shape the watcher uses internally.
func EmitTampered(emitter audit.Emitter, path, agentID string) error {
	return emitter.Emit(context.Background(), audit.Event{
		EventType: audit.HookTampered,
		Entity:    path,
		Detail:    map[string]string{"agent": agentID},
		Actor:     "daemon:hookwatch",
	})
}

// FormatDetail returns the detail string matching the old callback format,
// useful during migration.
func FormatDetail(path, agentID string) string {
	return fmt.Sprintf("re-injected agentjail hook into %s (%s)", path, agentID)
}
