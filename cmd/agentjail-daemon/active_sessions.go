package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// activeEntry is one entry in the active-sessions.json file.
type activeEntry struct {
	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
}

// activeTracker maintains a map of session IDs to their agent PIDs.
// On every update it atomically rewrites ~/.agentjail/active-sessions.json
// so the CLI can read it and check if the PID is still alive.
type activeTracker struct {
	mu       sync.Mutex
	sessions map[string]int // sessionID → agent PID
	path     string
}

func newActiveTracker(agentjailDir string) *activeTracker {
	return &activeTracker{
		sessions: make(map[string]int),
		path:     filepath.Join(agentjailDir, "active-sessions.json"),
	}
}

// update records or refreshes the PID for a session.
func (t *activeTracker) update(sessionID string, pid int) {
	if sessionID == "" || pid <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID] = pid
	t.flush()
}

// list returns a snapshot of currently tracked sessions.
func (t *activeTracker) list() []activeEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]activeEntry, 0, len(t.sessions))
	for sid, pid := range t.sessions {
		out = append(out, activeEntry{SessionID: sid, PID: pid})
	}
	return out
}

// flush writes the current session→PID map to disk. Caller must hold t.mu.
func (t *activeTracker) flush() {
	entries := make([]activeEntry, 0, len(t.sessions))
	for sid, pid := range t.sessions {
		entries = append(entries, activeEntry{SessionID: sid, PID: pid})
	}
	data, _ := json.Marshal(entries)

	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, t.path)
}

// cleanup removes the status file on daemon shutdown.
func (t *activeTracker) cleanup() {
	_ = os.Remove(t.path)
}
