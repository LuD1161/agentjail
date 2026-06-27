package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// activeTracker maintains a refcounted set of session IDs that have at least
// one open daemon socket connection. On every change it atomically rewrites
// ~/.agentjail/active-sessions.json so the CLI and macOS app can read it
// without querying the daemon over the socket.
type activeTracker struct {
	mu       sync.Mutex
	sessions map[string]int // sessionID → connection count
	path     string         // path to active-sessions.json
}

func newActiveTracker(agentjailDir string) *activeTracker {
	return &activeTracker{
		sessions: make(map[string]int),
		path:     filepath.Join(agentjailDir, "active-sessions.json"),
	}
}

// register marks a session as having an active connection. Call once per
// connection when the first request reveals the session ID.
func (t *activeTracker) register(sessionID string) {
	if sessionID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID]++
	t.flush()
}

// unregister decrements the refcount for a session. When it reaches zero
// the session is removed from the active set.
func (t *activeTracker) unregister(sessionID string) {
	if sessionID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID]--
	if t.sessions[sessionID] <= 0 {
		delete(t.sessions, sessionID)
	}
	t.flush()
}

// list returns a snapshot of currently active session IDs.
func (t *activeTracker) list() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.sessions))
	for sid := range t.sessions {
		out = append(out, sid)
	}
	return out
}

// flush writes the current active set to disk. Caller must hold t.mu.
func (t *activeTracker) flush() {
	ids := make([]string, 0, len(t.sessions))
	for sid := range t.sessions {
		ids = append(ids, sid)
	}
	data, _ := json.Marshal(ids)

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
