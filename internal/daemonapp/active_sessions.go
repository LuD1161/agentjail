package daemonapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/LuD1161/agentjail/internal/procutil"
)

// activeEntry is one entry in the active-sessions.json file.
type activeEntry struct {
	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
	CWD       string `json:"cwd"`
}

// sessionState is the in-memory record kept for each tracked session.
type sessionState struct {
	PID int    `json:"pid"`
	CWD string `json:"cwd"`
}

// activeTracker maintains a map of session IDs to their agent PIDs and CWDs.
// On every update it atomically rewrites ~/.agentjail/active-sessions.json
// so the CLI can read it and check if the PID is still alive.
type activeTracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionState // sessionID → agent PID/CWD
	path     string
}

func newActiveTracker(agentjailDir string) *activeTracker {
	return &activeTracker{
		sessions: make(map[string]*sessionState),
		path:     filepath.Join(agentjailDir, "active-sessions.json"),
	}
}

// update records or refreshes the PID and CWD for a session.
func (t *activeTracker) update(sessionID string, pid int, cwd string) {
	if sessionID == "" || pid <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID] = &sessionState{PID: pid, CWD: cwd}
	t.flush()
}

// list returns a snapshot of currently tracked sessions.
func (t *activeTracker) list() []activeEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]activeEntry, 0, len(t.sessions))
	for sid, state := range t.sessions {
		out = append(out, activeEntry{SessionID: sid, PID: state.PID, CWD: state.CWD})
	}
	return out
}

// isActive reports whether sessionID is currently tracked.
func (t *activeTracker) isActive(sessionID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.sessions[sessionID]
	return ok
}

// findSessionByPID walks the process tree from startPID upward, looking for
// a PID that matches any tracked session's agent PID. Returns the session ID
// and daemon-observed CWD if found. Uses procutil.FindAncestorPID with a
// 20-level limit.
func (t *activeTracker) findSessionByPID(startPID int) (sessionID, cwd string, ok bool) {
	t.mu.Lock()
	// Build a set of tracked PIDs -> sessionID for the matcher
	pidToSession := make(map[int]string, len(t.sessions))
	for sid, state := range t.sessions {
		pidToSession[state.PID] = sid
	}
	t.mu.Unlock()

	matchedPID, found := procutil.FindAncestorPID(startPID, func(pid int) bool {
		_, ok := pidToSession[pid]
		return ok
	})
	if !found {
		return "", "", false
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	sid := pidToSession[matchedPID]
	state, exists := t.sessions[sid]
	if !exists {
		return "", "", false
	}
	return sid, state.CWD, true
}

// flush writes the current session→PID/CWD map to disk. Caller must hold t.mu.
func (t *activeTracker) flush() {
	entries := make([]activeEntry, 0, len(t.sessions))
	for sid, state := range t.sessions {
		entries = append(entries, activeEntry{SessionID: sid, PID: state.PID, CWD: state.CWD})
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
