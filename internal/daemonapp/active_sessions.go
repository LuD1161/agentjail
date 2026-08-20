package daemonapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	PID                 int    `json:"pid"`
	CWD                 string `json:"cwd"`
	Root                string `json:"-"`
	Path                string `json:"-"`
	LaunchPID           int    `json:"-"`
	ConnectorCapability string `json:"-"`
	NetproxySessionID   string `json:"-"`
}

type launchState struct {
	Root                string
	Path                string
	StartMarker         procutil.StartMarker
	ConnectorCapability string
	NetproxySessionID   string
}

// activeTracker maintains a map of session IDs to their agent PIDs and CWDs.
// On every update it atomically rewrites ~/.agentjail/active-sessions.json
// so the CLI can read it and check if the PID is still alive.
type activeTracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionState // sessionID → agent PID/CWD
	launches map[int]launchState
	path     string
}

func newActiveTracker(agentjailDir string) *activeTracker {
	return &activeTracker{
		sessions: make(map[string]*sessionState),
		launches: make(map[int]launchState),
		path:     filepath.Join(agentjailDir, "active-sessions.json"),
	}
}

func (t *activeTracker) registerLaunch(pid int, root, pathValue, connectorCapability, netproxySessionID string) bool {
	root = filepath.Clean(root)
	if pid <= 1 || !filepath.IsAbs(root) || pathValue == "" {
		return false
	}
	startMarker, err := procutil.ReadProcessStartMarker(pid)
	if err != nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for existingPID := range t.launches {
		if !procutil.Alive(existingPID) {
			delete(t.launches, existingPID)
		}
	}
	if (connectorCapability == "") != (netproxySessionID == "") {
		return false
	}
	t.launches[pid] = launchState{Root: root, Path: pathValue, StartMarker: startMarker, ConnectorCapability: connectorCapability, NetproxySessionID: netproxySessionID}
	return true
}

func (t *activeTracker) unregisterLaunch(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.launches[pid]; !ok {
		return false
	}
	delete(t.launches, pid)
	for sessionID, state := range t.sessions {
		if state.LaunchPID == pid {
			delete(t.sessions, sessionID)
		}
	}
	t.flush()
	return true
}

// bindVerified associates a hook session only with an agent descended from an
// authenticated shield launch. Claimed cwd is accepted only beneath that root.
func (t *activeTracker) bindVerified(sessionID string, agentPID int, cwd string) bool {
	if sessionID == "" || agentPID <= 1 {
		return false
	}
	t.mu.Lock()
	launches := make(map[int]launchState, len(t.launches))
	for pid, launch := range t.launches {
		launches[pid] = launch
	}
	t.mu.Unlock()
	launchPID, ok := procutil.FindAncestorPID(agentPID, func(pid int) bool {
		_, exists := launches[pid]
		return exists
	})
	if !ok {
		return false
	}
	launch := launches[launchPID]
	currentStart, err := procutil.ReadProcessStartMarker(launchPID)
	if err != nil || currentStart != launch.StartMarker {
		return false
	}
	canonicalCWD := filepath.Clean(cwd)
	if canonicalCWD != launch.Root && !strings.HasPrefix(canonicalCWD, launch.Root+string(filepath.Separator)) {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.launches[launchPID]; !exists {
		return false
	}
	t.sessions[sessionID] = &sessionState{PID: agentPID, CWD: canonicalCWD, Root: launch.Root, Path: launch.Path, LaunchPID: launchPID, ConnectorCapability: launch.ConnectorCapability, NetproxySessionID: launch.NetproxySessionID}
	t.flush()
	return true
}

func (t *activeTracker) connectorCapability(sessionID string) (string, string, bool) {
	state, ok := t.metadata(sessionID)
	return state.ConnectorCapability, state.NetproxySessionID, ok && state.ConnectorCapability != "" && state.NetproxySessionID != ""
}

func (t *activeTracker) sessionsForLaunch(pid int) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ids []string
	for id, state := range t.sessions {
		if state.LaunchPID == pid {
			ids = append(ids, id)
		}
	}
	return ids
}

func (t *activeTracker) metadata(sessionID string) (sessionState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.sessions[sessionID]
	if !ok || state.Root == "" || state.Path == "" {
		return sessionState{}, false
	}
	return *state, true
}

// update records or refreshes the PID and CWD for a session.
func (t *activeTracker) update(sessionID string, pid int, cwd string) {
	if sessionID == "" || pid <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing := t.sessions[sessionID]; existing != nil && existing.Root != "" {
		// Authenticated launch bindings are refreshed only by bindVerified.
		// See ADR 0134-host-proxy-mvp.
		return
	}
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
