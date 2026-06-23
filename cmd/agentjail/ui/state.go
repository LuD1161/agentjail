// ui/state.go — in-memory session + event ring buffer for the local web UI.
//
// This package is a LOCAL DEV TOOL only. It is NOT part of the v0.1.0-alpha
// release. It is intended for demo recordings and internal debugging.
package ui

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxEvents is the ring-buffer capacity. Oldest events are dropped when full.
const maxEvents = 500

// EvalLine mirrors cmd/agentjail/logs.go evalLine — duplicated here to keep
// the ui package self-contained (no cross-package import needed for a dev tool).
type EvalLine struct {
	Time              time.Time `json:"time"`
	Level             string    `json:"level"`
	Msg               string    `json:"msg"`
	ReqID             string    `json:"req_id,omitempty"`
	Tool              string    `json:"tool,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	Agent             string    `json:"agent,omitempty"`
	CWD               string    `json:"cwd,omitempty"`
	Summary           string    `json:"summary,omitempty"`
	Action            string    `json:"action,omitempty"`
	RuleID            string    `json:"rule_id,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	Impact            string    `json:"impact,omitempty"`
	ElapsedUs         int64     `json:"elapsed_us,omitempty"`
	ToolInputRedacted string    `json:"tool_input_redacted,omitempty"`
	Err               string    `json:"err,omitempty"`
}

// SessionState tracks per-session aggregated stats.
type SessionState struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent,omitempty"`
	CWD       string    `json:"cwd,omitempty"`
	Branch    string    `json:"branch,omitempty"`
	RepoName  string    `json:"repo_name,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Total     int       `json:"total"`
	Allow     int       `json:"allow"`
	Deny      int       `json:"deny"`
	Ask       int       `json:"ask"`
	LastEvent string    `json:"last_event,omitempty"` // ISO timestamp of most recent evaluation
}

// SourceStatus describes where the snapshot came from.
type SourceStatus struct {
	Kind       string    `json:"kind"` // "sqlite" | "log"
	Path       string    `json:"path"`
	LivePath   string    `json:"live_path,omitempty"`
	Fallback   bool      `json:"fallback"`
	Warning    string    `json:"warning,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

// StateSnapshot is the JSON shape returned by GET /api/state.
type StateSnapshot struct {
	Sessions       []*SessionState `json:"sessions"`
	RecentEvents   []EvalLine      `json:"recent_events"`
	TotalAllow     int             `json:"total_allow"`
	TotalDeny      int             `json:"total_deny"`
	TotalAsk       int             `json:"total_ask"`
	TotalDecisions int             `json:"total_decisions"`
	FilteredCount  int             `json:"filtered_count"`
	Source         SourceStatus    `json:"source"`
}

// Store is the thread-safe in-memory state for the UI server.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
	events   []EvalLine // ring buffer, capped at maxEvents
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*SessionState),
		events:   make([]EvalLine, 0, maxEvents),
	}
}

// Ingest parses one log line and updates state. Returns the parsed EvalLine
// and true if the line was an eval event worth broadcasting; false otherwise.
func (s *Store) Ingest(raw []byte) (EvalLine, bool) {
	var line EvalLine
	if err := json.Unmarshal(raw, &line); err != nil {
		return EvalLine{}, false
	}
	if line.Msg != "eval" {
		return EvalLine{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update session state.
	if line.SessionID != "" {
		sess, ok := s.sessions[line.SessionID]
		if !ok {
			sess = &SessionState{
				ID:        line.SessionID,
				FirstSeen: line.Time,
			}
			s.sessions[line.SessionID] = sess
		}
		sess.LastSeen = line.Time
		sess.Total++
		switch line.Action {
		case "allow":
			sess.Allow++
		case "deny":
			sess.Deny++
		case "ask":
			sess.Ask++
		}
		if line.Agent != "" {
			sess.Agent = line.Agent
		}
		if line.CWD != "" {
			sess.CWD = line.CWD
			if sess.Branch == "" {
				sess.Branch, sess.RepoName = gitInfo(line.CWD)
			}
		}
	}

	// Append to ring buffer — drop oldest when full.
	if len(s.events) >= maxEvents {
		copy(s.events, s.events[1:])
		s.events[maxEvents-1] = line
	} else {
		s.events = append(s.events, line)
	}

	return line, true
}

// Snapshot returns a point-in-time copy of all state.
func (s *Store) Snapshot() StateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := StateSnapshot{
		Sessions:     make([]*SessionState, 0, len(s.sessions)),
		RecentEvents: make([]EvalLine, len(s.events)),
	}
	copy(snap.RecentEvents, s.events)

	for _, sess := range s.sessions {
		cp := *sess
		snap.Sessions = append(snap.Sessions, &cp)
		snap.TotalAllow += sess.Allow
		snap.TotalDeny += sess.Deny
		snap.TotalAsk += sess.Ask
	}
	snap.TotalDecisions = snap.TotalAllow + snap.TotalDeny + snap.TotalAsk

	return snap
}

// gitInfo runs git to get the branch name and repo basename for a directory.
// Returns ("", "") on any failure — never blocks the ingest path.
func gitInfo(cwd string) (branch, repoName string) {
	b, err := exec.Command("git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return "", ""
	}
	branch = strings.TrimSpace(string(b))

	t, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return branch, ""
	}
	repoName = filepath.Base(strings.TrimSpace(string(t)))
	return branch, repoName
}
