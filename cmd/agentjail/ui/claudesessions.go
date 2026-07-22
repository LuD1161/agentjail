package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/internal/procutil"
)

// claudeSessionMeta mirrors the ~/.claude/sessions/<pid>.json files Claude
// Code maintains per live process. They are the only place a user-assigned
// session name (/rename) exists, so the UI joins against them instead of
// showing directory basenames for sessions the user has already named.
type claudeSessionMeta struct {
	PID       int    `json:"pid"`
	SessionID string `json:"sessionId"`
	CWD       string `json:"cwd"`
	Name      string `json:"name"`
}

// loadClaudeSessionMeta scans ~/.claude/sessions. Best-effort: any unreadable
// or malformed entry is skipped, a missing directory returns nil. The dir
// holds one small JSON file per claude process, so a per-request scan is
// cheap.
func loadClaudeSessionMeta() []claudeSessionMeta {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(home, ".claude", "sessions"))
	if err != nil {
		return nil
	}
	var out []claudeSessionMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(home, ".claude", "sessions", e.Name()))
		if err != nil {
			continue
		}
		var m claudeSessionMeta
		if json.Unmarshal(b, &m) != nil || m.PID <= 0 {
			continue
		}
		out = append(out, m)
	}
	return out
}

// sessionNameByAncestor resolves a network session's name: the network store
// only knows the SHIELD pid (ADR 0100), and the claude process is its
// descendant, so walk each live claude pid's ancestry looking for ownerPID.
func sessionNameByAncestor(metas []claudeSessionMeta, ownerPID int) string {
	if ownerPID <= 0 {
		return ""
	}
	for _, m := range metas {
		if m.Name == "" || !procutil.Alive(m.PID) {
			continue
		}
		if _, ok := procutil.FindAncestorPID(m.PID, func(pid int) bool { return pid == ownerPID }); ok {
			return m.Name
		}
	}
	return ""
}

// claudeMetaBySessionID indexes metas by their Claude session id — the same
// identity the daemon's decision store keys sessions on, so the monitor
// sidebar joins directly.
func claudeMetaBySessionID(metas []claudeSessionMeta) map[string]claudeSessionMeta {
	out := make(map[string]claudeSessionMeta, len(metas))
	for _, m := range metas {
		if m.SessionID != "" {
			out[m.SessionID] = m
		}
	}
	return out
}
