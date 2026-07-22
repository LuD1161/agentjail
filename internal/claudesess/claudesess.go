// Package claudesess reads Claude Code's per-process session metadata
// (~/.claude/sessions/<pid>.json). It is the bridge between agentjail's two
// session identities: the shield's capture session (minted before claude
// exists) and the Claude session id the daemon's decisions are keyed on
// (AGE-111). The shield resolves its descendant's session id through this
// package and stamps it into the network store, so one coding session has
// one identifier everywhere.
package claudesess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/LuD1161/agentjail/internal/procutil"
)

// Meta mirrors one ~/.claude/sessions/<pid>.json file: the live claude
// process, its session id, launch directory, and user-assigned name.
type Meta struct {
	PID       int    `json:"pid"`
	SessionID string `json:"sessionId"`
	CWD       string `json:"cwd"`
	Name      string `json:"name"`
}

// Load scans the sessions directory. Best-effort: unreadable or malformed
// entries are skipped, a missing directory returns nil. One small JSON file
// per claude process, so callers can re-scan freely.
func Load() []Meta {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".claude", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Meta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m Meta
		if json.Unmarshal(b, &m) != nil || m.PID <= 0 {
			continue
		}
		out = append(out, m)
	}
	return out
}

// DescendantOf returns the live claude session whose process descends from
// ancestorPID. This is how the shield finds "its" claude: the agent is
// spawned as the shield's child, so the shield pid sits in the claude
// process's ancestry.
func DescendantOf(metas []Meta, ancestorPID int) (Meta, bool) {
	if ancestorPID <= 0 {
		return Meta{}, false
	}
	for _, m := range metas {
		if !procutil.Alive(m.PID) {
			continue
		}
		if _, ok := procutil.FindAncestorPID(m.PID, func(pid int) bool { return pid == ancestorPID }); ok {
			return m, true
		}
	}
	return Meta{}, false
}

// BySessionID indexes metas by Claude session id — the identity the daemon
// decision store keys sessions on.
func BySessionID(metas []Meta) map[string]Meta {
	out := make(map[string]Meta, len(metas))
	for _, m := range metas {
		if m.SessionID != "" {
			out[m.SessionID] = m
		}
	}
	return out
}
