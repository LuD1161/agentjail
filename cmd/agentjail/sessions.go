package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/internal/procutil"
	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/ui"
)

// activeSessionsPath returns the path to the daemon's active sessions file.
func activeSessionsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agentjail", "active-sessions.json")
}

type activeEntry struct {
	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
}

// loadActiveSessions reads the daemon's active-sessions.json, checks which
// PIDs are still alive, and returns the set of truly active session IDs.
func loadActiveSessions() map[string]bool {
	return loadActiveSessionsFromPath(activeSessionsPath())
}

func loadActiveSessionsFromPath(path string) map[string]bool {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []activeEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	m := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.PID > 0 && isProcessAlive(e.PID) {
			m[e.SessionID] = true
		}
	}
	return m
}

// isProcessAlive checks if a process with the given PID exists. The liveness
// check is shared with the network UI via procutil.Alive so the two paths
// cannot drift.
func isProcessAlive(pid int) bool {
	return procutil.Alive(pid)
}

type sessionOutput struct {
	SessionID     string `json:"session_id"`
	Name          string `json:"name,omitempty"`
	Agent         string `json:"agent,omitempty"`
	CWD           string `json:"cwd,omitempty"`
	StartTs       string `json:"start_ts"`
	EndTs         string `json:"end_ts,omitempty"`
	DecisionCount int    `json:"decision_count"`
	Active        bool   `json:"active"`
}

// loadSessionNames scans ~/.claude/sessions/*.json and returns a map from
// session ID prefix (first 8 hex chars) to the user-assigned session name.
func loadSessionNames() map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	pattern := filepath.Join(home, ".claude", "sessions", "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return nil
	}
	m := make(map[string]string, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var meta struct {
			SessionID string `json:"sessionId"`
			Name      string `json:"name"`
		}
		if json.Unmarshal(data, &meta) != nil || meta.SessionID == "" || meta.Name == "" {
			continue
		}
		prefix := meta.SessionID
		if len(prefix) >= 8 {
			prefix = prefix[:8]
		}
		m[prefix] = meta.Name
	}
	return m
}

func runSessions(args []string) int {
	if len(args) > 0 && args[0] == "list" {
		args = args[1:]
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		sessionsUsage()
		return 0
	}
	return runSessionsList(args)
}

func sessionsUsage() {
	fmt.Fprintln(os.Stderr, "usage: agentjail sessions [--active] [--json] [--no-color] [--since DURATION]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  --active     show only sessions with an active daemon connection")
	fmt.Fprintln(os.Stderr, "  --json       output as JSON array")
	fmt.Fprintln(os.Stderr, "  --no-color   disable color output")
	fmt.Fprintln(os.Stderr, "  --since      only sessions active within this duration (e.g. 1h, 7d, 30m)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  agentjail sessions")
	fmt.Fprintln(os.Stderr, "  agentjail sessions --active --json")
	fmt.Fprintln(os.Stderr, "  agentjail sessions --since 7d")
}

func runSessionsList(args []string) int {
	fs := flag.NewFlagSet("sessions list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	home, _ := os.UserHomeDir()
	dbPath := fs.String("db", filepath.Join(home, ".agentjail", "agentjail.db"), "path to SQLite event store")
	active := fs.Bool("active", false, "show only active sessions")
	jsonOut := fs.Bool("json", false, "output as JSON")
	since := fs.String("since", "24h", "time range (e.g. 1h, 7d, 30m); 0 for all time")
	noColor := fs.Bool("no-color", false, "disable color output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *noColor {
		restore := ui.DisableColor()
		defer restore()
	}

	sinceDur, err := parseDuration(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail sessions: invalid --since %q: %v\n", *since, err)
		return 2
	}

	st, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail sessions: open %s: %v\n", *dbPath, err)
		return 1
	}
	defer st.Close()

	ctx := context.Background()
	sessions, err := st.ListSessionsFiltered(ctx, store.SessionFilter{Since: sinceDur})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail sessions: %v\n", err)
		return 1
	}

	activeSet := loadActiveSessions()
	nameMap := loadSessionNames()

	var output []sessionOutput
	for _, s := range sessions {
		isActive := activeSet[s.SessionID]
		if *active && !isActive {
			continue
		}
		endStr := ""
		if !s.EndTs.IsZero() {
			endStr = s.EndTs.UTC().Format(time.RFC3339)
		}
		output = append(output, sessionOutput{
			SessionID:     s.SessionID,
			Name:          nameMap[shortSession(s.SessionID)],
			Agent:         s.Agent,
			CWD:           s.CWD,
			StartTs:       s.StartTs.UTC().Format(time.RFC3339),
			EndTs:         endStr,
			DecisionCount: s.DecisionCount,
			Active:        isActive,
		})
	}

	if *jsonOut {
		if output == nil {
			output = []sessionOutput{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(output)
		return 0
	}

	if len(output) == 0 {
		fmt.Println("No sessions found.")
		return 0
	}

	renderSessions(os.Stdout, output, ui.New(os.Stdout))
	return 0
}

func renderSessions(w io.Writer, sessions []sessionOutput, u *ui.UI) {
	header := fmt.Sprintf("%-22s  %-16s  %-6s  %-19s  %-19s  %-8s  %-10s  %s",
		"SESSION", "NAME", "ACTIVE", "START", "END", "COUNT", "AGENT", "CWD")
	fmt.Fprintln(w, u.Text(ui.ToneMuted, header))
	for _, s := range sessions {
		activeStr := " "
		if s.Active {
			activeStr = "*"
		}
		end := s.EndTs
		if end == "" {
			end = "-"
		} else if t, err := time.Parse(time.RFC3339, end); err == nil {
			end = t.Local().Format("2006-01-02 15:04:05")
		}
		start := s.StartTs
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			start = t.Local().Format("2006-01-02 15:04:05")
		}
		name := s.Name
		if len(name) > 16 {
			name = name[:15] + "…"
		}
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s  %s\n",
			u.Text(ui.ToneAccent, fmt.Sprintf("%-22s", shortSession(s.SessionID))),
			u.Text(ui.ToneAccent, fmt.Sprintf("%-16s", name)),
			u.Text(ui.ToneSuccess, fmt.Sprintf("%-6s", activeStr)),
			u.Text(ui.ToneMuted, fmt.Sprintf("%-19s", start)),
			u.Text(ui.ToneMuted, fmt.Sprintf("%-19s", end)),
			u.Text(ui.ToneAccent, fmt.Sprintf("%-8d", s.DecisionCount)),
			u.Text(ui.ToneWarning, fmt.Sprintf("%-10s", s.Agent)),
			u.Text(ui.ToneMuted, s.CWD))
	}
}

// parseDuration extends time.ParseDuration with support for "d" (days) suffix.
func parseDuration(s string) (time.Duration, error) {
	if s == "0" || s == "" {
		return 0, nil
	}
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var n int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err == nil {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
