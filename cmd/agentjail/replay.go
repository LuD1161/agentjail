package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	home, _ := os.UserHomeDir()
	dbPath := fs.String("db", filepath.Join(home, ".agentjail", "agentjail.db"), "path to SQLite event store")
	sessionID := fs.String("session", "", "session id to replay")
	verbose := fs.Bool("verbose", false, "include redacted tool_input")
	follow := fs.Bool("follow", false, "follow new decisions for the session")
	list := fs.Bool("list", false, "list sessions")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if !*list && strings.TrimSpace(*sessionID) == "" {
		fmt.Fprintln(os.Stderr, "agentjail replay: --session is required unless --list is set")
		return 2
	}
	st, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail replay: open %s: %v\n", *dbPath, err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	if *list {
		return replayListSessions(ctx, st)
	}
	return replaySession(ctx, st, *sessionID, *verbose, *follow)
}

func replayListSessions(ctx context.Context, st store.ReadOnlyStore) int {
	sessions, err := st.ListSessions(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail replay: list sessions: %v\n", err)
		return 1
	}
	fmt.Printf("%-8s  %-19s  %-19s  %-8s  %-10s  %s\n", "SESSION", "START", "END", "COUNT", "AGENT", "CWD")
	for _, s := range sessions {
		end := ""
		if !s.EndTs.IsZero() {
			end = s.EndTs.Local().Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-8s  %-19s  %-19s  %-8d  %-10s  %s\n",
			shortSession(s.SessionID), s.StartTs.Local().Format("2006-01-02 15:04:05"), end, s.DecisionCount, s.Agent, s.CWD)
	}
	return 0
}

func replaySession(ctx context.Context, st store.ReadOnlyStore, sessionID string, verbose, follow bool) int {
	fmt.Printf("%-8s  %-5s  %-18s  %-36s  %s\n", "TIME", "ACT", "TOOL", "RULE", "SUMMARY")
	lastID := int64(0)
	for {
		rows, err := st.ListDecisions(ctx, store.Filter{SessionID: sessionID, AfterID: lastID, Limit: 1000})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail replay: query session %s: %v\n", sessionID, err)
			return 1
		}
		for _, d := range rows {
			if d.ID > lastID {
				lastID = d.ID
			}
			printReplayDecision(d, verbose)
		}
		if !follow {
			return 0
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func printReplayDecision(d store.DecisionRecord, verbose bool) {
	fmt.Printf("%-8s  %-5s  %-18s  %-36s  %s\n",
		d.Ts.Local().Format("15:04:05"), strings.ToUpper(d.Action), d.ToolName, d.RuleID, d.Summary)
	if d.Reason != "" {
		fmt.Printf("          reason: %s\n", d.Reason)
	}
	if verbose && d.ToolInputRedacted != "" {
		fmt.Printf("          tool_input: %s\n", d.ToolInputRedacted)
	}
}

func shortSession(sessionID string) string {
	if len(sessionID) <= 8 {
		return sessionID
	}
	return sessionID[:8]
}
