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
	"golang.org/x/term"
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
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	basic := fs.Bool("basic", false, "plain text output (no TUI)")
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
	useColor := !*noColor && term.IsTerminal(int(os.Stdout.Fd()))
	if *list {
		return replayListSessions(ctx, st, useColor)
	}

	// Resolve session prefix to full ID.
	fullID, err := resolveSessionPrefix(ctx, st, *sessionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail replay: %v\n", err)
		return 1
	}

	// Load all decisions (paginated).
	allRows, err := loadAllDecisions(ctx, st, fullID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail replay: load decisions: %v\n", err)
		return 1
	}

	// Mode selection.
	isDumb := os.Getenv("TERM") == "dumb"
	fd := int(os.Stdout.Fd())
	isTTY := term.IsTerminal(fd)
	_, termRows, _ := term.GetSize(fd)
	tooSmall := termRows < 10

	if *basic || isDumb || !isTTY || tooSmall {
		return replayBasic(ctx, st, fullID, allRows, *verbose, *follow, useColor)
	}

	// TUI mode -- wired when replay_tui.go is present
	return replayBasic(ctx, st, fullID, allRows, *verbose, *follow, useColor)
}

func replayListSessions(ctx context.Context, st store.ReadOnlyStore, useColor bool) int {
	sessions, err := st.ListSessions(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail replay: list sessions: %v\n", err)
		return 1
	}
	if useColor {
		fmt.Printf("%s%s%-8s  %-19s  %-19s  %-8s  %-10s  %s%s\n",
			ansiBold, ansiDim,
			"SESSION", "START", "END", "COUNT", "AGENT", "CWD",
			ansiReset)
		fmt.Printf("%s%s%s\n", ansiDim, strings.Repeat("─", 100), ansiReset)
	} else {
		fmt.Printf("%-8s  %-19s  %-19s  %-8s  %-10s  %s\n", "SESSION", "START", "END", "COUNT", "AGENT", "CWD")
	}
	for _, s := range sessions {
		end := ""
		if !s.EndTs.IsZero() {
			end = s.EndTs.Local().Format("2006-01-02 15:04:05")
		}
		if useColor {
			u8 := detectLogsUTF8()
			glyph := agentGlyphFor(s.Agent, u8)
			info, ok := agentRegistry[s.Agent]
			glyphColor := ansiDim
			if ok && info.Color != "" {
				glyphColor = info.Color
			}
			fmt.Printf("%-8s  %s%-19s%s  %s%-19s%s  %-8d  %s%s%s %s%-10s%s  %s%s%s\n",
				shortSession(s.SessionID),
				ansiDim, s.StartTs.Local().Format("2006-01-02 15:04:05"), ansiReset,
				ansiDim, end, ansiReset,
				s.DecisionCount,
				glyphColor, glyph, ansiReset, ansiBold, s.Agent, ansiReset,
				ansiDim, s.CWD, ansiReset)
		} else {
			glyph := agentGlyphFor(s.Agent, detectLogsUTF8())
			fmt.Printf("%-8s  %-19s  %-19s  %-8d  %s %-10s  %s\n",
				shortSession(s.SessionID), s.StartTs.Local().Format("2006-01-02 15:04:05"), end, s.DecisionCount, glyph, s.Agent, s.CWD)
		}
	}
	return 0
}

// replayBasic prints pre-loaded decisions and optionally follows for new ones.
func replayBasic(ctx context.Context, st store.ReadOnlyStore, sessionID string, rows []store.DecisionRecord, verbose, follow, useColor bool) int {
	if useColor {
		fmt.Printf("%s%s%-8s    %-7s  %-18s  %-30s  %s%s\n",
			ansiBold, ansiDim,
			"TIME", "ACTION", "TOOL", "RULE", "SUMMARY",
			ansiReset)
		fmt.Printf("%s%s%s\n", ansiDim, strings.Repeat("─", 100), ansiReset)
	} else {
		fmt.Printf("%-8s    %-7s  %-18s  %-30s  %s\n", "TIME", "ACTION", "TOOL", "RULE", "SUMMARY")
		fmt.Println(strings.Repeat("-", 100))
	}
	var total, allow, deny, ask int
	for _, d := range rows {
		printReplayDecision(d, verbose, useColor)
		total++
		switch strings.ToLower(d.Action) {
		case "allow":
			allow++
		case "deny":
			deny++
		case "ask":
			ask++
		}
	}
	if !follow {
		printReplaySummary(total, allow, deny, ask, useColor)
		return 0
	}
	lastID := int64(0)
	if len(rows) > 0 {
		lastID = rows[len(rows)-1].ID
	}
	for {
		newRows, err := st.ListDecisions(ctx, store.Filter{SessionID: sessionID, AfterID: lastID, Limit: 1000})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail replay: query: %v\n", err)
			return 1
		}
		for _, d := range newRows {
			if d.ID > lastID {
				lastID = d.ID
			}
			printReplayDecision(d, verbose, useColor)
			total++
			switch strings.ToLower(d.Action) {
			case "allow":
				allow++
			case "deny":
				deny++
			case "ask":
				ask++
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func printReplaySummary(total, allow, deny, ask int, useColor bool) {
	if useColor {
		fmt.Printf("\n%s%s%s\n", ansiDim, strings.Repeat("─", 100), ansiReset)
		fmt.Printf("%s%d%s events  %s%d%s allow  %s%d%s deny  %s%d%s ask\n",
			ansiBold, total, ansiReset,
			ansiGreen, allow, ansiReset,
			ansiRedBold, deny, ansiReset,
			ansiYellow, ask, ansiReset)
	} else {
		fmt.Println()
		fmt.Println(strings.Repeat("-", 100))
		fmt.Printf("%d events  %d allow  %d deny  %d ask\n", total, allow, deny, ask)
	}
}

func printReplayDecision(d store.DecisionRecord, verbose, useColor bool) {
	action := strings.ToUpper(d.Action)
	tool := d.ToolName
	if tool == "" {
		tool = "-"
	}
	rule := d.RuleID
	if rule == "" {
		rule = "-"
	}
	summary := d.Summary
	glyph := agentGlyphFor(d.Agent, detectLogsUTF8())
	isDeny := strings.ToLower(d.Action) == "deny"
	isAsk := strings.ToLower(d.Action) == "ask"

	if useColor {
		info, ok := agentRegistry[d.Agent]
		glyphColor := ansiDim
		if ok && info.Color != "" {
			glyphColor = info.Color
		}
		actionColor := actionANSI(d.Action)
		fmt.Printf("%s  %s%s%s %s%-7s%s  %-18s  %s%-30s%s  %s\n",
			d.Ts.Local().Format("15:04:05"),
			glyphColor, glyph, ansiReset,
			actionColor, action, ansiReset,
			tool,
			ansiDim, rule, ansiReset,
			summary)
		if (isDeny || isAsk) && d.Reason != "" {
			fmt.Printf("            %sreason: %s%s\n", ansiDim, d.Reason, ansiReset)
		}
	} else {
		fmt.Printf("%-8s  %s %-7s  %-18s  %-30s  %s\n",
			d.Ts.Local().Format("15:04:05"), glyph, action, tool, rule, summary)
		if (isDeny || isAsk) && d.Reason != "" {
			fmt.Printf("            reason: %s\n", d.Reason)
		}
	}
	if verbose && d.ToolInputRedacted != "" {
		if useColor {
			fmt.Printf("            %stool_input: %s%s\n", ansiDim, d.ToolInputRedacted, ansiReset)
		} else {
			fmt.Printf("            tool_input: %s\n", d.ToolInputRedacted)
		}
	}
}

func shortSession(sessionID string) string {
	if len(sessionID) <= 8 {
		return sessionID
	}
	return sessionID[:8]
}

func resolveSessionPrefix(ctx context.Context, st store.ReadOnlyStore, prefix string) (string, error) {
	sessions, err := st.ListSessions(ctx)
	if err != nil {
		return "", fmt.Errorf("list sessions: %w", err)
	}
	for _, s := range sessions {
		if s.SessionID == prefix {
			return s.SessionID, nil
		}
	}
	var matches []store.Session
	for _, s := range sessions {
		if strings.HasPrefix(s.SessionID, prefix) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no session matching '%s'", prefix)
	case 1:
		return matches[0].SessionID, nil
	default:
		var ids []string
		for _, m := range matches {
			ids = append(ids, shortSession(m.SessionID))
		}
		return "", fmt.Errorf("ambiguous prefix '%s' matches %d sessions: %s", prefix, len(matches), strings.Join(ids, ", "))
	}
}

func loadAllDecisions(ctx context.Context, st store.ReadOnlyStore, sessionID string) ([]store.DecisionRecord, error) {
	var all []store.DecisionRecord
	afterID := int64(0)
	for {
		page, err := st.ListDecisions(ctx, store.Filter{
			SessionID: sessionID,
			AfterID:   afterID,
			Limit:     1000,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < 1000 {
			break
		}
		afterID = page[len(page)-1].ID
	}
	return all, nil
}
