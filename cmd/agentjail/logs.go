// logs.go — agentjail logs subcommand.
//
// Pretty-prints the daemon evaluation log (~/.agentjail/daemon.log) with
// color-coded action columns, optional follow mode, and action/tool/since
// filters. No new dependencies — stdlib + golang.org/x/term (already in go.mod).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// evalLine is the JSON shape emitted by the daemon for every tool-call
// evaluation. Fields match what cmd/agentjail-daemon/main.go writes via
// log/slog's JSON handler.
type evalLine struct {
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Msg       string    `json:"msg"`
	ReqID     string    `json:"req_id,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	CWD       string    `json:"cwd,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Action    string    `json:"action,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Impact    string    `json:"impact,omitempty"` // policy-declared consequence text; overrides builtinImpact when non-empty
	ElapsedUs int64     `json:"elapsed_us,omitempty"`
	Err       string    `json:"err,omitempty"`
}

// ─── agent normalization registry ────────────────────────────────────────────

// agentInfo describes how a logged agent string should be displayed.
// Glyph is the UTF-8 geometric symbol shown in the SOURCE column when the
// terminal supports UTF-8; ASCIIGlyph is the single-byte fallback.  Color is
// an ANSI color escape for the glyph; empty means no per-agent color (uses
// whatever the surrounding context already applies, e.g. ansiDim for try).
type agentInfo struct {
	Display    string // canonical human-readable name shown in the SOURCE column
	Glyph      string // UTF-8 geometric glyph (1 visible column)
	ASCIIGlyph string // ASCII fallback glyph (1 visible column)
	Color      string // ANSI color escape for the glyph; "" = no extra color
}

// agentRegistry maps the raw agent strings written by the daemon to their
// display names. Lookup is case-sensitive; the daemon writes lower-case keys.
// Unknown agents fall back to the "unknown" entry.
var agentRegistry = map[string]agentInfo{
	"claude":      {Display: "Claude",  Glyph: "✳", ASCIIGlyph: "*", Color: ansiColorClaude},
	"claude-code": {Display: "Claude",  Glyph: "✳", ASCIIGlyph: "*", Color: ansiColorClaude},
	"cursor":      {Display: "Cursor",  Glyph: "▸", ASCIIGlyph: ">", Color: ansiColorCursor},
	"codex":       {Display: "Codex",   Glyph: "◆", ASCIIGlyph: "#", Color: ansiColorCodex},
	// try rows: rendered dimmed; the glyph uses a plain asterisk (dim context).
	"try":         {Display: "try",     Glyph: "*", ASCIIGlyph: "*", Color: ansiColorTry},
	// unknown: neutral mid-dot; no distinct color — rendered with ansiDim.
	"unknown":     {Display: "unknown", Glyph: "·", ASCIIGlyph: ".", Color: ""},
}

// agentDisplay returns the canonical display name for the given raw agent
// string. Empty or unrecognized values return "unknown".
func agentDisplay(agent string) string {
	if info, ok := agentRegistry[agent]; ok {
		return info.Display
	}
	return "unknown"
}

// ─── UTF-8 / glyph capability detection ──────────────────────────────────────

// logsEnvLookup is the environment-variable lookup used by detectLogsUTF8.
// Tests replace this to inject arbitrary locale/TERM values without touching
// the real environment.
var logsEnvLookup func(string) string = os.Getenv

// detectLogsUTF8 returns true when the terminal can display UTF-8 glyphs.
// Logic mirrors internal/ui.detectGlyphs: UTF-8 if LC_ALL/LC_CTYPE/LANG
// contains "UTF-8" or "utf8" AND TERM != "dumb"; ASCII fallback otherwise.
// Replicated locally (not imported) to avoid coupling cmd/agentjail to the ui
// package — the ui package pulls in lipgloss/termenv which are not in this
// binary's dependency set.
func detectLogsUTF8() bool {
	if logsEnvLookup("TERM") == "dumb" {
		return false
	}
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		val := logsEnvLookup(key)
		if strings.Contains(val, "UTF-8") || strings.Contains(val, "utf8") {
			return true
		}
	}
	return false
}

// agentGlyphFor returns the appropriate single-column glyph string for the
// given agent, considering the terminal's UTF-8 capability.
func agentGlyphFor(agent string, useUTF8 bool) string {
	info, ok := agentRegistry[agent]
	if !ok {
		info = agentRegistry["unknown"]
	}
	if useUTF8 {
		return info.Glyph
	}
	return info.ASCIIGlyph
}

// agentColorFor returns the ANSI color escape for the glyph of the given
// agent. Returns "" for unknown (caller applies ansiDim instead).
func agentColorFor(agent string) string {
	if info, ok := agentRegistry[agent]; ok {
		return info.Color
	}
	return ""
}

// ─── SOURCE cell helpers ──────────────────────────────────────────────────────

// sourceWidth is the fixed column width for the SOURCE column in both the
// plain and rich views. Wide enough to show "Codex · a1b2c3 · ~/repo/api" in
// full and to keep a recognizable tail of longer repo paths after truncation.
// Consistent across header / separator / data rows.
const sourceWidth = 36

// cwdShort home-relativizes cwd ($HOME → "~") then keeps the last two
// non-empty path segments so long repo paths stay bounded.
// Returns "" when cwd is empty.
func cwdShort(cwd string) string {
	if cwd == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(cwd, home) {
		cwd = "~" + cwd[len(home):]
	}
	// Split and filter out empty elements (from leading/trailing slashes).
	raw := strings.Split(strings.TrimRight(cwd, "/"), "/")
	var parts []string
	for _, p := range raw {
		if p != "" {
			parts = append(parts, p)
		}
	}
	// If the path started with "/" (not "~"), re-add the root indicator so the
	// result makes sense when only 1-2 segments remain (e.g. "/tmp" → "/tmp").
	// For "~"-prefixed paths the first part already carries "~".
	if len(parts) > 2 {
		last2 := parts[len(parts)-2:]
		cwd = "…/" + strings.Join(last2, "/")
	} else if strings.HasPrefix(cwd, "/") && len(parts) > 0 {
		// Reconstruct with leading slash (e.g. "/a/b").
		cwd = "/" + strings.Join(parts, "/")
	} else if strings.HasPrefix(cwd, "~") {
		// Reconstruct with ~ prefix.
		cwd = "~/" + strings.Join(parts[1:], "/")
		if len(parts) == 1 {
			cwd = "~"
		}
	}
	return cwd
}

// isTryRow reports whether the row originated from `agentjail try`.
func isTryRow(agent, sessionID string) bool {
	return agent == "try" || sessionID == "agentjail-try"
}

// sourceCell returns the formatted SOURCE cell string (plain, no ANSI) for
// the given agent, session_id, and cwd. The caller is responsible for
// applying dim styling to try rows.
// Format: "<Display> · <short-session> · <cwd>" or "try (manual)" for try rows.
// The returned string is NOT padded — callers use fmt.Sprintf("%-*s", sourceWidth, ...).
func sourceCell(agent, sessionID, cwd string) string {
	if isTryRow(agent, sessionID) {
		return "try (manual)"
	}
	display := agentDisplay(agent)
	var parts []string
	parts = append(parts, display)
	if len(sessionID) >= 6 {
		parts = append(parts, sessionID[:6])
	} else if sessionID != "" {
		parts = append(parts, sessionID)
	}
	short := cwdShort(cwd)
	if short != "" {
		parts = append(parts, short)
	}
	return strings.Join(parts, " · ")
}

// logsOpts holds parsed options for the logs subcommand.
type logsOpts struct {
	logPath  string        // path to daemon.log
	follow   bool          // tail -f mode
	actions  []string      // filter by action (empty = all)
	tool     string        // filter by tool (empty = all)
	since    time.Duration // filter lines newer than this duration (0 = no filter)
	raw      bool          // pass-through raw JSON lines
	all      bool          // include non-eval INFO lines
	noColor  bool          // force no ANSI escapes
	useColor bool          // computed from noColor + isatty
	verbose  bool          // -v: show command/file_path + reason + session_id
	session  string        // filter by session_id substring
	basic    bool          // --basic: disable rich mode (scrolling region + status bar)
}

// ANSI escape sequences. We keep them as bare strings — no external dep.
const (
	ansiReset    = "\033[0m"
	ansiGreen    = "\033[32m"
	ansiYellow   = "\033[33m"
	ansiRedBold  = "\033[31;1m"
	ansiDim      = "\033[2m"
	ansiRed      = "\033[31m"
	ansiBold     = "\033[1m"

	// Per-agent brand colors (256-color ANSI; readable on dark terminals).
	// Claude  — orange-amber  (#d97706 → xterm-256 214)
	// Codex   — electric blue (#3b82f6 → xterm-256 75)
	// Cursor  — teal-green    (#10b981 → xterm-256 35)
	// try     — neutral white (bright)
	// unknown — dim grey (uses ansiDim, no extra constant needed)
	ansiColorClaude  = "\033[38;5;214m"
	ansiColorCodex   = "\033[38;5;75m"
	ansiColorCursor  = "\033[38;5;35m"
	ansiColorTry     = "\033[37m" // plain white; try rows are also dimmed
)

// runLogs is the entry point for `agentjail logs`. Returns an exit code.
func runLogs(args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	home, _ := os.UserHomeDir()
	defaultLog := filepath.Join(home, ".agentjail", "daemon.log")
	// Fallback for installs whose launchd plist still redirects the daemon to the
	// legacy /tmp path: if the canonical log is absent but the legacy one exists,
	// read that instead so `agentjail logs` works across mixed-version installs.
	if _, err := os.Stat(defaultLog); err != nil {
		const legacyLog = "/tmp/agentjail-daemon.log"
		if _, lerr := os.Stat(legacyLog); lerr == nil {
			defaultLog = legacyLog
		}
	}

	logPath := fs.String("log", defaultLog, "path to daemon log")
	noFollow := fs.Bool("no-follow", false, "print existing lines and exit (no tail)")
	actionStr := fs.String("action", "", "filter by action(s), comma-separated (allow,ask,deny)")
	tool := fs.String("tool", "", "filter by exact tool name")
	sinceStr := fs.String("since", "", "only lines newer than duration (e.g. 10m, 2h)")
	raw := fs.Bool("json", false, "pass-through raw daemon log lines")
	all := fs.Bool("all", false, "include non-eval INFO lines (startup, reload, etc.)")
	noColor := fs.Bool("no-color", false, "disable ANSI color output")
	verbose := fs.Bool("v", false, "verbose: show the command/file_path, reason, and session_id")
	sessionStr := fs.String("session", "", "filter by session_id substring match")
	basicMode := fs.Bool("basic", false, "disable rich TUI mode (no status bar, no IMPACT column); useful for piping or CI")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	// Parse --since duration.
	var sinceDur time.Duration
	if *sinceStr != "" {
		d, err := time.ParseDuration(*sinceStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentjail logs: --since: %v\n", err)
			return 2
		}
		sinceDur = d
	}

	// Parse --action (comma-separated).
	var actions []string
	if *actionStr != "" {
		for _, a := range strings.Split(*actionStr, ",") {
			a = strings.TrimSpace(strings.ToLower(a))
			if a != "" {
				actions = append(actions, a)
			}
		}
	}

	// Determine color: enabled when stdout is a TTY and --no-color not set.
	useColor := !*noColor && term.IsTerminal(int(os.Stdout.Fd()))

	// Rich mode: enabled on a TTY in follow mode when --basic is not set and
	// stdout is not being piped. If the terminal is < 10 rows tall, richState
	// will downgrade to basic automatically (active=false).
	richEnabled := useColor && !*basicMode

	opts := logsOpts{
		logPath:  *logPath,
		follow:   !*noFollow,
		actions:  actions,
		tool:     *tool,
		since:    sinceDur,
		raw:      *raw,
		all:      *all,
		noColor:  *noColor,
		useColor: useColor,
		verbose:  *verbose,
		session:  *sessionStr,
		basic:    !richEnabled,
	}

	// Signal handling — SIGINT / SIGTERM exits cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	doneCh := make(chan struct{})
	go func() {
		<-sigCh
		close(doneCh)
	}()
	defer signal.Stop(sigCh)

	// SIGWINCH: window resize events. Only register on systems that support it.
	winchCh := make(chan os.Signal, 1)
	registerSIGWINCH(winchCh)
	defer signal.Stop(winchCh)

	return streamLogs(opts, doneCh, winchCh)
}

// streamLogs opens the log file and processes lines. Follows in tail mode.
// winchCh receives SIGWINCH events (window resize) when on platforms that
// support it; a nil or never-signalled channel is safe.
func streamLogs(opts logsOpts, doneCh <-chan struct{}, winchCh <-chan os.Signal) int {
	f, err := os.Open(opts.logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail logs: open %s: %v\n", opts.logPath, err)
		return 1
	}
	defer f.Close()

	// ── Rich display setup ─────────────────────────────────────────────────
	var rich *richState
	if !opts.basic && opts.follow {
		rich = newRichState()
		if rich.active {
			rich.setup(opts)
			defer rich.cleanup()
		} else {
			// Terminal too small — warn and fall back to basic.
			fmt.Fprintln(os.Stderr, "agentjail logs: terminal too small for rich mode; using --basic output")
			rich = nil
		}
	}

	// Basic mode: print banner + column header (original behavior).
	if rich == nil && opts.useColor {
		if opts.follow {
			fmt.Printf("%sagentjail logs — watching %s (Ctrl-C to stop)%s\n",
				ansiDim, opts.logPath, ansiReset)
		}
		fmt.Printf("%s%s%-8s  %-*s  %-7s  %-18s  %-36s  %s%s\n",
			ansiBold, ansiDim,
			"TIME", sourceWidth, "SOURCE", "ACTION", "TOOL", "RULE", "LATENCY",
			ansiReset)
		fmt.Printf("%s%s%s\n",
			ansiDim,
			strings.Repeat("─", 8+2+sourceWidth+2+7+2+18+2+36+2+8),
			ansiReset)
	}

	// Use bufio.Reader rather than Scanner: Scanner sets a permanent done
	// flag on first EOF and ignores future appended data — fatal for tail-style
	// follow. ReadString('\n') re-enters the underlying Read on every call and
	// picks up appended bytes after a sleep.
	reader := bufio.NewReaderSize(f, 256*1024)

	// Track last inode for rotation detection (best-effort).
	lastIno := fileIno(opts.logPath)

	// Buffer for partial lines (when EOF hits mid-line; resume on next read).
	var pending []byte

	// ── Catchup: fast-forward through historical content ──────────────────
	// In rich+follow mode, read all existing lines without rendering each
	// one — only update status-bar counters. Then display the last screenful.
	// This avoids slow line-by-line terminal output when the log is large.
	if rich != nil && rich.active {
		viewportH := rich.rows - 7 // 3 header + 3 status bar + 1 margin
		if viewportH < 1 {
			viewportH = 1
		}

		// Process rotated files for counter recovery (oldest first).
		rotated := discoverRotatedLogs(opts.logPath)
		for _, rp := range rotated {
			rf, rerr := os.Open(rp)
			if rerr != nil {
				continue
			}
			rreader := bufio.NewReaderSize(rf, 256*1024)
			for {
				chunk, rerr := rreader.ReadString('\n')
				if len(chunk) > 0 && rerr == nil {
					raw := []byte(strings.TrimRight(chunk, "\n"))
					var el evalLine
					if jerr := json.Unmarshal(raw, &el); jerr == nil && el.Msg == "eval" {
						wouldCount := true
						if opts.since > 0 && time.Since(el.Time) > opts.since {
							wouldCount = false
						}
						if wouldCount && len(opts.actions) > 0 && !containsStr(opts.actions, strings.ToLower(el.Action)) {
							wouldCount = false
						}
						if wouldCount && opts.tool != "" && el.Tool != opts.tool {
							wouldCount = false
						}
						if wouldCount && opts.session != "" && !strings.Contains(el.SessionID, opts.session) {
							wouldCount = false
						}
						if wouldCount {
							var impact string
							if strings.ToLower(el.Action) == "deny" {
								impact = impactFor(el)
							}
							rich.recordEvent(el.Action, el.ElapsedUs, impact)
						}
					}
				}
				if rerr != nil {
					break
				}
			}
			rf.Close()
		}

		tailBuf := make([][]byte, viewportH)
		tailWr := 0
		tailLen := 0

		for {
			chunk, rerr := reader.ReadString('\n')
			if len(chunk) > 0 {
				if len(pending) > 0 {
					chunk = string(pending) + chunk
					pending = pending[:0]
				}
				if rerr == nil {
					raw := []byte(strings.TrimRight(chunk, "\n"))

					var el evalLine
					wouldDisplay := false
					if jerr := json.Unmarshal(raw, &el); jerr == nil {
						switch {
						case el.Msg == "eval":
							wouldDisplay = true
							if opts.since > 0 && time.Since(el.Time) > opts.since {
								wouldDisplay = false
							}
							if wouldDisplay && len(opts.actions) > 0 && !containsStr(opts.actions, strings.ToLower(el.Action)) {
								wouldDisplay = false
							}
							if wouldDisplay && opts.tool != "" && el.Tool != opts.tool {
								wouldDisplay = false
							}
							if wouldDisplay && opts.session != "" && !strings.Contains(el.SessionID, opts.session) {
								wouldDisplay = false
							}
							if wouldDisplay {
								var impact string
								if strings.ToLower(el.Action) == "deny" {
									impact = impactFor(el)
								}
								rich.recordEvent(el.Action, el.ElapsedUs, impact)
							}
						case el.Level == "WARN" || el.Level == "WARNING" || el.Level == "ERROR":
							wouldDisplay = true
						default:
							wouldDisplay = opts.all
						}
					} else {
						wouldDisplay = true
					}

					if wouldDisplay {
						tailBuf[tailWr%viewportH] = append([]byte(nil), raw...)
						tailWr++
						if tailLen < viewportH {
							tailLen++
						}
					}
					continue
				}
				pending = append(pending, chunk...)
			}

			if rerr != nil {
				break
			}
		}

		if tailLen > 0 {
			rich.suppressRecord = true
			start := 0
			if tailWr > viewportH {
				start = tailWr - tailLen
			}
			for i := 0; i < tailLen; i++ {
				idx := (start + i) % viewportH
				processLine(tailBuf[idx], opts, rich)
			}
			rich.suppressRecord = false
		}

		rich.redrawBar(opts.useColor)
	}

	for {
		// Check for shutdown signal or window resize.
		select {
		case <-doneCh:
			return 0
		case <-winchCh:
			if rich != nil {
				rich.resize(opts)
			}
		default:
		}

		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 {
			if len(pending) > 0 {
				chunk = string(pending) + chunk
				pending = pending[:0]
			}
			if err == nil {
				// Complete line — strip trailing newline and process.
				line := strings.TrimRight(chunk, "\n")
				if perr := processLine([]byte(line), opts, rich); perr != nil {
					fmt.Fprintf(os.Stderr, "agentjail logs: %v\n", perr)
				}
				continue
			}
			// EOF mid-line — stash and wait for the rest.
			pending = append(pending, chunk...)
		}

		if err != nil && err.Error() != "EOF" {
			fmt.Fprintf(os.Stderr, "agentjail logs: read error: %v\n", err)
			return 1
		}

		// EOF reached.
		if !opts.follow {
			// Flush any pending partial line (shouldn't normally happen).
			if len(pending) > 0 {
				_ = processLine(pending, opts, rich)
			}
			return 0
		}

		// Follow mode: check for log rotation (inode change).
		newIno := fileIno(opts.logPath)
		if newIno != 0 && newIno != lastIno {
			// File rotated — reopen.
			_ = f.Close()
			f, err = os.Open(opts.logPath)
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			lastIno = newIno
			reader = bufio.NewReaderSize(f, 256*1024)
			pending = pending[:0]
			continue
		}

		// No new data — sleep briefly and retry.
		time.Sleep(100 * time.Millisecond)
	}
}

// processLine parses and renders one log line according to opts.
// rich may be nil (basic mode).
func processLine(raw []byte, opts logsOpts, rich *richState) error {
	if len(raw) == 0 {
		return nil
	}

	// Raw / pass-through mode: print everything as-is.
	if opts.raw {
		fmt.Printf("%s\n", raw)
		return nil
	}

	var line evalLine
	if err := json.Unmarshal(raw, &line); err != nil {
		// Unparseable line — print dimmed.
		if opts.useColor {
			fmt.Printf("%s%s%s\n", ansiDim, raw, ansiReset)
		} else {
			fmt.Printf("%s\n", raw)
		}
		return nil
	}

	// Route by msg + level.
	switch {
	case line.Msg == "eval":
		return renderEvalLine(line, opts, rich)
	case line.Level == "WARN" || line.Level == "WARNING":
		return renderWarnErrorLine(line, opts, false)
	case line.Level == "ERROR":
		return renderWarnErrorLine(line, opts, true)
	default:
		// Non-eval INFO line: skip unless --all.
		if opts.all {
			renderInfoLine(line, opts)
		}
		return nil
	}
}

// renderEvalLine formats and prints a single eval line.
// rich may be nil (basic/pipe mode).
func renderEvalLine(line evalLine, opts logsOpts, rich *richState) error {
	// --since filter.
	if opts.since > 0 && time.Since(line.Time) > opts.since {
		return nil
	}

	// --action filter.
	if len(opts.actions) > 0 && !containsStr(opts.actions, strings.ToLower(line.Action)) {
		return nil
	}

	// --tool filter.
	if opts.tool != "" && line.Tool != opts.tool {
		return nil
	}

	// --session filter (substring match — useful when only part of the ID is known).
	if opts.session != "" && !strings.Contains(line.SessionID, opts.session) {
		return nil
	}

	// Format time as HH:MM:SS.
	timeStr := line.Time.Format("15:04:05")

	// ── SOURCE cell construction ────────────────────────────────────────────
	//
	// Visible layout: [glyph][space][body...]  total = sourceWidth visible cols.
	//   glyph:  1 visible column (UTF-8 or ASCII per detectLogsUTF8)
	//   space:  1 visible column separator
	//   body:   sourceWidth-2 visible columns (truncated/padded)
	//
	// ANSI escapes are wrapped only around the glyph so that %-*s padding in
	// callers never has to count invisible bytes — the body is padded manually
	// to (sourceWidth-2) before any escapes are prepended.
	isTry := isTryRow(line.Agent, line.SessionID)
	useUTF8 := detectLogsUTF8()

	// Effective agent key for registry lookups: unrecognized → "unknown".
	effectiveAgent := line.Agent
	if _, ok := agentRegistry[effectiveAgent]; !ok {
		effectiveAgent = "unknown"
	}

	// Build the body (plain text, no ANSI), padded to exactly sourceWidth-2.
	const bodyWidth = sourceWidth - 2
	srcRaw := sourceCell(line.Agent, line.SessionID, line.CWD)
	srcBody := padRight(truncate(srcRaw, bodyWidth), bodyWidth)

	// Build the complete SOURCE cell string.
	// Color mode: colored glyph + reset + space + body (dim-wrapped for try).
	// No-color mode: bare glyph (no escapes) + space + body.
	buildSourceCell := func() string {
		glyph := agentGlyphFor(effectiveAgent, useUTF8)
		if opts.useColor {
			color := agentColorFor(effectiveAgent)
			var coloredGlyph string
			if color != "" {
				coloredGlyph = color + glyph + ansiReset
			} else {
				// unknown agent: render glyph dimmed.
				coloredGlyph = ansiDim + glyph + ansiReset
			}
			if isTry {
				// try rows: entire body is dimmed; glyph color overrides the dim.
				return coloredGlyph + " " + ansiDim + srcBody + ansiReset
			}
			return coloredGlyph + " " + srcBody
		}
		// No-color: glyph without any escapes.
		return glyph + " " + srcBody
	}
	srcStr := buildSourceCell()

	// Format action — upper case, padded to 7 chars.
	actionUpper := strings.ToUpper(line.Action)
	actionPad := fmt.Sprintf("%-7s", actionUpper)

	// Format tool — padded to 18 chars.
	toolStr := line.Tool
	if toolStr == "" {
		toolStr = "—"
	}
	toolPad := fmt.Sprintf("%-18s", toolStr)

	// ── Rich mode ──────────────────────────────────────────────────────────
	if rich != nil && rich.active {
		// Derive impact text for DENY rows; rule_id for others.
		var impactStr string
		var impact string
		if strings.ToLower(line.Action) == "deny" {
			impact = impactFor(line)
			if opts.useColor {
				impactStr = fmt.Sprintf("%s%-50s%s", ansiRedBold, truncate(impact, 50), ansiReset)
			} else {
				impactStr = fmt.Sprintf("%-50s", truncate(impact, 50))
			}
		} else {
			ruleStr := line.RuleID
			if ruleStr == "" {
				ruleStr = "—"
			}
			if opts.useColor {
				impactStr = fmt.Sprintf("%s%-50s%s", ansiDim, truncate(ruleStr, 50), ansiReset)
			} else {
				impactStr = fmt.Sprintf("%-50s", truncate(ruleStr, 50))
			}
		}

		// Latency: ms format, sub-1ms shows ⚡ (no LATENCY column — show inline hint only).
		latHint := latencyStr(line.ElapsedUs, opts.useColor)

		var outputLine string
		if opts.useColor {
			actionColor := actionANSI(line.Action)
			outputLine = fmt.Sprintf("%s  %s  %s%s%s  %s  %s  %s%s%s",
				timeStr,
				srcStr,
				actionColor, actionPad, ansiReset,
				toolPad,
				impactStr,
				ansiDim, latHint, ansiReset,
			)
		} else {
			outputLine = fmt.Sprintf("%s  %s  %-7s  %-18s  %s  %s",
				timeStr, srcStr, actionUpper, toolStr, impactStr, latHint,
			)
		}
		rich.pushLine(outputLine)
		fmt.Println(outputLine)

		if !rich.suppressRecord {
			rich.recordEvent(line.Action, line.ElapsedUs, impact)
			rich.redrawBar(opts.useColor)
		}

		// Verbose secondary line — still useful in rich mode.
		if opts.verbose {
			renderVerboseSecondary(line, opts)
		}
		return nil
	}

	// ── Basic mode (original behavior) ────────────────────────────────────

	// Format rule_id — flex.
	ruleStr := line.RuleID
	if ruleStr == "" {
		ruleStr = "—"
	}
	// Right-align elapsed — raw µs suffix (engineering-accurate for basic/pipe mode).
	elapsedStr := fmt.Sprintf("%dµs", line.ElapsedUs)

	if opts.useColor {
		actionColor := actionANSI(line.Action)
		fmt.Printf("%s  %s  %s%s%s  %s  %s%-36s%s  %s%s%s\n",
			timeStr,
			srcStr,
			actionColor, actionPad, ansiReset,
			toolPad,
			ansiDim, ruleStr, ansiReset,
			ansiDim, elapsedStr, ansiReset,
		)
	} else {
		fmt.Printf("%s  %s  %-7s  %-18s  %-36s  %s\n",
			timeStr, srcStr, actionUpper, toolStr, ruleStr, elapsedStr,
		)
	}

	// Verbose: emit a second indented line with the command/file_path, session,
	// and reason. Keeps the main row scannable while exposing the why.
	if opts.verbose {
		renderVerboseSecondary(line, opts)
	}
	return nil
}

// renderVerboseSecondary prints the -v secondary lines (summary, reason, session).
func renderVerboseSecondary(line evalLine, opts logsOpts) {
	session := line.SessionID
	if len(session) > 12 {
		session = session[:12] + "…"
	}
	summary := line.Summary
	if summary == "" {
		summary = "—"
	}
	reason := line.Reason
	if opts.useColor {
		if summary != "—" {
			fmt.Printf("          %s↳ %s%s\n", ansiDim, summary, ansiReset)
		}
		if reason != "" {
			fmt.Printf("          %s  reason: %s%s\n", ansiDim, reason, ansiReset)
		}
		if session != "" {
			fmt.Printf("          %s  session: %s%s\n", ansiDim, session, ansiReset)
		}
	} else {
		if summary != "—" {
			fmt.Printf("          ↳ %s\n", summary)
		}
		if reason != "" {
			fmt.Printf("            reason: %s\n", reason)
		}
		if session != "" {
			fmt.Printf("            session: %s\n", session)
		}
	}
}

// truncate returns s truncated to max runes, appending "…" when trimmed.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

// padRight returns s padded with trailing spaces to exactly width visible
// columns (rune count). If s is already wider it is truncated (with ellipsis).
// Used to manually control column width when ANSI escapes cannot be mixed with
// fmt.Sprintf %-*s (which counts bytes, not visible columns).
func padRight(s string, width int) string {
	runes := []rune(s)
	if len(runes) > width {
		// Should not happen if callers truncate first, but be defensive.
		return string(runes[:width-1]) + "…"
	}
	if len(runes) == width {
		return s
	}
	return s + strings.Repeat(" ", width-len(runes))
}

// renderWarnErrorLine prints a WARN or ERROR daemon log line.
func renderWarnErrorLine(line evalLine, opts logsOpts, isError bool) error {
	label := "[WARN]"
	color := ansiYellow
	if isError {
		label = "[ERROR]"
		color = ansiRed
	}

	msg := line.Msg
	if line.Err != "" {
		msg = fmt.Sprintf("%s: %s", msg, line.Err)
	}
	timeStr := line.Time.Format("15:04:05")

	if opts.useColor {
		fmt.Printf("%s  %s%s%s  %s\n", timeStr, color, label, ansiReset, msg)
	} else {
		fmt.Printf("%s  %s  %s\n", timeStr, label, msg)
	}
	return nil
}

// renderInfoLine prints a non-eval INFO line in dim text (--all mode).
func renderInfoLine(line evalLine, opts logsOpts) {
	timeStr := line.Time.Format("15:04:05")
	if opts.useColor {
		fmt.Printf("%s%s  %s%s\n", ansiDim, timeStr, line.Msg, ansiReset)
	} else {
		fmt.Printf("%s  %s\n", timeStr, line.Msg)
	}
}

// actionANSI returns the ANSI escape for the given action string.
func actionANSI(action string) string {
	switch strings.ToLower(action) {
	case "allow":
		return ansiGreen
	case "deny":
		return ansiRedBold
	case "ask":
		return ansiYellow
	default:
		return ansiBold
	}
}

// containsStr reports whether target appears in list (case-sensitive).
func containsStr(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// fileIno returns the inode number for the file at path, or 0 on error.
func fileIno(path string) uint64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return sys.Ino
}

// discoverRotatedLogs returns paths to rotated log files (e.g., path.5, path.4,
// ..., path.1) that exist on disk, sorted oldest-first (highest suffix first).
// The current (non-suffixed) log file is NOT included in the result.
func discoverRotatedLogs(basePath string) []string {
	var paths []string
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%d", basePath, i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		paths = append(paths, p)
	}
	// Reverse: oldest (highest suffix) first.
	for i, j := 0, len(paths)-1; i < j; i, j = i+1, j-1 {
		paths[i], paths[j] = paths[j], paths[i]
	}
	return paths
}
