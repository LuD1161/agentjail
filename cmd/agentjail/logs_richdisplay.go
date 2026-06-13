// logs_richdisplay.go — ANSI scrolling-region status bar for `agentjail logs`.
//
// Rich mode is enabled automatically when stdout is a TTY and the terminal is
// at least 10 rows tall. Set --basic to force plain output (identical to the
// legacy behavior).
//
// ANSI approach: DECSTBM (\x1b[<top>;<bottom>r) reserves the bottom 3 rows for
// a status bar. Content printed above scrolls naturally; the bar is redrawn
// after every event. We use stdlib + golang.org/x/term only — no bubbletea,
// no tcell, no lipgloss.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/term"
)

const scrollbackCap = 500

// richState holds all mutable state for the rich status bar. Access is
// single-threaded (one goroutine drives the log loop) so no mutex is needed on
// the counters; the terminal write helpers are called inline.
type richState struct {
	mu sync.Mutex // guards terminal writes when SIGWINCH handler races

	// Counts.
	allow int
	deny  int
	ask   int

	// Latency ring buffer (microseconds). Fixed size; overwrites oldest.
	latBuf [100]int64
	latIdx int
	latN   int // number filled (0..100)

	// DENY impact history (last 5).
	impacts    [5]string
	impactIdx  int
	impactN    int

	// Terminal dimensions.
	rows int
	cols int

	// Whether rich mode is active.
	active bool

	// Scrollback ring buffer for resize replay.
	scrollback    [500]string
	scrollbackWr  int
	scrollbackLen int

	// When true, renderEvalLine skips recordEvent/redrawBar (used during catchup tail render).
	suppressRecord bool
}

// newRichState returns an initialized richState. It queries the terminal size.
// If the terminal is too small (< 10 rows) or size cannot be determined,
// active is false and all other methods are no-ops.
func newRichState() *richState {
	r := &richState{}
	r.refresh()
	return r
}

// refresh re-queries the terminal size. Called at startup and on SIGWINCH.
func (r *richState) refresh() {
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 10 {
		r.active = false
		r.rows = 0
		r.cols = 0
		return
	}
	r.rows = rows
	r.cols = cols
	r.active = true
}

// setup emits the ANSI sequences to enter rich mode:
//  1. Clear screen + home cursor.
//  2. Print header rows at the top.
//  3. Set scrolling region to rows 1..(height-3).
func (r *richState) setup(opts logsOpts) {
	if !r.active {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear screen and home the cursor.
	fmt.Print("\x1b[2J\x1b[H")

	// Print watching banner + column header at the top.
	if opts.follow {
		fmt.Printf("%sagentjail logs — watching %s (Ctrl-C to stop)%s\r\n",
			ansiDim, opts.logPath, ansiReset)
	}
	fmt.Printf("%s%s%-8s  %-*s  %-7s  %-18s  %-50s  %s%s\r\n",
		ansiBold, ansiDim,
		"TIME", sourceWidth, "SOURCE", "ACTION", "TOOL", "IMPACT / RULE", "LATENCY",
		ansiReset)
	sep := strings.Repeat("─", r.cols)
	fmt.Printf("%s%s%s\r\n", ansiDim, sep, ansiReset)

	// Reserve bottom 3 rows for the status bar.
	// Scrolling region: rows 4..(height-3) in 1-indexed ANSI coords.
	// The 3 header lines we just wrote occupy rows 1-3.
	topRow := 4
	bottomRow := r.rows - 3
	if bottomRow < topRow {
		bottomRow = topRow
	}
	fmt.Printf("\x1b[%d;%dr", topRow, bottomRow)

	// Move cursor into the scrolling region so the next Println goes there.
	fmt.Printf("\x1b[%d;0H", topRow)
}

// resize handles a terminal resize: resets the scrolling region, re-runs setup.
func (r *richState) resize(opts logsOpts) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset scrolling region first.
	fmt.Print("\x1b[r")

	// Re-query size.
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 10 {
		r.active = false
		return
	}
	r.rows = rows
	r.cols = cols
	r.active = true

	// Redraw setup.
	fmt.Print("\x1b[2J\x1b[H")
	if opts.follow {
		fmt.Printf("%sagentjail logs — watching %s (Ctrl-C to stop)%s\r\n",
			ansiDim, opts.logPath, ansiReset)
	}
	fmt.Printf("%s%s%-8s  %-*s  %-7s  %-18s  %-50s  %s%s\r\n",
		ansiBold, ansiDim,
		"TIME", sourceWidth, "SOURCE", "ACTION", "TOOL", "IMPACT / RULE", "LATENCY",
		ansiReset)
	sep := strings.Repeat("─", r.cols)
	fmt.Printf("%s%s%s\r\n", ansiDim, sep, ansiReset)

	topRow := 4
	bottomRow := r.rows - 3
	if bottomRow < topRow {
		bottomRow = topRow
	}
	fmt.Printf("\x1b[%d;%dr", topRow, bottomRow)
	fmt.Printf("\x1b[%d;0H", topRow)
	r.replayTail()
}

// cleanup resets the scrolling region and positions the cursor cleanly at the
// bottom so the shell prompt appears after the status bar area.
func (r *richState) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Print("\x1b[r")                             // reset scrolling region
	fmt.Printf("\x1b[%d;0H\n", r.rows)             // move to last row + newline
}

// recordEvent updates counters and the latency ring buffer after each event.
func (r *richState) recordEvent(action string, elapsedUs int64, impact string) {
	switch strings.ToLower(action) {
	case "allow":
		r.allow++
	case "deny":
		r.deny++
		// Record impact in circular buffer.
		r.impacts[r.impactIdx%5] = impact
		r.impactIdx++
		if r.impactN < 5 {
			r.impactN++
		}
	case "ask":
		r.ask++
	}

	// Record latency.
	r.latBuf[r.latIdx%100] = elapsedUs
	r.latIdx++
	if r.latN < 100 {
		r.latN++
	}
}

// redrawBar redraws the bottom 3 rows of the terminal with the status bar.
// Layout:
//
//	row height-2: separator line
//	row height-1: counts + median latency + saved summary
//	row height:   controls hint
func (r *richState) redrawBar(useColor bool) {
	if !r.active {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Save cursor position.
	fmt.Print("\x1b[s")

	// ── separator ─────────────────────────────────────────────────────────
	separatorRow := r.rows - 2
	fmt.Printf("\x1b[%d;0H\x1b[2K", separatorRow)
	sep := strings.Repeat("─", r.cols)
	if useColor {
		fmt.Printf("%s%s%s", ansiDim, sep, ansiReset)
	} else {
		fmt.Print(sep)
	}

	// ── status line 1 ─────────────────────────────────────────────────────
	statusRow := r.rows - 1
	fmt.Printf("\x1b[%d;0H\x1b[2K", statusRow)

	// Counts.
	var countStr string
	if useColor {
		countStr = fmt.Sprintf("%s🟢 %d allow%s · %s🔴 %d deny%s · %s🟡 %d ask%s",
			ansiGreen, r.allow, ansiReset,
			ansiRed, r.deny, ansiReset,
			ansiYellow, r.ask, ansiReset,
		)
	} else {
		countStr = fmt.Sprintf("allow:%d  deny:%d  ask:%d", r.allow, r.deny, r.ask)
	}

	// Median latency.
	medStr := medianLatencyStr(r.latBuf[:r.latN])

	// Saved summary (deduped impact buckets).
	savedStr := savedSummary(r.impacts[:r.impactN])

	line1 := countStr + " · " + medStr
	if savedStr != "" {
		line1 += " · saved: " + savedStr
	}
	fmt.Print(line1)

	// ── status line 2 (controls) ───────────────────────────────────────────
	controlsRow := r.rows
	fmt.Printf("\x1b[%d;0H\x1b[2K", controlsRow)
	if useColor {
		fmt.Printf("%s%*s%s", ansiDim, r.cols, "⌃C to stop", ansiReset)
	} else {
		fmt.Printf("%*s", r.cols, "^C to stop")
	}

	// Restore cursor position (back to scrolling region).
	fmt.Print("\x1b[u")
}

// ─── latency helpers ──────────────────────────────────────────────────────────

// latencyStr formats a microsecond count as a display string.
//   - sub-1 ms → "<1ms ⚡"  (yellow bolt in color mode, plain otherwise)
//   - >= 1 ms  → "Nms"  (rounded)
func latencyStr(us int64, useColor bool) string {
	if us < 1000 {
		if useColor {
			return fmt.Sprintf("<1ms %s⚡%s", ansiYellow, ansiReset)
		}
		return "<1ms ⚡"
	}
	ms := (us + 500) / 1000 // round to nearest ms
	return fmt.Sprintf("%dms", ms)
}

// medianLatencyStr computes the median of the given latency slice and formats
// it for the status bar. Returns "—" when the slice is empty.
func medianLatencyStr(lats []int64) string {
	if len(lats) == 0 {
		return "median —"
	}
	cp := make([]int64, len(lats))
	copy(cp, lats)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	mid := cp[len(cp)/2]
	if mid < 1000 {
		return "median <1ms"
	}
	ms := (mid + 500) / 1000
	return fmt.Sprintf("median %dms", ms)
}

// ─── saved summary ────────────────────────────────────────────────────────────

// savedSummary converts the impact history into a deduped "N category, M other"
// string for the status bar. Returns "" when no denies recorded yet.
func savedSummary(impacts []string) string {
	if len(impacts) == 0 {
		return ""
	}

	// Count by bucket.
	counts := make(map[string]int)
	var order []string
	for _, imp := range impacts {
		if imp == "" {
			continue
		}
		b := impactBucket(imp)
		if _, seen := counts[b]; !seen {
			order = append(order, b)
		}
		counts[b]++
	}

	if len(counts) == 0 {
		return ""
	}

	// Render top 3 buckets by insertion order (most-recent-first order is
	// preserved by the circular buffer walking the impacts slice).
	var parts []string
	for i, b := range order {
		if i >= 3 {
			break
		}
		n := counts[b]
		if n == 1 {
			parts = append(parts, "1 "+b)
		} else {
			parts = append(parts, fmt.Sprintf("%d %s", n, b))
		}
	}
	return strings.Join(parts, ", ")
}

func (r *richState) pushLine(line string) {
	r.scrollback[r.scrollbackWr%scrollbackCap] = line
	r.scrollbackWr++
	if r.scrollbackLen < scrollbackCap {
		r.scrollbackLen++
	}
}

func (r *richState) replayTail() {
	if r.scrollbackLen == 0 {
		return
	}
	viewportH := r.rows - 7
	if viewportH < 1 {
		viewportH = 1
	}
	count := r.scrollbackLen
	if count > viewportH {
		count = viewportH
	}
	start := (r.scrollbackWr - count + scrollbackCap) % scrollbackCap
	for i := 0; i < count; i++ {
		idx := (start + i) % scrollbackCap
		fmt.Println(r.scrollback[idx])
	}
}
