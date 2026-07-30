package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
)

// runStats renders typed aggregates from the singleton read-only store.
// Latency remains a local engineering metric. See ADR 0002-latency-as-engineering-metric.
func runStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	home, _ := os.UserHomeDir()
	dbPath := fs.String("db", filepath.Join(home, ".agentjail", "agentjail.db"), "path to SQLite event store")
	jsonOut := fs.Bool("json", false, "output as JSON")
	since := fs.String("since", "0", "time range (e.g. 24h, 7d, 30m); 0 for all time")
	topN := fs.Int("top", 10, "how many rows to show per breakdown table")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *topN < 1 {
		fmt.Fprintln(os.Stderr, "agentjail stats: --top must be at least 1")
		return 2
	}

	sinceDur, err := parseDuration(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail stats: invalid --since %q: %v\n", *since, err)
		return 2
	}
	cutoff := time.Time{} // zero == all time
	if sinceDur > 0 {
		cutoff = time.Now().Add(-sinceDur)
	}

	st, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail stats: open %s: %v\n", *dbPath, err)
		return 1
	}
	defer st.Close()

	rep, err := st.ComputeStats(context.Background(), cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail stats: %v\n", err)
		return 1
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}

	renderStats(os.Stdout, rep, *since, *topN)
	return 0
}

const statsRule = "─────────────────────────────────────────────────────────────────────────"

// renderStats prints the human-readable report. Dependency-light on purpose
// (no internal/ui): plain fmt + block-glyph bars, matching the CLI convention.
func renderStats(w io.Writer, rep store.StatsReport, since string, topN int) {
	scope := "all time"
	if !rep.Since.IsZero() {
		scope = "last " + since
	}

	fmt.Fprintf(w, "AgentJail Activity (%s)\n", scope)
	fmt.Fprintln(w, "════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)

	window := "—"
	if rep.FirstDay != "" {
		if rep.FirstDay == rep.LastDay {
			window = rep.FirstDay
		} else {
			window = rep.FirstDay + " → " + rep.LastDay
		}
	}
	fmt.Fprintf(w, "Total outcomes:             %d\n", rep.Total)
	fmt.Fprintf(w, "Sessions:                   %d\n", rep.Sessions)
	fmt.Fprintf(w, "Allowed / Asked / Blocked:  %d / %d / %d\n", rep.Allow, rep.Ask, rep.Deny)
	fmt.Fprintf(w, "Active days:                %d  (%s)\n", rep.ActiveDays, window)
	fmt.Fprintf(w, "Latency (p50/p90/p95/p99/max): %s / %s / %s / %s / %s\n",
		usDur(rep.Latency.P50), usDur(rep.Latency.P90), usDur(rep.Latency.P95),
		usDur(rep.Latency.P99), usDur(rep.Latency.Max))

	blockRate := 0.0
	if rep.Total > 0 {
		blockRate = float64(rep.Deny) / float64(rep.Total) * 100
	}
	fmt.Fprintf(w, "Block rate: %s %.1f%%\n", meter(blockRate, 24), blockRate)

	renderBreakdown(w, "Top Policy Deny Rules", "Rule", rep.DenyRules, topN)
	renderBreakdown(w, "By Agent", "Agent", rep.ByAgent, topN)
	renderBreakdown(w, "By Surface (audit_log)", "Event", rep.BySurface, topN)

	if len(rep.CoverageGaps) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "⚠ Coverage gaps: %d day(s) where the shield activated but zero decisions were recorded.\n", len(rep.CoverageGaps))
		fmt.Fprintf(w, "  %s\n", strings.Join(rep.CoverageGaps, ", "))
		fmt.Fprintln(w, "  This may indicate an under-recording window; run `agentjail doctor`.")
	}
}

// renderBreakdown prints one ranked table with proportional impact bars.
func renderBreakdown(w io.Writer, title, colName string, rows []store.LabeledCount, topN int) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", title)
	fmt.Fprintln(w, statsRule)
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	var total, max int64
	for _, r := range rows {
		total += r.Count
		if r.Count > max {
			max = r.Count
		}
	}
	fmt.Fprintf(w, "  %-3s %-32s %8s %6s  %s\n", "#", colName, "Count", "Share", "Impact")
	for i, r := range rows {
		if i >= topN {
			fmt.Fprintf(w, "  … and %d more\n", len(rows)-topN)
			break
		}
		share := 0.0
		if total > 0 {
			share = float64(r.Count) / float64(total) * 100
		}
		fmt.Fprintf(w, "  %-3d %-32s %8d %5.1f%%  %s\n",
			i+1, truncate(r.Label, 32), r.Count, share, bar(r.Count, max, 10))
	}
}

// bar renders a proportional block bar of the given width for count/max.
func bar(count, max int64, width int) string {
	if max <= 0 {
		return strings.Repeat("░", width)
	}
	filled := int(float64(count) / float64(max) * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// meter renders a percentage as a fixed-width block meter (0-100%).
func meter(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// usDur formats a microsecond count as a compact human duration.
func usDur(us int64) string {
	switch {
	case us <= 0:
		return "—"
	case us < 1000:
		return fmt.Sprintf("%dµs", us)
	case us < 1_000_000:
		return fmt.Sprintf("%.1fms", float64(us)/1000)
	default:
		return fmt.Sprintf("%.2fs", float64(us)/1_000_000)
	}
}
