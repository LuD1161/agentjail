package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/store"
)

// monitorRow is the JSON shape of one report line.
type monitorRow struct {
	RuleID      string `json:"rule_id"`
	WouldAction string `json:"would_action"`
	ToolName    string `json:"tool_name"`
	Count       int64  `json:"count"`
}

// runMonitor renders the would-have-blocked report: what policy matched on
// calls that ran anyway. See ADR 0091-monitor-mode-tools.
func runMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	home, _ := os.UserHomeDir()
	dbPath := fs.String("db", filepath.Join(home, ".agentjail", "agentjail.db"), "path to SQLite event store")
	policyPath := fs.String("policy", filepath.Join(home, ".agentjail", "policy.yaml"), "path to policy.yaml")
	jsonOut := fs.Bool("json", false, "output as JSON")
	since := fs.String("since", "24h", "time range (e.g. 1h, 7d, 30m); 0 for all time")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	sinceDur, err := parseDuration(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail monitor: invalid --since %q: %v\n", *since, err)
		return 2
	}
	cutoff := time.Time{} // zero == all time
	if sinceDur > 0 {
		cutoff = time.Now().Add(-sinceDur)
	}

	st, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail monitor: open %s: %v\n", *dbPath, err)
		return 1
	}
	defer st.Close()

	rows, err := st.CountWouldBlock(context.Background(), cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail monitor: %v\n", err)
		return 1
	}

	out := make([]monitorRow, 0, len(rows))
	var total int64
	for _, r := range rows {
		out = append(out, monitorRow{RuleID: r.RuleID, WouldAction: r.WouldAction, ToolName: r.ToolName, Count: r.Count})
		total += r.Count
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	monitoring := enforcementIsMonitor(*policyPath)

	if len(out) == 0 {
		if monitoring {
			// Monitor mode with nothing to show is ambiguous: it can mean the
			// agent did nothing risky, or that the ruleset is too thin to fire.
			// Say so rather than let an empty table read as a clean bill.
			fmt.Println("agentjail monitor: nothing would have been blocked in this window.")
			fmt.Println("Monitor mode is ON, so this reflects your current ruleset — a thin ruleset flags nothing.")
		} else {
			fmt.Println("agentjail monitor: no monitor-mode decisions in this window.")
			fmt.Println("Enforcement is ON, so verdicts are acted on and nothing is merely recorded.")
			fmt.Println("To try log-only: set `enforcement: monitor` in " + *policyPath + " and reload the daemon.")
		}
		return 0
	}

	if !monitoring {
		// The rows are historical: they were recorded while monitor mode was on.
		fmt.Println("Note: enforcement is currently ON — these are from an earlier monitor-mode window.")
		fmt.Println()
	}

	fmt.Printf("Would have blocked %d tool call(s) since %s:\n\n", total, *since)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "COUNT\tVERDICT\tTOOL\tRULE")
	for _, r := range out {
		rule := r.RuleID
		if rule == "" {
			rule = "(none)"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", r.Count, r.WouldAction, r.ToolName, rule)
	}
	_ = w.Flush()

	if monitoring {
		fmt.Println("\nNothing above was blocked. Set `enforcement: enforce` in " + *policyPath + " to act on these.")
	}
	return 0
}

// enforcementIsMonitor reports whether policy.yaml currently selects monitor
// mode. Best-effort: an unreadable config reports false, since the report's
// framing is the only thing that depends on it.
func enforcementIsMonitor(policyPath string) bool {
	cfg, err := agentconfig.LoadOrDefault(policyPath)
	if err != nil {
		return false
	}
	return cfg.Monitoring()
}
