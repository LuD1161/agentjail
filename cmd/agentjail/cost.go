package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/costanalytics"
	"github.com/LuD1161/agentjail/internal/ui"
)

func runCost(args []string) int {
	fs := flag.NewFlagSet("cost", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	periodStr := fs.String("period", "7d", "time period (e.g. 7d, 30d, 24h)")
	projectDir := fs.String("project", "", "filter to a specific project directory")
	jsonOut := fs.Bool("json", false, "output as JSON")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	period, err := parsePeriod(*periodStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail cost: --period: %v\n", err)
		return 2
	}

	since := time.Now().Add(-period)
	sessions, errs := costanalytics.CollectAll(since)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}

	if *projectDir != "" {
		sessions = costanalytics.FilterByProject(sessions, *projectDir)
	}

	report := costanalytics.Aggregate(sessions, costanalytics.Period(*periodStr))

	// Load policy config for budget checking.
	policyPath, pathErr := policyConfigPath()
	var costCfg config.CostConfig
	if pathErr != nil {
		fmt.Fprintf(os.Stderr, "warning: resolve policy config: %v\n", pathErr)
	} else if policyPath != "" {
		if policyCfg, err := config.LoadOrDefault(policyPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: load cost budgets: %v\n", err)
		} else {
			costCfg = policyCfg.Cost
		}
	}
	budgetStatus := costanalytics.CheckBudget(
		costCfg.DailyBudget, costCfg.ProjectBudgets, costCfg.AlertThreshold, sessions,
	)

	if *jsonOut {
		out := struct {
			costanalytics.CostReport
			BudgetAlerts []costanalytics.BudgetAlert `json:"budget_alerts"`
		}{
			CostReport:   report,
			BudgetAlerts: budgetStatus.Alerts,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return boolToExit(enc.Encode(out))
	}

	printCostReport(report)
	printBudgetAlerts(budgetStatus)
	return 0
}

func printCostReport(r costanalytics.CostReport) {
	u := ui.New(os.Stdout)
	w := os.Stdout

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s (last %s)\n", u.Section("Agent Cost Report"), r.Period)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Total spend:  $%.2f  (%d sessions)\n", r.TotalCost, r.SessionCount)
	fmt.Fprintln(w)

	if len(r.ByProject) > 0 {
		fmt.Fprintln(w, u.Section("By Project"))
		for _, p := range r.ByProject {
			fmt.Fprintf(w, "  %-45s $%-8.2f %3.0f%%   %d sessions\n",
				truncateStr(string(p.Project), 45), p.CostUSD, p.Percent, p.SessionCount)
		}
		fmt.Fprintln(w)
	}

	if len(r.ByModel) > 0 {
		fmt.Fprintln(w, u.Section("By Model"))
		for _, m := range r.ByModel {
			fmt.Fprintf(w, "  %-30s $%-8.2f %3.0f%%   %s output tokens\n",
				m.Model, m.CostUSD, m.Percent, formatTokens(m.OutputTokens))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, u.Section("Token Efficiency"))
	fmt.Fprintf(w, "  Cache hit rate:     %.0f%%\n", r.CacheHitRate)
	fmt.Fprintf(w, "  Avg cost/session:   $%.2f\n", r.AvgCost)
	fmt.Fprintf(w, "  Avg tokens/session: %s in, %s out\n",
		formatTokens(r.AvgInputTok), formatTokens(r.AvgOutputTok))
	fmt.Fprintln(w)
}

func parsePeriod(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid period %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid period %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("period must be positive")
	}
	return d, nil
}

func formatTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return strconv.FormatInt(n, 10)
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

func printBudgetAlerts(status costanalytics.BudgetStatus) {
	if len(status.Alerts) == 0 {
		return
	}

	u := ui.New(os.Stdout)
	w := os.Stdout

	fmt.Fprintln(w, u.Section("Budget Alerts"))
	for _, a := range status.Alerts {
		switch a.Level {
		case "exceeded":
			fmt.Fprintf(w, "  %s %s\n", u.Badge("fail", "EXCEEDED:"), a.Message)
		case "warning":
			fmt.Fprintf(w, "  %s %s\n", u.Badge("warn", "WARNING:"), a.Message)
		}
	}
	fmt.Fprintln(w)
}

func boolToExit(err error) int {
	if err != nil {
		return 1
	}
	return 0
}
