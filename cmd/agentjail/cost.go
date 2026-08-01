package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
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
	noColor := fs.Bool("no-color", false, "disable color output")

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
	if len(*projectDir) > costanalytics.MaxProjectFilterBytes {
		fmt.Fprintln(os.Stderr, "agentjail cost: --project is too long")
		return 2
	}
	if *noColor {
		restore := ui.DisableColor()
		defer restore()
	}

	since := time.Now().Add(-period)
	sessions, errs := costanalytics.CollectAll(since)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}

	reportSessions := sessions
	if *projectDir != "" {
		reportSessions = costanalytics.FilterByProject(sessions, *projectDir)
	}

	report := costanalytics.Aggregate(reportSessions, costanalytics.Period(*periodStr))

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
	printCostReportTo(os.Stdout, r)
}

func printCostReportTo(w io.Writer, r costanalytics.CostReport) {
	printCostReportToWithUI(w, r, ui.New(w))
}

func printCostReportToWithUI(w io.Writer, r costanalytics.CostReport, u *ui.UI) {

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s (last %s)\n", u.Section("Agent Cost Report"), r.Period)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Total spend:  %s  %s\n",
		u.Text(ui.ToneAccent, fmt.Sprintf("$%.2f", r.TotalCost)),
		u.Text(ui.ToneMuted, fmt.Sprintf("(%d sessions)", r.SessionCount)))
	fmt.Fprintln(w)

	if len(r.ByProject) > 0 {
		fmt.Fprintln(w, u.Section("By Project"))
		for _, p := range r.ByProject {
			project := fmt.Sprintf("%-45s", truncateStr(u.Sanitize(string(p.Project)), 45))
			fmt.Fprintf(w, "  %s %s %s   %s\n",
				u.Text(ui.ToneAccent, project),
				u.Text(ui.ToneSuccess, fmt.Sprintf("$%-8.2f", p.CostUSD)),
				u.Text(ui.ToneMuted, fmt.Sprintf("%3.0f%%", p.Percent)),
				u.Text(ui.ToneMuted, fmt.Sprintf("%d sessions", p.SessionCount)))
		}
		fmt.Fprintln(w)
	}

	if len(r.ByModel) > 0 {
		fmt.Fprintln(w, u.Section("By Model"))
		for _, m := range r.ByModel {
			model := fmt.Sprintf("%-30s", truncateStr(u.Sanitize(string(m.Model)), 30))
			fmt.Fprintf(w, "  %s %s %s   %s\n",
				u.Text(ui.ToneAccent, model),
				u.Text(ui.ToneSuccess, fmt.Sprintf("$%-8.2f", m.CostUSD)),
				u.Text(ui.ToneMuted, fmt.Sprintf("%3.0f%%", m.Percent)),
				u.Text(ui.ToneMuted, formatTokens(m.OutputTokens)+" output tokens"))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, u.Section("Token Efficiency"))
	fmt.Fprintf(w, "  Cache hit rate:     %s\n", u.Text(ui.ToneSuccess, fmt.Sprintf("%.0f%%", r.CacheHitRate)))
	fmt.Fprintf(w, "  Avg cost/session:   %s\n", u.Text(ui.ToneAccent, fmt.Sprintf("$%.2f", r.AvgCost)))
	fmt.Fprintf(w, "  Avg tokens/session: %s\n", u.Text(ui.ToneMuted,
		fmt.Sprintf("%s in, %s out", formatTokens(r.AvgInputTok), formatTokens(r.AvgOutputTok))))
	fmt.Fprintln(w)
}

func parsePeriod(s string) (time.Duration, error) {
	return costanalytics.ParsePeriod(s)
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
		message := u.Sanitize(a.Message)
		switch a.Level {
		case "exceeded":
			fmt.Fprintf(w, "  %s %s\n", u.Badge("fail", "EXCEEDED:"), message)
		case "warning":
			fmt.Fprintf(w, "  %s %s\n", u.Badge("warn", "WARNING:"), message)
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
