package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	fmt.Fprintln(w, u.BoxRows("Agent Cost Report · last "+string(r.Period), costDashboardRows(u, r)))
	fmt.Fprintln(w)
}

func costDashboardRows(u *ui.UI, r costanalytics.CostReport) []ui.BoxRow {
	lines := []ui.BoxRow{
		{Text: "ESTIMATED API COST"},
		{Text: fmt.Sprintf("$%.2f   %d sessions", r.TotalCost, r.SessionCount)},
	}

	if len(r.ByProject) > 0 {
		lines = append(lines, ui.BoxRow{}, ui.BoxRow{Text: "BY PROJECT"})
		for _, project := range r.ByProject {
			name := truncateStr(u.Sanitize(string(project.Project)), 26)
			lines = append(lines, ui.BoxRow{Text: "  " + u.Emoji("📁  ") + fmt.Sprintf("%-26s %s  $%8.2f  %3d sess", name, costShareBar(project.Percent, 14), project.CostUSD, project.SessionCount)})
		}
	}

	models := visibleModelSummaries(r.ByModel)
	if len(models) > 0 {
		lines = append(lines, ui.BoxRow{}, ui.BoxRow{Text: "BY MODEL · API LIST-PRICE ESTIMATE"})
		for i, model := range models {
			name := truncateStr(u.Sanitize(string(model.Model)), 26)
			lines = append(lines, ui.BoxRow{Text: fmt.Sprintf("  %-26s %s  $%8.2f  %3d sess", name, costShareBar(model.Percent, 14), model.CostUSD, model.SessionCount)})
			for _, detail := range modelUsageDetails(model) {
				lines = append(lines, ui.BoxRow{Text: detail, Tone: ui.BoxToneMuted})
			}
			if i < len(models)-1 {
				lines = append(lines, ui.BoxRow{})
			}
		}
	}

	lines = append(lines,
		ui.BoxRow{},
		ui.BoxRow{Text: "TOKEN EFFICIENCY"},
		ui.BoxRow{Text: fmt.Sprintf("Cache hit  %.0f%%   ·   Avg API estimate / session  $%.2f", r.CacheHitRate, r.AvgCost)},
		ui.BoxRow{Text: fmt.Sprintf("Avg usage  %s input   ·   %s output", formatTokens(r.AvgInputTok), formatTokens(r.AvgOutputTok))},
		ui.BoxRow{},
		ui.BoxRow{Text: "API list-price equivalent · subscriptions are not billed this way", Tone: ui.BoxToneMuted},
		ui.BoxRow{Text: "local aggregates · offline pricing · no transcript upload", Tone: ui.BoxToneMuted},
	)
	return lines
}

func modelUsageDetails(model costanalytics.ModelSummary) []string {
	details := []string{fmt.Sprintf("      usage   %s input · %s cache reads · %s output",
		formatTokens(model.InputTokens), formatTokens(model.CacheRead), formatTokens(model.OutputTokens))}
	cacheWrites := "      writes  " + formatTokens(model.CacheWrite) + " cache writes"
	if model.CacheWrite5m != 0 || model.CacheWrite1h != 0 {
		cacheWrites += fmt.Sprintf(" (%s 5m · %s 1h)", formatTokens(model.CacheWrite5m), formatTokens(model.CacheWrite1h))
	}
	if model.CacheWrite != 0 {
		details = append(details, cacheWrites)
	}
	if model.BaseEstimate {
		details = append(details, "      pricing base rates only · incomplete per-request usage")
	}
	if model.TTLEstimate {
		details = append(details, "      pricing 5m rate used · cache-write TTL unavailable")
	}
	return details
}

func visibleModelSummaries(models []costanalytics.ModelSummary) []costanalytics.ModelSummary {
	visible := make([]costanalytics.ModelSummary, 0, len(models))
	for _, model := range models {
		if model.CostUSD == 0 && model.InputTokens == 0 && model.OutputTokens == 0 && model.CacheRead == 0 && model.CacheWrite == 0 {
			continue
		}
		visible = append(visible, model)
	}
	return visible
}

func costShareBar(percent float64, width int) string {
	percent = max(0, min(100, percent))
	filled := int(percent/100*float64(width) + 0.5)
	return "[" + strings.Repeat("=", filled) + strings.Repeat("-", width-filled) + "]"
}

func parsePeriod(s string) (time.Duration, error) {
	return costanalytics.ParsePeriod(s)
}

func formatTokens(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
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
