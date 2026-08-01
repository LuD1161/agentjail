package ui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/costanalytics"
)

// CostQuery is the UI's typed request to the local transcript cost domain.
type CostQuery struct {
	Period  string
	Since   time.Time
	Project string
}

// CostProvider is defined by the UI consumer so transcript discovery and
// aggregation remain independently testable. See ADR 0035-domain-driven-interface-first-typesafe.
type CostProvider interface {
	Summary(context.Context, CostQuery) (costanalytics.CostReport, []costanalytics.BudgetAlert, error)
}

type localCostProvider struct{}

func (localCostProvider) Summary(_ context.Context, query CostQuery) (costanalytics.CostReport, []costanalytics.BudgetAlert, error) {
	sessions, collectErrs := costanalytics.CollectAll(query.Since)
	for _, err := range collectErrs {
		slog.Debug("cost transcript source unavailable", "err", err)
	}
	if query.Project != "" {
		sessions = costanalytics.FilterByProject(sessions, query.Project)
	}

	report := costanalytics.Aggregate(sessions, costanalytics.Period(query.Period))
	alerts := []costanalytics.BudgetAlert{}
	home, err := os.UserHomeDir()
	if err != nil {
		return report, alerts, nil
	}
	policy, err := config.LoadOrDefault(filepath.Join(home, ".agentjail", "policy.yaml"))
	if err != nil {
		slog.Debug("cost budget config unavailable", "err", err)
		return report, alerts, nil
	}
	status := costanalytics.CheckBudget(
		policy.Cost.DailyBudget,
		policy.Cost.ProjectBudgets,
		policy.Cost.AlertThreshold,
		sessions,
	)
	return report, status.Alerts, nil
}

type costSummaryResponse struct {
	costanalytics.CostReport
	BudgetAlerts []costanalytics.BudgetAlert `json:"budget_alerts"`
}

func (s *Server) handleCostSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "7d"
	}
	duration, err := parseCostPeriod(period)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("invalid period: %v", err), http.StatusBadRequest)
		return
	}

	report, alerts, err := s.costProvider.Summary(r.Context(), CostQuery{
		Period:  period,
		Since:   s.now().Add(-duration),
		Project: r.URL.Query().Get("project"),
	})
	if err != nil {
		writeJSONError(w, fmt.Sprintf("cost summary: %v", err), http.StatusServiceUnavailable)
		return
	}
	if alerts == nil {
		alerts = []costanalytics.BudgetAlert{}
	}
	if report.ByProject == nil {
		report.ByProject = []costanalytics.ProjectSummary{}
	}
	if report.ByModel == nil {
		report.ByModel = []costanalytics.ModelSummary{}
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	writeJSON(w, costSummaryResponse{CostReport: report, BudgetAlerts: alerts})
}

func parseCostPeriod(value string) (time.Duration, error) {
	if len(value) > 1 && value[len(value)-1] == 'd' {
		days, err := strconv.Atoi(value[:len(value)-1])
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid period %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid period %q", value)
	}
	return duration, nil
}
