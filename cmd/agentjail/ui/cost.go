package ui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/costanalytics"
	localstore "github.com/LuD1161/agentjail/internal/store"
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

type localCostProvider struct {
	open func() (localstore.ReadStore, error)
}

func (provider localCostProvider) Summary(ctx context.Context, query CostQuery) (costanalytics.CostReport, []costanalytics.BudgetAlert, error) {
	if provider.open == nil {
		return costanalytics.CostReport{}, nil, fmt.Errorf("cost index is unavailable")
	}
	indexed, err := provider.open()
	if err != nil {
		return costanalytics.CostReport{}, nil, err
	}
	sessions, indexStatus, err := costanalytics.ReadIndexedSessions(ctx, indexed, query.Since)
	if err != nil {
		return costanalytics.CostReport{}, nil, err
	}
	if !indexStatus.Ready {
		return costanalytics.CostReport{}, nil, fmt.Errorf("cost index is still building")
	}
	if time.Since(indexStatus.LatestUpdate) > 26*time.Hour {
		slog.Debug("cost index is stale", "updated_at", indexStatus.LatestUpdate)
	}
	for _, warning := range costanalytics.PricingWarnings(sessions) {
		slog.Debug("cost estimate warning", "err", warning)
	}
	reportSessions := sessions
	if query.Project != "" {
		reportSessions = costanalytics.FilterByProject(sessions, query.Project)
	}

	report := costanalytics.Aggregate(reportSessions, costanalytics.Period(query.Period))
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
	project := r.URL.Query().Get("project")
	if len(project) > costanalytics.MaxProjectFilterBytes {
		writeJSONError(w, "project filter is too long", http.StatusBadRequest)
		return
	}

	report, alerts, err := s.costProvider.Summary(r.Context(), CostQuery{
		Period:  period,
		Since:   s.now().Add(-duration),
		Project: project,
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
	return costanalytics.ParsePeriod(value)
}
