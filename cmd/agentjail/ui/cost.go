package ui

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/audit"
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
	Summary(context.Context, CostQuery) (CostSummary, error)
}

type localCostProvider struct {
	open func() (localstore.ReadStore, error)
	now  func() time.Time
}

func (provider localCostProvider) Summary(ctx context.Context, query CostQuery) (CostSummary, error) {
	if provider.open == nil {
		return CostSummary{}, fmt.Errorf("cost index is unavailable")
	}
	indexed, err := provider.open()
	if err != nil {
		return CostSummary{}, err
	}
	sessions, indexStatus, err := costanalytics.ReadIndexedSessions(ctx, indexed, query.Since)
	if err != nil {
		return CostSummary{}, err
	}
	if !indexStatus.Ready {
		return CostSummary{}, fmt.Errorf("cost index is still building")
	}
	reportSessions := sessions
	if query.Project != "" {
		reportSessions = costanalytics.FilterByProject(sessions, query.Project)
	}

	result := CostSummary{
		CostReport:   costanalytics.Aggregate(reportSessions, costanalytics.Period(query.Period)),
		BudgetAlerts: []costanalytics.BudgetAlert{},
		Warnings:     []CostWarning{},
		IndexedAt:    indexStatus.LatestUpdate,
	}
	now := time.Now()
	if provider.now != nil {
		now = provider.now()
	}
	if now.Sub(indexStatus.LatestUpdate) > 26*time.Hour {
		result.Warnings = append(result.Warnings, CostWarning{Code: CostWarningStale, Message: "Usage index is stale; recent spend may be missing. Keep the daemon running to refresh it."})
	}
	failures, err := indexed.ListAuditLog(ctx, localstore.AuditLogFilter{EventType: audit.CostIndexFailed, Limit: 1})
	if err != nil {
		result.Warnings = append(result.Warnings, CostWarning{Code: CostWarningStatus, Message: "Index refresh status is unavailable; the last indexed estimate is shown."})
	} else if len(failures) > 0 && !failures[0].Ts.Before(indexStatus.LatestUpdate) {
		result.Warnings = append(result.Warnings, CostWarning{Code: CostWarningRefresh, Message: "The latest recorded index refresh failed; usage may be incomplete. Check daemon diagnostics and retry the refresh."})
	}
	for _, warning := range costanalytics.PricingWarnings(reportSessions) {
		result.Warnings = append(result.Warnings, CostWarning{Code: CostWarningPricing, Message: warning.Error()})
	}
	home, err := os.UserHomeDir()
	if err != nil {
		result.Warnings = append(result.Warnings, budgetUnavailableWarning())
		return result, nil
	}
	policy, err := config.LoadOrDefault(filepath.Join(home, ".agentjail", "policy.yaml"))
	if err != nil {
		result.Warnings = append(result.Warnings, budgetUnavailableWarning())
		return result, nil
	}
	status := costanalytics.CheckBudget(
		policy.Cost.DailyBudget,
		policy.Cost.ProjectBudgets,
		policy.Cost.AlertThreshold,
		sessions,
	)
	result.BudgetAlerts = status.Alerts
	return result, nil
}

type CostWarningCode string

const (
	CostWarningStale   CostWarningCode = "stale_index"
	CostWarningPricing CostWarningCode = "pricing_estimate"
	CostWarningRefresh CostWarningCode = "refresh_failed"
	CostWarningStatus  CostWarningCode = "refresh_status_unavailable"
	CostWarningBudget  CostWarningCode = "budget_config_unavailable"
)

type CostWarning struct {
	Code    CostWarningCode `json:"code"`
	Message string          `json:"message"`
}

func budgetUnavailableWarning() CostWarning {
	return CostWarning{Code: CostWarningBudget, Message: "Budget configuration could not be loaded; budget alerts are unavailable. Check policy.yaml with agentjail doctor."}
}

type CostSummary struct {
	costanalytics.CostReport
	BudgetAlerts []costanalytics.BudgetAlert `json:"budget_alerts"`
	Warnings     []CostWarning               `json:"warnings"`
	IndexedAt    time.Time                   `json:"indexed_at"`
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

	report, err := s.costProvider.Summary(r.Context(), CostQuery{
		Period:  period,
		Since:   s.now().Add(-duration),
		Project: project,
	})
	if err != nil {
		writeJSONError(w, fmt.Sprintf("cost summary: %v", err), http.StatusServiceUnavailable)
		return
	}
	if report.BudgetAlerts == nil {
		report.BudgetAlerts = []costanalytics.BudgetAlert{}
	}
	if report.Warnings == nil {
		report.Warnings = []CostWarning{}
	}
	if report.ByProject == nil {
		report.ByProject = []costanalytics.ProjectSummary{}
	}
	if report.ByModel == nil {
		report.ByModel = []costanalytics.ModelSummary{}
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	writeJSON(w, report)
}

func parseCostPeriod(value string) (time.Duration, error) {
	return costanalytics.ParsePeriod(value)
}
