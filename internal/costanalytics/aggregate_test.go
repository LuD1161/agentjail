package costanalytics

import (
	"strings"
	"testing"
	"time"
)

func TestAggregateCountsSessionsAcrossModelsOnce(t *testing.T) {
	sessions := []SessionCost{
		{Source: "claude-code", SessionID: "one", Project: "/tmp/project-a", Model: "alpha", CostUSD: 1, InputTokens: 10, OutputTokens: 2, CacheRead: 100, CacheWrite: 5},
		{Source: "claude-code", SessionID: "one", Project: "/tmp/project-a", Model: "beta", CostUSD: 2, InputTokens: 20, OutputTokens: 4, CacheRead: 200, CacheWrite: 10},
		{Source: "opencode", SessionID: "two", Project: "/tmp/project-b", Model: "alpha", CostUSD: 3, InputTokens: 30, OutputTokens: 6, CacheRead: 300, CacheWrite: 15},
	}

	report := Aggregate(sessions, "7d")
	if report.SessionCount != 2 {
		t.Fatalf("SessionCount = %d, want 2", report.SessionCount)
	}
	if report.TotalCost != 6 || report.AvgCost != 3 {
		t.Fatalf("cost totals = total %v avg %v", report.TotalCost, report.AvgCost)
	}
	if len(report.ByModel) != 2 || report.ByModel[0].Model != "alpha" {
		t.Fatalf("ByModel = %+v", report.ByModel)
	}
	if report.ByModel[0].SessionCount != 2 || report.ByModel[0].InputTokens != 40 || report.ByModel[0].OutputTokens != 8 ||
		report.ByModel[0].CacheRead != 400 || report.ByModel[0].CacheWrite != 20 {
		t.Fatalf("alpha summary = %+v", report.ByModel[0])
	}
}

func TestMissingPricingErrorsExposeFutureCatalogLag(t *testing.T) {
	errs := missingPricingErrors([]SessionCost{
		{Model: "future-model", InputTokens: 10},
		{Model: "future-model", OutputTokens: 5},
		{Model: "gpt-5.6-sol", InputTokens: 10},
		{Model: "<synthetic>", InputTokens: 10},
	})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "future-model") {
		t.Fatalf("errors = %v, want one future-model diagnostic", errs)
	}
}

func TestCheckBudgetUsesInjectedDay(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	sessions := []SessionCost{
		{CostUSD: 9, StartedAt: now.Add(-time.Hour)},
		{CostUSD: 20, StartedAt: now.Add(-24 * time.Hour)},
	}

	status := checkBudgetAt(now, 10, nil, 0.8, sessions)
	if len(status.Alerts) != 1 || status.Alerts[0].Level != BudgetWarning {
		t.Fatalf("alerts = %+v", status.Alerts)
	}
}
