package costanalytics

import (
	"testing"
	"time"
)

func TestCheckBudget_Disabled(t *testing.T) {
	sessions := []SessionCost{{CostUSD: 10, StartedAt: time.Now().UTC()}}
	status := CheckBudget(0, nil, 0.8, sessions)
	if len(status.Alerts) != 0 {
		t.Fatalf("expected no alerts when budget is disabled, got %d", len(status.Alerts))
	}
}

func TestCheckBudget_GlobalWarning(t *testing.T) {
	now := time.Now().UTC()
	sessions := []SessionCost{
		{CostUSD: 42, StartedAt: now},
	}
	status := CheckBudget(50, nil, 0.8, sessions)
	if len(status.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(status.Alerts))
	}
	a := status.Alerts[0]
	if a.Level != "warning" {
		t.Errorf("expected level=warning, got %q", a.Level)
	}
	if a.Scope != "global" {
		t.Errorf("expected scope=global, got %q", a.Scope)
	}
}

func TestCheckBudget_GlobalExceeded(t *testing.T) {
	now := time.Now().UTC()
	sessions := []SessionCost{
		{CostUSD: 30, StartedAt: now},
		{CostUSD: 25, StartedAt: now},
	}
	status := CheckBudget(50, nil, 0.8, sessions)
	if len(status.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(status.Alerts))
	}
	if status.Alerts[0].Level != "exceeded" {
		t.Errorf("expected level=exceeded, got %q", status.Alerts[0].Level)
	}
}

func TestCheckBudget_BelowThreshold(t *testing.T) {
	now := time.Now().UTC()
	sessions := []SessionCost{
		{CostUSD: 10, StartedAt: now},
	}
	status := CheckBudget(50, nil, 0.8, sessions)
	if len(status.Alerts) != 0 {
		t.Fatalf("expected no alerts below threshold, got %d", len(status.Alerts))
	}
}

func TestCheckBudget_YesterdayIgnored(t *testing.T) {
	yesterday := time.Now().UTC().Add(-25 * time.Hour)
	sessions := []SessionCost{
		{CostUSD: 100, StartedAt: yesterday},
	}
	status := CheckBudget(50, nil, 0.8, sessions)
	if len(status.Alerts) != 0 {
		t.Fatalf("expected no alerts for yesterday's sessions, got %d", len(status.Alerts))
	}
}

func TestCheckBudget_ProjectBudget(t *testing.T) {
	now := time.Now().UTC()
	sessions := []SessionCost{
		{CostUSD: 45, Project: "/home/user/Repos/prod-api", StartedAt: now},
		{CostUSD: 5, Project: "/home/user/Repos/other", StartedAt: now},
	}
	budgets := map[string]float64{
		"~/Repos/prod-api": 40,
	}

	// Override normalizeProject behavior: sessions have absolute paths,
	// config uses ~ paths. normalizeProject converts abs -> ~.
	// We need the home dir to match. Instead, use pre-normalized projects.
	sessions2 := []SessionCost{
		{CostUSD: 45, Project: "~/Repos/prod-api", StartedAt: now},
		{CostUSD: 5, Project: "~/Repos/other", StartedAt: now},
	}
	// normalizeProject won't change ~ paths since they don't start with home dir.
	// But in the real flow, the session.Project is an absolute path which
	// normalizeProject converts. For testing, just set projects that already
	// match the budget keys.
	_ = sessions // unused, just for illustration

	status := CheckBudget(0, budgets, 0.8, sessions2)
	if len(status.Alerts) != 1 {
		t.Fatalf("expected 1 project alert, got %d", len(status.Alerts))
	}
	a := status.Alerts[0]
	if a.Level != "exceeded" {
		t.Errorf("expected level=exceeded, got %q", a.Level)
	}
	if a.Scope != "~/Repos/prod-api" {
		t.Errorf("expected scope=~/Repos/prod-api, got %q", a.Scope)
	}
}

func TestCheckBudget_EmptyAlerts(t *testing.T) {
	status := CheckBudget(50, nil, 0.8, nil)
	if status.Alerts == nil {
		t.Fatal("Alerts should be non-nil empty slice, not nil")
	}
	if len(status.Alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(status.Alerts))
	}
}
