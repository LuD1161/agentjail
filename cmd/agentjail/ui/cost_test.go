package ui

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/LuD1161/agentjail/internal/costindex"
	localstore "github.com/LuD1161/agentjail/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costanalytics"
)

type fakeCostProvider struct {
	report   costanalytics.CostReport
	alerts   []costanalytics.BudgetAlert
	err      error
	query    CostQuery
	warnings []CostWarning
}

func (f *fakeCostProvider) Summary(_ context.Context, query CostQuery) (CostSummary, error) {
	f.query = query
	return CostSummary{CostReport: f.report, BudgetAlerts: f.alerts, Warnings: f.warnings}, f.err
}

func TestCostSummary(t *testing.T) {
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	provider := &fakeCostProvider{
		report: costanalytics.CostReport{Period: "30d", TotalCost: 12.5, SessionCount: 4},
	}
	srv := NewServer("", "", "", false, NewStore(), "")
	srv.costProvider = provider
	srv.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodGet, "/api/cost/summary?period=30d&project=%2Fwork%2Fagentjail", nil)
	rec := httptest.NewRecorder()
	srv.handleCostSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if provider.query.Period != "30d" || provider.query.Project != "/work/agentjail" {
		t.Fatalf("query = %#v", provider.query)
	}
	if want := now.Add(-30 * 24 * time.Hour); !provider.query.Since.Equal(want) {
		t.Fatalf("since = %s, want %s", provider.query.Since, want)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache, no-store, must-revalidate" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var response CostSummary
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Period != "30d" || response.TotalCost != 12.5 || response.SessionCount != 4 {
		t.Fatalf("response = %#v", response)
	}
	if response.ByProject == nil || response.ByModel == nil || response.BudgetAlerts == nil {
		t.Fatalf("response collections must be arrays: %#v", response)
	}
}

func TestCostSummaryRejectsInvalidPeriod(t *testing.T) {
	srv := NewServer("", "", "", false, NewStore(), "")
	req := httptest.NewRequest(http.MethodGet, "/api/cost/summary?period=0d", nil)
	rec := httptest.NewRecorder()

	srv.handleCostSummary(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCostSummaryRejectsOversizedInputs(t *testing.T) {
	srv := NewServer("", "", "", false, NewStore(), "")
	for _, target := range []string{
		"/api/cost/summary?period=91d",
		"/api/cost/summary?project=" + strings.Repeat("x", costanalytics.MaxProjectFilterBytes+1),
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		srv.handleCostSummary(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d", target[:min(len(target), 32)], rec.Code, http.StatusBadRequest)
		}
	}
}

func TestCostSummaryUnavailable(t *testing.T) {
	srv := NewServer("", "", "", false, NewStore(), "")
	srv.costProvider = &fakeCostProvider{err: errors.New("reader failed")}
	req := httptest.NewRequest(http.MethodGet, "/api/cost/summary", nil)
	rec := httptest.NewRecorder()

	srv.handleCostSummary(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

type costReadFixture struct {
	localstore.ReadStore
	status   costindex.Status
	rows     []costindex.DailyUsage
	failures []localstore.AuditLogEntry
	auditErr error
}

func (f costReadFixture) CostIndexStatus(context.Context) (costindex.Status, error) {
	return f.status, nil
}
func (f costReadFixture) ListCostDailyUsage(context.Context, costindex.Window) ([]costindex.DailyUsage, error) {
	return f.rows, nil
}

func TestLocalCostLimitationsReachResponse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".agentjail"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".agentjail", "policy.yaml"), []byte("cost: [invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	fixture := costReadFixture{status: costindex.Status{Ready: true, LatestUpdate: now.Add(-48 * time.Hour)}, rows: []costindex.DailyUsage{{Model: "unknown-test-model", Usage: costindex.TokenUsage{Input: 10}, SessionID: "test", StartedAt: now}}}
	srv := NewServer("", "", "", false, NewStore(), "")
	srv.now = func() time.Time { return now }
	srv.costProvider = localCostProvider{open: func() (localstore.ReadStore, error) { return fixture, nil }, now: srv.now}
	rec := httptest.NewRecorder()
	srv.handleCostSummary(rec, httptest.NewRequest(http.MethodGet, "/api/cost/summary", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var response CostSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	got := map[CostWarningCode]bool{}
	for _, warning := range response.Warnings {
		got[warning.Code] = true
	}
	for _, code := range []CostWarningCode{CostWarningStale, CostWarningPricing, CostWarningBudget} {
		if !got[code] {
			t.Errorf("missing %s warning: %+v", code, response.Warnings)
		}
	}
	if response.SessionCount != 1 || !response.IndexedAt.Equal(fixture.status.LatestUpdate) {
		t.Fatalf("partial data lost: %+v", response)
	}
	if strings.Contains(rec.Body.String(), "invalid") {
		t.Fatal("raw config error leaked into response")
	}
}

func TestLocalCostBuildingRemainsUnavailable(t *testing.T) {
	provider := localCostProvider{open: func() (localstore.ReadStore, error) { return costReadFixture{}, nil }}
	_, err := provider.Summary(context.Background(), CostQuery{})
	if err == nil || !strings.Contains(err.Error(), "building") {
		t.Fatalf("got %v", err)
	}
}

func (f costReadFixture) ListAuditLog(_ context.Context, filter localstore.AuditLogFilter) ([]localstore.AuditLogEntry, error) {
	if filter.EventType != "cost_index.failed" || filter.Limit != 1 {
		return nil, errors.New("incorrect audit query")
	}
	return f.failures, f.auditErr
}

func TestLocalCostRefreshFailureFreshness(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		failed   time.Time
		auditErr error
		want     CostWarningCode
	}{
		{"failure after projection", now.Add(time.Minute), nil, CostWarningRefresh},
		{"projection replaces failure", now.Add(-time.Minute), nil, ""},
		{"audit unavailable", now, errors.New("audit unavailable"), CostWarningStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := costReadFixture{status: costindex.Status{Ready: true, LatestUpdate: now}, failures: []localstore.AuditLogEntry{{Ts: tc.failed}}, auditErr: tc.auditErr}
			provider := localCostProvider{open: func() (localstore.ReadStore, error) { return fixture, nil }, now: func() time.Time { return now }}
			report, err := provider.Summary(context.Background(), CostQuery{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(report.Warnings) != 0 {
					t.Fatalf("unexpected warnings %+v", report.Warnings)
				}
				return
			}
			if len(report.Warnings) != 1 || report.Warnings[0].Code != tc.want {
				t.Fatalf("got %+v, want %s", report.Warnings, tc.want)
			}
		})
	}
}
