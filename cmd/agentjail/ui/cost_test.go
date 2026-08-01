package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costanalytics"
)

type fakeCostProvider struct {
	report costanalytics.CostReport
	alerts []costanalytics.BudgetAlert
	err    error
	query  CostQuery
}

func (f *fakeCostProvider) Summary(_ context.Context, query CostQuery) (costanalytics.CostReport, []costanalytics.BudgetAlert, error) {
	f.query = query
	return f.report, f.alerts, f.err
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
	var response costSummaryResponse
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
