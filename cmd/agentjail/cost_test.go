package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costanalytics"
	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/muesli/termenv"
)

func TestParsePeriod(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		ok    bool
	}{
		{input: "7d", want: 7 * 24 * time.Hour, ok: true},
		{input: "24h", want: 24 * time.Hour, ok: true},
		{input: "90d", want: 90 * 24 * time.Hour, ok: true},
		{input: "0d"},
		{input: "91d"},
		{input: "999999999999999999999d"},
		{input: "-1h"},
		{input: "forever"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePeriod(tt.input)
			if (err == nil) != tt.ok {
				t.Fatalf("parsePeriod(%q) error = %v", tt.input, err)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parsePeriod(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestPrintCostReportUsesColorWhenAvailable(t *testing.T) {
	var out bytes.Buffer
	u := ui.NewWithProfile(&out, termenv.TrueColor)
	printCostReportToWithUI(&out, costanalytics.CostReport{Period: "7d", TotalCost: 1}, u)
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("colored cost output contains no ANSI escapes: %q", out.String())
	}
}

func TestPrintCostReportSanitizesTranscriptMetadata(t *testing.T) {
	var out bytes.Buffer
	printCostReportTo(&out, costanalytics.CostReport{
		Period:    "1d",
		ByProject: []costanalytics.ProjectSummary{{Project: "project\x1b[2J", CostUSD: 1}},
		ByModel:   []costanalytics.ModelSummary{{Model: "model\x1b]0;title\a", CostUSD: 1}},
	})
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("terminal escape survived report rendering: %q", out.String())
	}
}

func TestPrintCostReportRendersDashboard(t *testing.T) {
	var out bytes.Buffer
	printCostReportTo(&out, costanalytics.CostReport{
		Period:       "7d",
		TotalCost:    18.42,
		SessionCount: 31,
		ByProject: []costanalytics.ProjectSummary{
			{Project: "production-api", CostUSD: 10.96, Percent: 59.5},
		},
		ByModel: []costanalytics.ModelSummary{
			{Model: "gpt-5.6-sol", CostUSD: 10.96, Percent: 59.5},
		},
		CacheHitRate: 74,
		AvgCost:      0.59,
		AvgInputTok:  123_000,
		AvgOutputTok: 4_500,
	})

	for _, want := range []string{
		"Agent Cost Report · last 7d",
		"TOTAL SPEND",
		"$18.42   31 sessions",
		"BY PROJECT",
		"production-api",
		"BY MODEL",
		"gpt-5.6-sol",
		"Cache hit  74%",
		"offline pricing",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dashboard missing %q:\n%s", want, out.String())
		}
	}
}

func TestCostShareBarBoundsPercent(t *testing.T) {
	if got := costShareBar(-1, 4); got != "[----]" {
		t.Fatalf("negative bar = %q", got)
	}
	if got := costShareBar(101, 4); got != "[====]" {
		t.Fatalf("overflow bar = %q", got)
	}
}
