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
