package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/store"
)

func TestRenderStatsReportsFinalOutcomes(t *testing.T) {
	rep := store.StatsReport{
		Total:    10,
		Sessions: 2,
		Allow:    7,
		Ask:      1,
		Deny:     2,
		DenyRules: []store.LabeledCount{
			{Label: "command_policy/no-sudo", Count: 1},
		},
	}
	var out bytes.Buffer
	renderStats(&out, rep, "0", 10)

	for _, want := range []string{
		"Total outcomes:             10",
		"Allowed / Asked / Blocked:  7 / 1 / 2",
		"Block rate:",
		"20.0%",
		"Top Policy Deny Rules",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestStatsFormatting(t *testing.T) {
	if got := meter(50, 4); got != "██░░" {
		t.Errorf("meter(50, 4) = %q, want %q", got, "██░░")
	}
	for _, tc := range []struct {
		us   int64
		want string
	}{
		{0, "—"},
		{999, "999µs"},
		{1500, "1.5ms"},
		{2_000_000, "2.00s"},
	} {
		if got := usDur(tc.us); got != tc.want {
			t.Errorf("usDur(%d) = %q, want %q", tc.us, got, tc.want)
		}
	}
}
