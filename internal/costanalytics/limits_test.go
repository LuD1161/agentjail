package costanalytics

import (
	"strings"
	"testing"
	"time"
)

func TestParsePeriodBounds(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "90d", want: 90 * 24 * time.Hour, ok: true},
		{value: "2160h", want: 90 * 24 * time.Hour, ok: true},
		{value: "91d"},
		{value: "2161h"},
		{value: "999999999999999999999d"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := ParsePeriod(test.value)
			if (err == nil) != test.ok {
				t.Fatalf("ParsePeriod(%q) error = %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("ParsePeriod(%q) = %s, want %s", test.value, got, test.want)
			}
		})
	}
}

func TestAppendSessionCostsCapsResults(t *testing.T) {
	existing := make([]SessionCost, maxSessionCosts-1)
	got, err := appendSessionCosts(existing, []SessionCost{{}, {}})
	if err == nil || len(got) != maxSessionCosts {
		t.Fatalf("got len=%d err=%v, want capped result and error", len(got), err)
	}
}

func TestTranscriptScannerSkipsOversizedLineAndContinues(t *testing.T) {
	input := "first\n" + strings.Repeat("x", maxTranscriptLineBytes+2) + "\nlast\n"
	scanner := newTranscriptScanner(strings.NewReader(input))

	var lines []string
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			lines = append(lines, string(scanner.Bytes()))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lines, ","); got != "first,last" {
		t.Fatalf("lines = %q, want oversized record skipped and later record read", got)
	}
}
