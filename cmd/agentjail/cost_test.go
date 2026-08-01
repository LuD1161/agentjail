package main

import (
	"testing"
	"time"
)

func TestParsePeriod(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		ok    bool
	}{
		{input: "7d", want: 7 * 24 * time.Hour, ok: true},
		{input: "24h", want: 24 * time.Hour, ok: true},
		{input: "0d"},
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
