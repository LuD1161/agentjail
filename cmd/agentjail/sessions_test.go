package main

import (
	"testing"
	"time"
)

func TestParseDuration_Standard(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"500ms", 500 * time.Millisecond},
		{"24h", 24 * time.Hour},
	}
	for _, tc := range tests {
		got, err := parseDuration(tc.input)
		if err != nil {
			t.Errorf("parseDuration(%q): %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDuration(%q) = %v; want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseDuration_Days(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
	}
	for _, tc := range tests {
		got, err := parseDuration(tc.input)
		if err != nil {
			t.Errorf("parseDuration(%q): %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDuration(%q) = %v; want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseDuration_Zero(t *testing.T) {
	for _, input := range []string{"0", ""} {
		got, err := parseDuration(input)
		if err != nil {
			t.Errorf("parseDuration(%q): %v", input, err)
		}
		if got != 0 {
			t.Errorf("parseDuration(%q) = %v; want 0", input, got)
		}
	}
}

func TestLoadActiveSessions_MissingFile(t *testing.T) {
	m := loadActiveSessions()
	if m != nil && len(m) > 0 {
		t.Errorf("expected nil or empty map when no file exists, got %v", m)
	}
}
