package main

import (
	"os"
	"path/filepath"
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

func TestLoadActiveSessionsFromPath_MissingFile(t *testing.T) {
	m := loadActiveSessionsFromPath(filepath.Join(t.TempDir(), "nonexistent.json"))
	if m != nil && len(m) > 0 {
		t.Errorf("expected nil or empty map when no file exists, got %v", m)
	}
}

func TestLoadActiveSessionsFromPath_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active-sessions.json")
	os.WriteFile(path, []byte(`["session-a","session-b"]`), 0644)

	m := loadActiveSessionsFromPath(path)
	if len(m) != 2 || !m["session-a"] || !m["session-b"] {
		t.Errorf("expected {session-a: true, session-b: true}, got %v", m)
	}
}
