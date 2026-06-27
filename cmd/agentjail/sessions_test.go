package main

import (
	"encoding/json"
	"fmt"
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

func TestLoadActiveSessionsFromPath_WithPID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active-sessions.json")

	// Use our own PID — guaranteed to be alive.
	myPID := os.Getpid()
	entries := []activeEntry{
		{SessionID: "alive-session", PID: myPID},
		{SessionID: "dead-session", PID: 99999999},
	}
	data, _ := json.Marshal(entries)
	os.WriteFile(path, data, 0644)

	m := loadActiveSessionsFromPath(path)
	if !m["alive-session"] {
		t.Error("expected alive-session to be active (our PID is alive)")
	}
	if m["dead-session"] {
		t.Error("expected dead-session to be inactive (PID 99999999 should not exist)")
	}
}

func TestIsProcessAlive(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Error("our own PID should be alive")
	}
	if isProcessAlive(99999999) {
		t.Error("PID 99999999 should not be alive")
	}
}

func TestLoadActiveSessionsFromPath_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active-sessions.json")
	os.WriteFile(path, []byte("not json"), 0644)

	m := loadActiveSessionsFromPath(path)
	if len(m) != 0 {
		t.Errorf("expected empty map for invalid JSON, got %v", m)
	}
}

func TestLoadActiveSessionsFromPath_BackwardsCompat(t *testing.T) {
	// Old format was a plain string array — should not crash, just return empty.
	dir := t.TempDir()
	path := filepath.Join(dir, "active-sessions.json")
	os.WriteFile(path, []byte(`["session-a","session-b"]`), 0644)

	m := loadActiveSessionsFromPath(path)
	// Old format won't parse into []activeEntry, so empty is fine.
	fmt.Printf("backwards compat: %v (ok if empty)\n", m)
}
