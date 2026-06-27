package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestActiveTracker_Update(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 1000)
	at.update("session-2", 2000)

	got := at.list()
	sort.Slice(got, func(i, j int) bool { return got[i].SessionID < got[j].SessionID })
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].SessionID != "session-1" || got[0].PID != 1000 {
		t.Errorf("entry 0: got %+v, want {session-1, 1000}", got[0])
	}
	if got[1].SessionID != "session-2" || got[1].PID != 2000 {
		t.Errorf("entry 1: got %+v, want {session-2, 2000}", got[1])
	}
}

func TestActiveTracker_UpdateRefreshesPID(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 1000)
	at.update("session-1", 2000)

	got := at.list()
	if len(got) != 1 || got[0].PID != 2000 {
		t.Errorf("expected PID updated to 2000, got %+v", got)
	}
}

func TestActiveTracker_FlushToDisk(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("abc-123", 1234)
	at.update("def-456", 5678)

	data, err := os.ReadFile(filepath.Join(dir, "active-sessions.json"))
	if err != nil {
		t.Fatalf("read active-sessions.json: %v", err)
	}
	var entries []activeEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SessionID < entries[j].SessionID })
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries on disk, got %d", len(entries))
	}
	if entries[0].PID != 1234 || entries[1].PID != 5678 {
		t.Errorf("unexpected PIDs: %+v", entries)
	}
}

func TestActiveTracker_Cleanup(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 1000)
	path := filepath.Join(dir, "active-sessions.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("expected file to exist after update")
	}

	at.cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed after cleanup")
	}
}

func TestActiveTracker_EmptySessionID(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("", 1000)
	at.update("session-1", 0)
	at.update("session-2", -1)

	got := at.list()
	if len(got) != 0 {
		t.Errorf("empty/invalid entries should be ignored: got %v", got)
	}
}
