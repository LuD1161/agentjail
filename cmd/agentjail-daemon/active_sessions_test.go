package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestActiveTracker_RegisterUnregister(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.register("session-1")
	at.register("session-2")

	got := at.list()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "session-1" || got[1] != "session-2" {
		t.Errorf("after register: got %v, want [session-1 session-2]", got)
	}

	at.unregister("session-1")
	got = at.list()
	if len(got) != 1 || got[0] != "session-2" {
		t.Errorf("after unregister session-1: got %v, want [session-2]", got)
	}

	at.unregister("session-2")
	got = at.list()
	if len(got) != 0 {
		t.Errorf("after unregister all: got %v, want []", got)
	}
}

func TestActiveTracker_Refcount(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.register("session-1")
	at.register("session-1")
	at.register("session-1")

	at.unregister("session-1")
	got := at.list()
	if len(got) != 1 {
		t.Errorf("after 3 register + 1 unregister: got %v, want [session-1]", got)
	}

	at.unregister("session-1")
	at.unregister("session-1")
	got = at.list()
	if len(got) != 0 {
		t.Errorf("after full unregister: got %v, want []", got)
	}
}

func TestActiveTracker_FlushToDisk(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.register("abc-123")
	at.register("def-456")

	data, err := os.ReadFile(filepath.Join(dir, "active-sessions.json"))
	if err != nil {
		t.Fatalf("read active-sessions.json: %v", err)
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sort.Strings(ids)
	if len(ids) != 2 || ids[0] != "abc-123" || ids[1] != "def-456" {
		t.Errorf("on-disk: got %v, want [abc-123 def-456]", ids)
	}

	at.unregister("abc-123")
	at.unregister("def-456")

	data, err = os.ReadFile(filepath.Join(dir, "active-sessions.json"))
	if err != nil {
		t.Fatalf("read after unregister: %v", err)
	}
	if err := json.Unmarshal(data, &ids); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("on-disk after unregister: got %v, want []", ids)
	}
}

func TestActiveTracker_Cleanup(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.register("session-1")
	path := filepath.Join(dir, "active-sessions.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("expected file to exist after register")
	}

	at.cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed after cleanup")
	}
}

func TestActiveTracker_EmptySessionID(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.register("")
	at.unregister("")

	got := at.list()
	if len(got) != 0 {
		t.Errorf("empty session ID should be ignored: got %v", got)
	}
}
