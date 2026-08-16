package daemonapp

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

	at.update("session-1", 1000, "/tmp/a")
	at.update("session-2", 2000, "/tmp/b")

	got := at.list()
	sort.Slice(got, func(i, j int) bool { return got[i].SessionID < got[j].SessionID })
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].SessionID != "session-1" || got[0].PID != 1000 || got[0].CWD != "/tmp/a" {
		t.Errorf("entry 0: got %+v, want {session-1, 1000, /tmp/a}", got[0])
	}
	if got[1].SessionID != "session-2" || got[1].PID != 2000 || got[1].CWD != "/tmp/b" {
		t.Errorf("entry 1: got %+v, want {session-2, 2000, /tmp/b}", got[1])
	}
}

func TestActiveTracker_UpdateRefreshesPID(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 1000, "/tmp/a")
	at.update("session-1", 2000, "/tmp/c")

	got := at.list()
	if len(got) != 1 || got[0].PID != 2000 || got[0].CWD != "/tmp/c" {
		t.Errorf("expected PID/CWD updated to 2000/tmp/c, got %+v", got)
	}
}

func TestActiveTracker_FlushToDisk(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("abc-123", 1234, "/tmp/abc")
	at.update("def-456", 5678, "/tmp/def")

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
	if entries[0].CWD != "/tmp/abc" || entries[1].CWD != "/tmp/def" {
		t.Errorf("unexpected CWDs: %+v", entries)
	}
}

func TestActiveTracker_Cleanup(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 1000, "/tmp/a")
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

	at.update("", 1000, "/tmp/a")
	at.update("session-1", 0, "/tmp/b")
	at.update("session-2", -1, "/tmp/c")

	got := at.list()
	if len(got) != 0 {
		t.Errorf("empty/invalid entries should be ignored: got %v", got)
	}
}

func TestFindSessionByPID_DirectMatch(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 4242, "/repo/work")

	sid, cwd, ok := at.findSessionByPID(4242)
	if !ok {
		t.Fatal("expected direct match to be found")
	}
	if sid != "session-1" {
		t.Errorf("expected session-1, got %q", sid)
	}
	if cwd != "/repo/work" {
		t.Errorf("expected cwd /repo/work, got %q", cwd)
	}
}

func TestFindSessionByPID_NotFound(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	at.update("session-1", 4242, "/repo/work")

	// Use PID 1 (init), which FindAncestorPID rejects immediately since it
	// never walks past PID 1, and is guaranteed not to match any tracked
	// session PID here.
	_, _, ok := at.findSessionByPID(1)
	if ok {
		t.Error("expected no match for an untracked PID")
	}
}

func TestIsActive(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)

	if at.isActive("session-1") {
		t.Error("expected session-1 to be inactive before update")
	}

	at.update("session-1", 4242, "/repo/work")

	if !at.isActive("session-1") {
		t.Error("expected session-1 to be active after update")
	}
	if at.isActive("session-2") {
		t.Error("expected session-2 to remain inactive")
	}
}

func TestAuthenticatedSessionIgnoresUnverifiedRefresh(t *testing.T) {
	dir := t.TempDir()
	at := newActiveTracker(dir)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !at.registerLaunch(os.Getpid(), cwd, "/trusted/bin") {
		t.Fatal("register launch")
	}
	if !at.bindVerified("session-1", os.Getpid(), cwd) {
		t.Fatal("bind verified session")
	}
	at.update("session-1", 4242, "/untrusted")
	state, ok := at.metadata("session-1")
	if !ok || state.PID != os.Getpid() || state.CWD != filepath.Clean(cwd) || state.Path != "/trusted/bin" {
		t.Fatalf("authenticated state changed: %+v, %v", state, ok)
	}
}
