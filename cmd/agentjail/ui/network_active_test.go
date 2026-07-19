package ui

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/mitm"
)

// deadPID returns a PID that is guaranteed not to be alive: it starts a trivial
// process, waits for it to exit, and returns its (now-reaped) PID.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	return pid
}

// TestAggregateSessionsActiveFromPID guards approach 3a: a session's active flag
// tracks the owning shield PID's liveness, independent of last_seen recency.
// See ADR 0100-network-active-pid.
func TestAggregateSessionsActiveFromPID(t *testing.T) {
	stale := time.Now().Add(-30 * time.Minute).UTC()
	livePID := os.Getpid()
	dead := deadPID(t)

	rows := []mitm.RequestLog{
		// Live owner, but last_seen far outside any recency window -> still active.
		{Ts: stale, Host: "a", Method: "GET", Path: "/", URL: "https://a/", SessionID: "live", OwnerPID: livePID},
		{Ts: time.Now().UTC(), Host: "a", Method: "GET", Path: "/2", URL: "https://a/2", SessionID: "live", OwnerPID: livePID},
		// Dead owner -> inactive.
		{Ts: time.Now().UTC(), Host: "b", Method: "GET", Path: "/", URL: "https://b/", SessionID: "gone", OwnerPID: dead},
	}

	got := aggregateSessions(rows)
	byID := map[string]SessionInfo{}
	for _, s := range got {
		byID[s.SessionID] = s
	}

	live, ok := byID["live"]
	if !ok {
		t.Fatalf("missing session %q", "live")
	}
	if !live.Active {
		t.Errorf("live session: Active=false, want true (owner PID %d is alive despite stale last_seen)", livePID)
	}
	if live.RequestCount != 2 {
		t.Errorf("live session: RequestCount=%d, want 2", live.RequestCount)
	}
	if live.OwnerPID != livePID {
		t.Errorf("live session: OwnerPID=%d, want %d", live.OwnerPID, livePID)
	}

	gone, ok := byID["gone"]
	if !ok {
		t.Fatalf("missing session %q", "gone")
	}
	if gone.Active {
		t.Errorf("gone session: Active=true, want false (owner PID %d is dead)", dead)
	}
}
