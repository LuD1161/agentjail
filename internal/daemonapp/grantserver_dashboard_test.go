package daemonapp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/costanalytics"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/store"
)

func TestLocalDashboardProjectionIsBoundedAndOmitsFullPaths(t *testing.T) {
	root := t.TempDir()
	eventStore, err := store.Open(filepath.Join(root, "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventStore.Close()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for i, action := range []string{"allow", "deny", "ask"} {
		err := eventStore.RecordDecision(context.Background(), store.DecisionRecord{
			Ts: now.Add(time.Duration(i) * time.Minute), SessionID: "session-1", Agent: "codex",
			Action: action, CWD: "/Users/private/work/agentjail", ToolName: "shell",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	active := newActiveTracker(root)
	active.update("session-1", os.Getpid(), "/Users/private/work/agentjail")
	started := make(chan struct{})
	release := make(chan struct{})
	projector := &localDashboardProjector{
		store: eventStore, activeSessions: active,
		tokenCache: newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) {
			close(started)
			<-release
			return []costanalytics.SessionCost{{Agent: costanalytics.AgentCodex, StartedAt: now, InputTokens: 10, OutputTokens: 5, CacheRead: 2}}, nil
		}),
	}

	snapshot, err := projector.DashboardSnapshot(context.Background(), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TotalCalls != 3 || snapshot.AllowedCalls != 1 || snapshot.DeniedCalls != 1 || snapshot.AskedCalls != 1 {
		t.Fatalf("unexpected totals: %+v", snapshot)
	}
	if snapshot.ActiveSessions != 1 || len(snapshot.RecentSessions) != 1 {
		t.Fatalf("unexpected sessions: %+v", snapshot.RecentSessions)
	}
	if got := snapshot.RecentSessions[0].Project; got != "agentjail" {
		t.Fatalf("project = %q, want basename only", got)
	}
	if snapshot.RecentSessions[0].Active != true {
		t.Fatal("tracked session must be active")
	}
	if snapshot.TokenStatus != grantctl.DashboardTokensLoading || len(snapshot.Tokens) != 0 {
		t.Fatalf("initial token state = %q %+v, want non-blocking loading", snapshot.TokenStatus, snapshot.Tokens)
	}
	<-started
	close(release)
	deadline := time.Now().Add(time.Second)
	for snapshot.TokenStatus == grantctl.DashboardTokensLoading && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		snapshot, err = projector.DashboardSnapshot(context.Background(), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
	}
	if snapshot.TokenStatus != grantctl.DashboardTokensReady || len(snapshot.Tokens) != 1 || snapshot.Tokens[0].InputTokens != 10 || snapshot.Tokens[0].CacheTokens != 2 {
		t.Fatalf("ready tokens: status=%q points=%+v", snapshot.TokenStatus, snapshot.Tokens)
	}
	if len(snapshot.TokenAgents) != 1 || snapshot.TokenAgents[0].Agent != string(costanalytics.AgentCodex) || snapshot.TokenAgents[0].InputTokens != 10 {
		t.Fatalf("agent token spread: %+v", snapshot.TokenAgents)
	}
}

func TestDashboardSnapshotResponseRejectsMissingProjectorAndVersions(t *testing.T) {
	now := time.Now()
	for _, version := range []grantctl.ProtocolVersion{0, 2} {
		if response := dashboardSnapshotResponse(nil, version, now); response.OK {
			t.Fatalf("version %d unexpectedly accepted", version)
		}
	}
	if response := dashboardSnapshotResponse(nil, grantctl.DashboardProtocolVersion, now); response.OK || response.Error != "dashboard snapshot unavailable" {
		t.Fatalf("unexpected nil projector response: %+v", response)
	}
}
