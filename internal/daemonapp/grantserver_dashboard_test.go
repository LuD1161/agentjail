package daemonapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		toolName := "shell"
		if i == 0 {
			toolName = "mcp__linear__create_issue"
		}
		err := eventStore.RecordDecision(context.Background(), store.DecisionRecord{
			Ts: now.Add(time.Duration(i) * time.Minute), SessionID: "session-1", Agent: "codex",
			Action: action, CWD: "/Users/private/work/agentjail", ToolName: toolName,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	active := newActiveTracker(root)
	active.update("session-1", os.Getpid(), "/Users/private/work/agentjail")
	if err := eventStore.UpsertDiscoveredTool(context.Background(), "chrome-devtools", "navigate_page", "audit"); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertDiscoveredTool(context.Background(), "chrome-devtools", "take_snapshot", "audit"); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertMCPDiscoveryStatus(context.Background(), "chrome-devtools", store.MCPDiscoveryConnected); err != nil {
		t.Fatal(err)
	}
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
	if len(snapshot.MCPTools) != 2 || snapshot.MCPTools[0].Server != "chrome-devtools" || len(snapshot.MCPTools[0].Tools) != 2 || snapshot.MCPTools[1].Server != "linear" || len(snapshot.MCPTools[1].Tools) != 1 || snapshot.MCPTools[1].Tools[0] != "create_issue" {
		t.Fatalf("MCP tools: %+v", snapshot.MCPTools)
	}
	if len(snapshot.MCPDiscovery) != 1 || snapshot.MCPDiscovery[0].Server != "chrome-devtools" || snapshot.MCPDiscovery[0].Status != grantctl.MCPDiscoveryConnected {
		t.Fatalf("MCP discovery statuses: %+v", snapshot.MCPDiscovery)
	}
}

func TestDashboardTokenCacheServesPersistedAggregateBeforeRefresh(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "cache", "dashboard-tokens-v1.json")
	cache := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) {
		return []costanalytics.SessionCost{{Agent: costanalytics.AgentCodex, StartedAt: now.Add(-24 * time.Hour), InputTokens: 42}}, nil
	}, path)
	cache.refresh(now.AddDate(0, 0, -34), now)

	collectorCalled := make(chan struct{}, 1)
	reloaded := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) {
		collectorCalled <- struct{}{}
		return nil, nil
	}, path)
	points, agents, status := reloaded.snapshot(now.AddDate(0, 0, -34), now.Add(time.Second))
	if status != grantctl.DashboardTokensReady || len(points) != 1 || points[0].InputTokens != 42 {
		t.Fatalf("persisted snapshot: status=%q points=%+v", status, points)
	}
	if len(agents) != 1 || agents[0].Agent != string(costanalytics.AgentCodex) || agents[0].InputTokens != 42 {
		t.Fatalf("persisted agents: %+v", agents)
	}
	select {
	case <-collectorCalled:
		t.Fatal("fresh persisted aggregate unexpectedly triggered collection")
	default:
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions: info=%v err=%v", info, err)
	}
}

func TestDashboardTokenCacheRefreshesOnlyRecentDaysAfterRestart(t *testing.T) {
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "dashboard-tokens-v1.json")
	cached := dashboardTokenCacheFile{
		Version: 1, LoadedAt: now.Add(-dashboardTokenCacheTTL - time.Minute),
		LocalSessions: []grantctl.DashboardLocalSessionV1{},
		Points:        []grantctl.DashboardTokenDayV1{{Day: "2026-08-20", InputTokens: 10}},
		Agents:        []grantctl.DashboardTokenAgentV1{{Agent: "codex", InputTokens: 10}},
		AgentDays:     []dashboardTokenAgentDay{{Day: "2026-08-20", Agent: "codex", InputTokens: 10}},
	}
	data, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var collectedSince time.Time
	cache := newDashboardTokenCache(func(since time.Time) ([]costanalytics.SessionCost, []error) {
		collectedSince = since
		return []costanalytics.SessionCost{{Agent: costanalytics.AgentClaudeCode, StartedAt: now, InputTokens: 5}}, nil
	}, path)
	cache.refresh(now.AddDate(0, 0, -34), now)
	if want := now.Truncate(24 * time.Hour).Add(-24 * time.Hour); !collectedSince.Equal(want) {
		t.Fatalf("collected since %s, want %s", collectedSince, want)
	}
	points, agents, status := cache.snapshot(now.AddDate(0, 0, -34), now)
	if status != grantctl.DashboardTokensReady || len(points) != 2 {
		t.Fatalf("merged points: status=%q points=%+v", status, points)
	}
	if len(agents) != 2 {
		t.Fatalf("merged agents: %+v", agents)
	}
}

func TestDashboardTokenCacheIgnoresMalformedSecretBearingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tokens-v1.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"credential":"must-not-surface","points":`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) { return nil, nil }, path)
	if len(cache.points) != 0 || !cache.loadedAt.IsZero() {
		t.Fatalf("malformed cache was accepted: %+v", cache)
	}
}

func TestDashboardTokenCacheRejectsInvalidAgentAggregate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tokens-v1.json")
	cached := dashboardTokenCacheFile{
		Version: 1, LoadedAt: time.Now().UTC(),
		Agents: []grantctl.DashboardTokenAgentV1{{Agent: "codex", InputTokens: -1}},
	}
	data, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) { return nil, nil }, path)
	if len(cache.agents) != 0 || !cache.loadedAt.IsZero() {
		t.Fatalf("invalid cache was accepted: %+v", cache)
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

func TestLocalHistoryAvailableWithoutAuditOrNetwork(t *testing.T) {
	eventStore, err := store.Open(filepath.Join(t.TempDir(), "agentjail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer eventStore.Close()
	now := time.Now().UTC()
	cache := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) {
		return []costanalytics.SessionCost{{Agent: costanalytics.AgentCodex, SessionID: "original-id", Project: "/Users/private/work/demo", StartedAt: now.Add(-time.Hour)}}, nil
	})
	cache.refresh(now.AddDate(0, 0, -34), now)
	projector := &localDashboardProjector{store: eventStore, tokenCache: cache}
	snapshot, err := projector.DashboardSnapshot(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.LocalSessions) != 1 || snapshot.LocalSessions[0].Project != "demo" {
		t.Fatalf("history: %+v", snapshot.LocalSessions)
	}
	if snapshot.TotalCalls != 0 || snapshot.TotalSessions != 0 || snapshot.ActiveSessions != 0 || len(snapshot.RecentSessions) != 0 {
		t.Fatalf("transcripts inflated audit totals: %+v", snapshot)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "/Users/private") || strings.Contains(string(data), "original-id") {
		t.Fatal("raw path or transcript identity exposed")
	}
}

func TestLocalHistoryDeduplicatesModelsBoundsAndSorts(t *testing.T) {
	now := time.Now().UTC()
	costs := []costanalytics.SessionCost{}
	for i := 0; i < 20; i++ {
		costs = append(costs, costanalytics.SessionCost{Agent: costanalytics.AgentCodex, SessionID: costanalytics.SessionID(fmt.Sprint(i)), Project: "/workspace/demo", StartedAt: now.Add(-time.Duration(i) * time.Hour)})
	}
	duplicate := costs[0]
	duplicate.Model = "another-model"
	costs = append(costs, duplicate)
	costs = append(costs, costanalytics.SessionCost{SessionID: "future", StartedAt: now.Add(time.Hour)})
	sessions := projectDashboardLocalSessions(costs, nil, now.AddDate(0, 0, -34), now.AddDate(0, 0, -34), now)
	if len(sessions) != grantctl.MaxDashboardSessions {
		t.Fatalf("count: %d", len(sessions))
	}
	seen := map[string]bool{}
	for i, session := range sessions {
		if seen[session.ID] {
			t.Fatal("duplicate session")
		}
		seen[session.ID] = true
		if i > 0 && session.StartedAtUnixMs > sessions[i-1].StartedAtUnixMs {
			t.Fatal("history unsorted")
		}
	}
}

func TestLocalHistoryPersistsAndLegacyCacheBackfills(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "cache.json")
	cache := newDashboardTokenCache(func(time.Time) ([]costanalytics.SessionCost, []error) {
		return []costanalytics.SessionCost{{Agent: costanalytics.AgentCodex, SessionID: "demo", Project: "/workspace/demo", StartedAt: now.Add(-time.Hour), InputTokens: 1}}, nil
	}, path)
	cache.refresh(now.AddDate(0, 0, -34), now)
	loaded := newDashboardTokenCache(nil, path)
	if len(loaded.localSessions) != 1 || loaded.loadedAt.IsZero() {
		t.Fatal("history cache not restored")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy dashboardTokenCacheFile
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.LocalSessions = nil
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded = newDashboardTokenCache(nil, path)
	if !loaded.loadedAt.IsZero() || len(loaded.points) == 0 {
		t.Fatal("legacy cache must retain tokens while requesting history backfill")
	}
}
