package daemonapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LuD1161/agentjail/internal/costanalytics"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/procutil"
	"github.com/LuD1161/agentjail/internal/store"
)

type dashboardSnapshotProjector interface {
	DashboardSnapshot(context.Context, time.Time) (grantctl.DashboardSnapshotV1, error)
}

type localDashboardProjector struct {
	store          store.EventStore
	activeSessions *activeTracker
	tokenCache     *dashboardTokenCache
}

func newLocalDashboardProjector(eventStore store.EventStore, activeSessions *activeTracker) dashboardSnapshotProjector {
	if eventStore == nil {
		return nil
	}
	return &localDashboardProjector{
		store: eventStore, activeSessions: activeSessions,
		tokenCache: newDashboardTokenCache(costanalytics.CollectAll, defaultDashboardTokenCachePath()),
	}
}

const dashboardTokenCacheTTL = 5 * time.Minute

type dashboardTokenCache struct {
	mu         sync.Mutex
	collect    func(time.Time) ([]costanalytics.SessionCost, []error)
	points     []grantctl.DashboardTokenDayV1
	agents     []grantctl.DashboardTokenAgentV1
	agentDays  []dashboardTokenAgentDay
	loadedAt   time.Time
	refreshing bool
	path       string
}

type dashboardTokenAgentDay struct {
	Day          string `json:"day"`
	Agent        string `json:"agent"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	CacheTokens  int64  `json:"cache_tokens"`
}

type dashboardTokenCacheFile struct {
	Version   int                              `json:"version"`
	LoadedAt  time.Time                        `json:"loaded_at"`
	Points    []grantctl.DashboardTokenDayV1   `json:"points"`
	Agents    []grantctl.DashboardTokenAgentV1 `json:"agents"`
	AgentDays []dashboardTokenAgentDay         `json:"agent_days"`
}

func defaultDashboardTokenCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agentjail", "cache", "dashboard-tokens-v1.json")
}

func newDashboardTokenCache(collect func(time.Time) ([]costanalytics.SessionCost, []error), paths ...string) *dashboardTokenCache {
	cache := &dashboardTokenCache{collect: collect}
	if len(paths) > 0 {
		cache.path = paths[0]
		cache.load()
	}
	return cache
}

func (c *dashboardTokenCache) snapshot(since, now time.Time) ([]grantctl.DashboardTokenDayV1, []grantctl.DashboardTokenAgentV1, grantctl.DashboardTokenStatus) {
	c.mu.Lock()
	if !c.refreshing && (c.loadedAt.IsZero() || now.Sub(c.loadedAt) >= dashboardTokenCacheTTL) {
		c.refreshing = true
		go c.refresh(since, now)
	}
	points := append(make([]grantctl.DashboardTokenDayV1, 0, len(c.points)), c.points...)
	agents := append(make([]grantctl.DashboardTokenAgentV1, 0, len(c.agents)), c.agents...)
	status := grantctl.DashboardTokensReady
	if c.refreshing {
		status = grantctl.DashboardTokensLoading
	}
	c.mu.Unlock()
	return points, agents, status
}

func (c *dashboardTokenCache) refresh(since, now time.Time) {
	c.mu.Lock()
	refreshSince := since
	previousPoints := append([]grantctl.DashboardTokenDayV1(nil), c.points...)
	previousAgentDays := append([]dashboardTokenAgentDay(nil), c.agentDays...)
	if !c.loadedAt.IsZero() && len(previousPoints) > 0 {
		refreshSince = now.UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
		if refreshSince.Before(since) {
			refreshSince = since
		}
	}
	c.mu.Unlock()

	costs, errs := c.collect(refreshSince)
	if len(costs) == 0 && len(errs) > 0 && len(previousPoints) > 0 {
		c.mu.Lock()
		c.loadedAt = now
		c.refreshing = false
		c.mu.Unlock()
		return
	}
	points, agents, agentDays := aggregateDashboardTokenDetails(costs, refreshSince, now)
	if refreshSince.After(since) {
		points = mergeDashboardTokenDays(previousPoints, points, refreshSince, since, now)
		agentDays = mergeDashboardTokenAgentDays(previousAgentDays, agentDays, refreshSince, since, now)
		agents = aggregateDashboardTokenAgents(agentDays)
	}
	c.mu.Lock()
	c.points = points
	c.agents = agents
	c.agentDays = agentDays
	c.loadedAt = now
	c.refreshing = false
	cacheFile := dashboardTokenCacheFile{
		Version: 1, LoadedAt: c.loadedAt,
		Points:    append([]grantctl.DashboardTokenDayV1(nil), c.points...),
		Agents:    append([]grantctl.DashboardTokenAgentV1(nil), c.agents...),
		AgentDays: append([]dashboardTokenAgentDay(nil), c.agentDays...),
	}
	c.mu.Unlock()
	c.save(cacheFile)
}

func (c *dashboardTokenCache) load() {
	if c.path == "" {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil || len(data) > 512*1024 {
		return
	}
	var cached dashboardTokenCacheFile
	if json.Unmarshal(data, &cached) != nil || !validDashboardTokenCacheFile(cached) {
		return
	}
	c.points = cached.Points
	c.agents = cached.Agents
	c.agentDays = cached.AgentDays
	c.loadedAt = cached.LoadedAt
}

func (c *dashboardTokenCache) save(cached dashboardTokenCacheFile) {
	if c.path == "" {
		return
	}
	data, err := json.Marshal(cached)
	if err != nil || len(data) > 512*1024 || os.MkdirAll(filepath.Dir(c.path), 0o700) != nil {
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".dashboard-tokens-*")
	if err != nil {
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeAllAndSync(temporary, data) != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return
	}
	_ = os.Rename(temporaryPath, c.path)
}

func writeAllAndSync(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func validDashboardTokenCacheFile(cached dashboardTokenCacheFile) bool {
	if cached.Version != 1 || cached.LoadedAt.IsZero() || len(cached.Points) > 35 || len(cached.Agents) > 8 || len(cached.AgentDays) > 280 {
		return false
	}
	for _, point := range cached.Points {
		if len(point.Day) != 10 || point.InputTokens < 0 || point.OutputTokens < 0 || point.CacheTokens < 0 {
			return false
		}
	}
	for _, agent := range cached.Agents {
		if agent.Agent == "" || len(agent.Agent) > grantctl.MaxDashboardLabelBytes || agent.InputTokens < 0 || agent.OutputTokens < 0 || agent.CacheTokens < 0 {
			return false
		}
	}
	for _, point := range cached.AgentDays {
		if len(point.Day) != 10 || point.Agent == "" || len(point.Agent) > grantctl.MaxDashboardLabelBytes || point.InputTokens < 0 || point.OutputTokens < 0 || point.CacheTokens < 0 {
			return false
		}
	}
	return true
}

func (p *localDashboardProjector) DashboardSnapshot(ctx context.Context, now time.Time) (grantctl.DashboardSnapshotV1, error) {
	since := now.AddDate(0, 0, -34)
	stats, err := p.store.ComputeStats(ctx, since)
	if err != nil {
		return grantctl.DashboardSnapshotV1{}, fmt.Errorf("compute dashboard stats: %w", err)
	}
	sessions, err := p.store.ListSessionsFiltered(ctx, store.SessionFilter{Since: 35 * 24 * time.Hour, Limit: grantctl.MaxDashboardSessions})
	if err != nil {
		return grantctl.DashboardSnapshotV1{}, fmt.Errorf("list dashboard sessions: %w", err)
	}
	discoveredTools, err := p.store.ListDiscoveredTools(ctx, "")
	if err != nil {
		return grantctl.DashboardSnapshotV1{}, fmt.Errorf("list dashboard MCP tools: %w", err)
	}
	auditedToolNames, err := p.store.ListDistinctMCPToolNames(ctx)
	if err != nil {
		return grantctl.DashboardSnapshotV1{}, fmt.Errorf("list audited dashboard MCP tools: %w", err)
	}

	active := make(map[string]struct{})
	if p.activeSessions != nil {
		for _, entry := range p.activeSessions.list() {
			if procutil.Alive(entry.PID) {
				active[entry.SessionID] = struct{}{}
			}
		}
	}
	snapshot := grantctl.DashboardSnapshotV1{
		ProtocolVersion:   grantctl.DashboardProtocolVersion,
		GeneratedAtUnixMs: grantctl.UnixMilliseconds(now.UnixMilli()),
		TotalCalls:        stats.Total, AllowedCalls: stats.Allow, DeniedCalls: stats.Deny, AskedCalls: stats.Ask,
		TotalSessions: stats.Sessions, ActiveSessions: len(active),
		RecentSessions: make([]grantctl.DashboardSessionV1, 0, len(sessions)),
		Activity:       make([]grantctl.DashboardDayV1, 0, len(stats.Daily)),
		MCPTools:       dashboardMCPTools(discoveredTools, auditedToolNames),
		TokenCoverage:  []string{"Claude Code", "Codex", "OpenCode"},
		TokenAgents:    make([]grantctl.DashboardTokenAgentV1, 0),
	}
	for _, session := range sessions {
		_, isActive := active[session.SessionID]
		projected := grantctl.DashboardSessionV1{
			SessionID:       boundedDashboardLabel(session.SessionID, grantctl.MaxDashboardSessionIDBytes),
			Agent:           boundedDashboardLabel(session.Agent, grantctl.MaxDashboardLabelBytes),
			Project:         dashboardProjectName(session.CWD),
			StartedAtUnixMs: grantctl.UnixMilliseconds(session.StartTs.UnixMilli()),
			AuditedCalls:    session.DecisionCount, Active: isActive,
		}
		if !session.EndTs.IsZero() {
			projected.EndedAtUnixMs = grantctl.UnixMilliseconds(session.EndTs.UnixMilli())
		}
		snapshot.RecentSessions = append(snapshot.RecentSessions, projected)
	}
	for _, day := range stats.Daily {
		snapshot.Activity = append(snapshot.Activity, grantctl.DashboardDayV1{Day: day.Day, Count: day.Count})
	}

	snapshot.Tokens, snapshot.TokenAgents, snapshot.TokenStatus = p.tokenCache.snapshot(since, now)
	return snapshot, nil
}

func dashboardMCPTools(discovered []store.DiscoveredTool, auditedToolNames []string) []grantctl.DashboardMCPToolsV1 {
	byServer := make(map[string]map[string]struct{})
	for _, entry := range discovered {
		addDashboardMCPTool(byServer, entry.Server, entry.Tool)
	}
	for _, name := range auditedToolNames {
		rest, ok := strings.CutPrefix(name, "mcp__")
		if !ok {
			continue
		}
		server, tool, ok := strings.Cut(rest, "__")
		if !ok {
			continue
		}
		addDashboardMCPTool(byServer, server, tool)
	}
	servers := make([]string, 0, len(byServer))
	for server := range byServer {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	if len(servers) > 64 {
		servers = servers[:64]
	}
	out := make([]grantctl.DashboardMCPToolsV1, 0, len(servers))
	for _, server := range servers {
		tools := make([]string, 0, len(byServer[server]))
		for tool := range byServer[server] {
			tools = append(tools, tool)
		}
		sort.Strings(tools)
		out = append(out, grantctl.DashboardMCPToolsV1{Server: server, Tools: tools})
	}
	return out
}

func addDashboardMCPTool(byServer map[string]map[string]struct{}, rawServer, rawTool string) {
	server := boundedDashboardLabel(rawServer, grantctl.MaxDashboardLabelBytes)
	tool := boundedDashboardLabel(rawTool, grantctl.MaxDashboardLabelBytes)
	if server == "" || tool == "" {
		return
	}
	if byServer[server] == nil {
		byServer[server] = make(map[string]struct{})
	}
	if len(byServer[server]) < 128 {
		byServer[server][tool] = struct{}{}
	}
}

func aggregateDashboardTokens(costs []costanalytics.SessionCost, since, now time.Time) ([]grantctl.DashboardTokenDayV1, []grantctl.DashboardTokenAgentV1) {
	points, agents, _ := aggregateDashboardTokenDetails(costs, since, now)
	return points, agents
}

func aggregateDashboardTokenDetails(costs []costanalytics.SessionCost, since, now time.Time) ([]grantctl.DashboardTokenDayV1, []grantctl.DashboardTokenAgentV1, []dashboardTokenAgentDay) {
	byDay := make(map[string]*grantctl.DashboardTokenDayV1)
	byAgentDay := make(map[string]*dashboardTokenAgentDay)
	for _, cost := range costs {
		if cost.StartedAt.Before(since) || cost.StartedAt.After(now) {
			continue
		}
		day := cost.StartedAt.UTC().Format("2006-01-02")
		point := byDay[day]
		if point == nil {
			point = &grantctl.DashboardTokenDayV1{Day: day}
			byDay[day] = point
		}
		point.InputTokens += cost.InputTokens
		point.OutputTokens += cost.OutputTokens
		point.CacheTokens += cost.CacheRead + cost.CacheWrite
		agent := string(cost.Agent)
		if agent == "" {
			agent = string(cost.Source)
		}
		agentKey := day + "\x00" + agent
		agentPoint := byAgentDay[agentKey]
		if agentPoint == nil {
			agentPoint = &dashboardTokenAgentDay{Day: day, Agent: agent}
			byAgentDay[agentKey] = agentPoint
		}
		agentPoint.InputTokens += cost.InputTokens
		agentPoint.OutputTokens += cost.OutputTokens
		agentPoint.CacheTokens += cost.CacheRead + cost.CacheWrite
	}
	days := make([]string, 0, len(byDay))
	for day := range byDay {
		days = append(days, day)
	}
	sort.Strings(days)
	points := make([]grantctl.DashboardTokenDayV1, 0, len(days))
	for _, day := range days {
		points = append(points, *byDay[day])
	}
	agentDays := make([]dashboardTokenAgentDay, 0, len(byAgentDay))
	for _, point := range byAgentDay {
		agentDays = append(agentDays, *point)
	}
	sort.Slice(agentDays, func(i, j int) bool {
		if agentDays[i].Day == agentDays[j].Day {
			return agentDays[i].Agent < agentDays[j].Agent
		}
		return agentDays[i].Day < agentDays[j].Day
	})
	return points, aggregateDashboardTokenAgents(agentDays), agentDays
}

func aggregateDashboardTokenAgents(days []dashboardTokenAgentDay) []grantctl.DashboardTokenAgentV1 {
	byAgent := make(map[string]*grantctl.DashboardTokenAgentV1)
	for _, day := range days {
		point := byAgent[day.Agent]
		if point == nil {
			point = &grantctl.DashboardTokenAgentV1{Agent: day.Agent}
			byAgent[day.Agent] = point
		}
		point.InputTokens += day.InputTokens
		point.OutputTokens += day.OutputTokens
		point.CacheTokens += day.CacheTokens
	}
	agents := make([]grantctl.DashboardTokenAgentV1, 0, len(byAgent))
	for _, point := range byAgent {
		agents = append(agents, *point)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Agent < agents[j].Agent })
	return agents
}

func mergeDashboardTokenDays(previous, current []grantctl.DashboardTokenDayV1, refreshedSince, since, now time.Time) []grantctl.DashboardTokenDayV1 {
	byDay := make(map[string]grantctl.DashboardTokenDayV1)
	cutoff := refreshedSince.UTC().Format("2006-01-02")
	first := since.UTC().Format("2006-01-02")
	last := now.UTC().Format("2006-01-02")
	for _, point := range previous {
		if point.Day >= first && point.Day <= last && point.Day < cutoff {
			byDay[point.Day] = point
		}
	}
	for _, point := range current {
		byDay[point.Day] = point
	}
	days := make([]string, 0, len(byDay))
	for day := range byDay {
		days = append(days, day)
	}
	sort.Strings(days)
	points := make([]grantctl.DashboardTokenDayV1, 0, len(days))
	for _, day := range days {
		points = append(points, byDay[day])
	}
	return points
}

func mergeDashboardTokenAgentDays(previous, current []dashboardTokenAgentDay, refreshedSince, since, now time.Time) []dashboardTokenAgentDay {
	byKey := make(map[string]dashboardTokenAgentDay)
	cutoff := refreshedSince.UTC().Format("2006-01-02")
	first := since.UTC().Format("2006-01-02")
	last := now.UTC().Format("2006-01-02")
	for _, point := range previous {
		if point.Day >= first && point.Day <= last && point.Day < cutoff {
			byKey[point.Day+"\x00"+point.Agent] = point
		}
	}
	for _, point := range current {
		byKey[point.Day+"\x00"+point.Agent] = point
	}
	points := make([]dashboardTokenAgentDay, 0, len(byKey))
	for _, point := range byKey {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Day == points[j].Day {
			return points[i].Agent < points[j].Agent
		}
		return points[i].Day < points[j].Day
	})
	return points
}

func dashboardProjectName(cwd string) string {
	if cwd == "" {
		return "Unknown project"
	}
	name := filepath.Base(filepath.Clean(cwd))
	if name == "." || name == string(filepath.Separator) {
		return "Unknown project"
	}
	return boundedDashboardLabel(name, grantctl.MaxDashboardLabelBytes)
}

func boundedDashboardLabel(value string, limit int) string {
	if value == "" {
		return "Unknown"
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func dashboardSnapshotResponse(projector dashboardSnapshotProjector, version grantctl.ProtocolVersion, now time.Time) grantctl.Response {
	if version == 0 {
		return grantctl.Response{OK: false, Error: "dashboard_snapshot requires protocol_version"}
	}
	if version != grantctl.DashboardProtocolVersion {
		return grantctl.Response{OK: false, Error: fmt.Sprintf("unsupported dashboard protocol version %d", version)}
	}
	if projector == nil {
		return grantctl.Response{OK: false, Error: "dashboard snapshot unavailable"}
	}
	snapshot, err := projector.DashboardSnapshot(context.Background(), now)
	if err != nil {
		return grantctl.Response{OK: false, Error: "dashboard snapshot unavailable"}
	}
	return grantctl.Response{OK: true, DashboardSnapshot: &snapshot}
}
