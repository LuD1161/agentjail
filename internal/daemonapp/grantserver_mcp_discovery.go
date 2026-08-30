package daemonapp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/audit"
	"github.com/LuD1161/agentjail/internal/grantctl"
	"github.com/LuD1161/agentjail/internal/mcpclient"
	"github.com/LuD1161/agentjail/internal/store"
)

type mcpToolDiscoveryService interface {
	Discover(context.Context, time.Time) (grantctl.MCPToolsDiscoveryV1, error)
}

type localMCPToolDiscoveryService struct {
	store store.EventStore
	mu    sync.Mutex
}

func newLocalMCPToolDiscoveryService(eventStore store.EventStore) mcpToolDiscoveryService {
	if eventStore == nil {
		return nil
	}
	return &localMCPToolDiscoveryService{store: eventStore}
}

func (s *localMCPToolDiscoveryService) Discover(ctx context.Context, _ time.Time) (discovery grantctl.MCPToolsDiscoveryV1, resultErr error) {
	if !s.mu.TryLock() {
		return grantctl.MCPToolsDiscoveryV1{}, fmt.Errorf("MCP tool discovery already in progress")
	}
	defer s.mu.Unlock()
	defer func() {
		if resultErr == nil {
			return
		}
		slog.Warn("MCP tool discovery failed")
		if err := s.store.Emit(ctx, audit.Event{EventType: audit.MCPDiscoveryFailed, Actor: "cli"}); err != nil {
			slog.Warn("audit emit failed for MCP discovery failure", "error", err)
		}
	}()

	slog.Info("MCP tool discovery started")
	if err := s.store.Emit(ctx, audit.Event{EventType: audit.MCPDiscoveryStarted, Actor: "cli"}); err != nil {
		slog.Warn("audit emit failed for MCP discovery start", "error", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return grantctl.MCPToolsDiscoveryV1{}, fmt.Errorf("resolve home for MCP discovery: %w", err)
	}
	entries := mcpclient.DiscoverServersWithConfig(home)
	configs := make([]mcpclient.MCPServerConfig, 0, len(entries))
	for _, entry := range entries {
		configs = append(configs, entry.Config)
	}
	results := mcpclient.ListAllTools(ctx, configs)

	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 64 {
		names = names[:64]
	}

	discovery = grantctl.MCPToolsDiscoveryV1{
		ProtocolVersion: grantctl.MCPDiscoveryProtocolVersion,
		Servers:         make([]grantctl.MCPServerToolsDiscoveryV1, 0, len(names)),
	}
	for _, name := range names {
		result := results[name]
		server := grantctl.MCPServerToolsDiscoveryV1{
			Server: boundedDashboardLabel(name, grantctl.MaxDashboardLabelBytes),
			Status: grantctl.MCPDiscoveryStatus(result.Status),
			Tools:  make([]string, 0, min(len(result.Tools), 128)),
		}
		seen := make(map[string]struct{})
		for _, info := range result.Tools {
			tool := boundedDashboardLabel(info.Name, grantctl.MaxDashboardLabelBytes)
			if tool == "" {
				continue
			}
			if _, exists := seen[tool]; exists {
				continue
			}
			seen[tool] = struct{}{}
			server.Tools = append(server.Tools, tool)
			if len(server.Tools) == 128 {
				break
			}
		}
		sort.Strings(server.Tools)
		for _, tool := range server.Tools {
			if err := s.store.UpsertDiscoveredTool(ctx, server.Server, tool, "live"); err != nil {
				return grantctl.MCPToolsDiscoveryV1{}, fmt.Errorf("persist enumerated MCP tool: %w", err)
			}
		}
		discovery.Servers = append(discovery.Servers, server)
	}

	connected := 0
	for _, server := range discovery.Servers {
		if server.Status == grantctl.MCPDiscoveryConnected {
			connected++
		}
	}
	slog.Info("MCP tool discovery completed", "servers", len(discovery.Servers), "connected", connected)
	if err := s.store.Emit(ctx, audit.Event{
		EventType: audit.MCPDiscoveryCompleted,
		Actor:     "cli",
		Detail: map[string]string{
			"servers":   fmt.Sprintf("%d", len(discovery.Servers)),
			"connected": fmt.Sprintf("%d", connected),
		},
	}); err != nil {
		slog.Warn("audit emit failed for MCP discovery completion", "error", err)
	}
	return discovery, nil
}

func mcpToolsDiscoveryResponse(service mcpToolDiscoveryService, version grantctl.ProtocolVersion, now time.Time) grantctl.Response {
	if version != grantctl.MCPDiscoveryProtocolVersion {
		return grantctl.Response{OK: false, Error: "mcp_tools_discover requires supported protocol_version"}
	}
	if service == nil {
		return grantctl.Response{OK: false, Error: "MCP tool discovery unavailable"}
	}
	discovery, err := service.Discover(context.Background(), now)
	if err != nil {
		return grantctl.Response{OK: false, Error: "MCP tool discovery failed"}
	}
	return grantctl.Response{OK: true, MCPToolsDiscovery: &discovery}
}
