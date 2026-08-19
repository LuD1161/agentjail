package daemonapp

import (
	"context"
	"errors"
	"os"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/hostconnector"
	"github.com/LuD1161/agentjail/internal/mcpclient"
	"github.com/LuD1161/agentjail/internal/mcpgrant"
	"github.com/LuD1161/agentjail/internal/policyeval"
)

// MCPGrantBoundary is the hook-side enforcement point for configured MCP
// calls. It authorizes the agent's request; it is not an MCP wire proxy.
// See ADR 0141-runtime-grants and ADR 0003-mcp-reverse-proxy.
type MCPGrantBoundary struct {
	gate       mcpgrant.Gate
	routes     map[mcpgrant.ServerID]hostconnector.ConnectorID
	connectors connectorUser
}

type connectorUser interface {
	Use(context.Context, hostconnector.Binding, hostconnector.ConnectorID) (hostconnector.Use, error)
}

// MCPConnectorRoute is fixed host-owned startup configuration. The hook never
// accepts a connector ID or host destination from the agent.
type MCPConnectorRoute struct {
	Server    mcpgrant.ServerID
	Connector hostconnector.ConnectorID
}

// NewMCPGrantBoundary builds a static MCP authorization boundary. Passing a
// nil authority deliberately leaves canonical MCP asks denied, rather than
// treating hook visibility or a retry as approval.
func NewMCPGrantBoundary(servers mcpgrant.ServerRegistry, upstream mcpgrant.Upstream, authority mcpgrant.Authority, routes []MCPConnectorRoute, connectors connectorUser) *MCPGrantBoundary {
	routeMap := make(map[mcpgrant.ServerID]hostconnector.ConnectorID, len(routes))
	for _, route := range routes {
		if route.Server != "" && route.Connector != "" {
			routeMap[route.Server] = route.Connector
		}
	}
	return &MCPGrantBoundary{gate: mcpgrant.NewGate(servers, upstream, authority), routes: routeMap, connectors: connectors}
}

// configuredMCPGrantBoundary takes exact server identities only from the
// agent's startup configuration. Policy globs do not register a server.
func configuredMCPGrantBoundary(authority mcpgrant.Authority, cfg *agentconfig.PolicyConfig) *MCPGrantBoundary {
	home, err := os.UserHomeDir()
	if err != nil {
		return NewMCPGrantBoundary(emptyMCPServers{}, configuredMCPUpstream{}, authority, nil, nil)
	}
	entries := mcpclient.DiscoverServersWithConfig(home)
	servers := make([]mcpgrant.ServerID, 0, len(entries))
	for _, entry := range entries {
		candidate := mcpgrant.ServerID(entry.Name)
		if _, err := mcpgrant.NewStaticServers(candidate); err == nil {
			servers = append(servers, candidate)
		}
	}
	registry, err := mcpgrant.NewStaticServers(servers...)
	if err != nil {
		return NewMCPGrantBoundary(emptyMCPServers{}, configuredMCPUpstream{}, authority, nil, nil)
	}
	return NewMCPGrantBoundary(registry, configuredMCPUpstream{}, authority, configuredMCPConnectorRoutes(cfg), nil)
}

// configuredMCPConnectorRoutes maps only exact, fixed MCP connector IDs to
// matching configured MCP server IDs. The daemon has no netproxy control token
// or session transport, so a route with no trusted Use proof remains denied.
func configuredMCPConnectorRoutes(cfg *agentconfig.PolicyConfig) []MCPConnectorRoute {
	if cfg == nil {
		return nil
	}
	connectors, err := cfg.Network.ConfiguredHostConnectors()
	if err != nil {
		return nil
	}
	routes := make([]MCPConnectorRoute, 0, len(connectors))
	for _, connector := range connectors {
		if connector.Transport() != hostconnector.TransportMCP {
			continue
		}
		server := mcpgrant.ServerID(connector.ID())
		if _, err := mcpgrant.NewStaticServers(server); err != nil {
			continue
		}
		routes = append(routes, MCPConnectorRoute{Server: server, Connector: connector.ID()})
	}
	return routes
}

type configuredMCPUpstream struct{}

// A configured MCP client owns transport reachability. The hook has no wire
// receipt, so this only attests startup configuration, never a proxy forward.
func (configuredMCPUpstream) Available(context.Context, mcpgrant.ServerID) bool { return true }

type emptyMCPServers struct{}

func (emptyMCPServers) Configured(mcpgrant.ServerID) bool { return false }

type mcpGrantResolution struct {
	lease mcpgrant.ForwardLease
}

func (b *MCPGrantBoundary) check(ctx context.Context, req policyeval.Request, epoch grant.PolicyEpoch, canonical string) (mcpGrantResolution, mcpgrant.Result, error) {
	if b == nil || canonical != string(mcpgrant.PolicyAsk) {
		return mcpGrantResolution{}, mcpgrant.Result{}, nil
	}
	principal, err := grant.NewPrincipal(grant.PrincipalID(req.Agent), grant.SessionID(req.SessionID))
	if err != nil {
		return mcpGrantResolution{}, mcpgrant.Result{}, err
	}
	call, err := mcpgrant.ParseHookCall(req.ToolName, req.ToolInput)
	if err != nil {
		return mcpGrantResolution{}, mcpgrant.Result{}, err
	}
	result := b.gate.Check(ctx, principal, epoch, mcpgrant.PolicyAsk, call)
	if result.Final != mcpgrant.FinalForwardAuthorized || result.Effective != mcpgrant.EffectiveGrantAllow {
		return mcpGrantResolution{}, result, nil
	}
	if connectorID, routed := b.routes[call.Server()]; routed {
		if b.connectors == nil {
			if result.Lease != nil {
				_ = result.Lease.Rollback(ctx)
			}
			return mcpGrantResolution{}, result, errors.New("configured MCP connector is unavailable")
		}
		binding, err := hostconnector.NewBinding(principal)
		if err != nil {
			if result.Lease != nil {
				_ = result.Lease.Rollback(ctx)
			}
			return mcpGrantResolution{}, result, err
		}
		if _, err := b.connectors.Use(ctx, binding, connectorID); err != nil {
			if result.Lease != nil {
				_ = result.Lease.Rollback(ctx)
			}
			return mcpGrantResolution{}, result, err
		}
	}
	return mcpGrantResolution{lease: result.Lease}, result, nil
}

// commit is called at the final hook allow response. Hooks provide no honest
// forwarding receipt, so the boundary never rolls back after this point.
func (r mcpGrantResolution) commit(ctx context.Context) error {
	if r.lease == nil {
		return nil
	}
	return r.lease.Confirm(ctx, mcpgrant.ForwardingBegan)
}
