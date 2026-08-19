package daemonapp

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/hostconnector"
	"github.com/LuD1161/agentjail/internal/mcpgrant"
	"github.com/LuD1161/agentjail/internal/policyeval"
	"github.com/LuD1161/agentjail/internal/store"
)

const mcpGrantTestPolicy = `
package agentjail

import future.keywords.if

default decision = {"action": "allow", "reason": "default", "rule_id": "default"}

decision = {"action": "deny", "reason": "locked", "rule_id": "mcp_policy/blocked"} if {
    input.tool_name == "mcp__filesystem__read_file"
    input.tool_input.path == "/denied"
}

decision = {"action": "ask", "reason": "review MCP call", "rule_id": "mcp_policy/tool_ask"} if {
    input.tool_name == "mcp__filesystem__read_file"
    input.tool_input.path != "/denied"
}

decision = {"action": "ask", "reason": "review unknown MCP call", "rule_id": "mcp_policy/tool_ask"} if {
    startswith(input.tool_name, "mcp__")
    input.tool_name != "mcp__filesystem__read_file"
}
`

type mcpLifecycleAudit struct{}

func (mcpLifecycleAudit) EmitLifecycle(context.Context, grant.LifecycleEvent) error { return nil }

type readyMCPUpstream bool

func (u readyMCPUpstream) Available(context.Context, mcpgrant.ServerID) bool { return bool(u) }

type failingConnector struct{ calls int }

func (c *failingConnector) Use(context.Context, hostconnector.Binding, hostconnector.ConnectorID) (hostconnector.Use, error) {
	c.calls++
	return hostconnector.Use{}, errors.New("connector unavailable")
}

func newMCPGrantDaemon(t *testing.T, manager *grant.Manager, routes []MCPConnectorRoute, connectors connectorUser) (*server, string) {
	t.Helper()
	srv, socket := newTestServer(t)
	engine, err := policy.NewHookOPAEngine(context.Background(), [][2]string{{"mcp.rego", mcpGrantTestPolicy}})
	if err != nil {
		t.Fatal(err)
	}
	srv.evaluator = policyeval.New(engine, policy.NewLRUCache(policy.DefaultCacheSize), [][2]string{{"mcp.rego", mcpGrantTestPolicy}}, nil)
	servers, err := mcpgrant.NewStaticServers("filesystem")
	if err != nil {
		t.Fatal(err)
	}
	srv.mcpGrants = NewMCPGrantBoundary(servers, readyMCPUpstream(true), mcpgrant.NewManagerAuthority(manager), routes, connectors)
	srv.policyEpoch.Store(7)
	return srv, socket
}

func newMCPGrantManager(t *testing.T) *grant.Manager {
	t.Helper()
	manager, err := grant.NewManager(grant.ManagerConfig{Audit: mcpLifecycleAudit{}, Capacity: grant.Capacity{Global: 16, PerSession: 8}})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func activateDaemonMCPGrant(t *testing.T, manager *grant.Manager, scope grant.Scope) {
	t.Helper()
	principal, err := grant.NewPrincipal("claude", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	call, err := mcpgrant.NewCall("filesystem", "read_file", []byte(`{"path":"/allowed"}`))
	if err != nil {
		t.Fatal(err)
	}
	control := mcpgrant.NewControl(manager)
	pending, err := control.Request(context.Background(), principal, call, scope, 7, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.ApproveAndActivate(context.Background(), pending.ID(), "trusted-companion"); err != nil {
		t.Fatal(err)
	}
}

func mcpHookRequest(path string, meta interface{}) Request {
	input := map[string]interface{}{"path": path}
	if meta != nil {
		input["_meta"] = meta
	}
	return Request{ID: "mcp-grant", HookEvent: "PreToolUse", ToolName: "mcp__filesystem__read_file", ToolInput: input, SessionID: "session-a", CWD: "/repo", Agent: "claude"}
}

func TestDaemonMCPGrantPreservesCanonicalAskAndConsumesOnceAtResponse(t *testing.T) {
	manager := newMCPGrantManager(t)
	activateDaemonMCPGrant(t, manager, grant.OnceScope())
	srv, socket := newMCPGrantDaemon(t, manager, nil, nil)
	decisionStore, err := store.Open(filepath.Join(t.TempDir(), "decisions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = decisionStore.Close() })
	srv.eventStore = decisionStore
	srv.decCh = make(chan store.DecisionRecord, 2)

	allowed := sendRequest(t, socket, mcpHookRequest("/allowed", map[string]interface{}{"progressToken": "opaque"}))
	if allowed.Action != "allow" || allowed.PolicyAction != "ask" || allowed.EffectiveAction != "allow" || allowed.Adapter != "mcp_runtime_grant" {
		t.Fatalf("runtime grant lost canonical/effective separation: %#v", allowed)
	}
	row := <-srv.decCh
	if row.Action != "allow" || row.PolicyAction != "ask" || row.EffectiveAction != "allow" || row.Adapter != "mcp_runtime_grant" {
		t.Fatalf("decision row lost canonical/effective separation: %#v", row)
	}
	replayed := sendRequest(t, socket, mcpHookRequest("/allowed", nil))
	if replayed.Action != "deny" || replayed.PolicyAction != "ask" || replayed.EffectiveAction != "deny" || replayed.Adapter != "mcp_runtime_grant" {
		t.Fatalf("once grant replay did not fail closed: %#v", replayed)
	}
}

func TestDaemonMCPGrantFailsClosedWithoutGrantOrValidArguments(t *testing.T) {
	manager := newMCPGrantManager(t)
	_, socket := newMCPGrantDaemon(t, manager, nil, nil)
	for _, request := range []Request{
		mcpHookRequest("/allowed", nil),
		mcpHookRequest("/allowed", "not-an-object"),
		{ID: "unknown", HookEvent: "PreToolUse", ToolName: "mcp__unknown__read_file", ToolInput: map[string]interface{}{}, SessionID: "session-a", CWD: "/repo", Agent: "claude"},
	} {
		response := sendRequest(t, socket, request)
		if response.Action != "deny" || response.PolicyAction != "ask" || response.EffectiveAction != "deny" || response.Adapter != "mcp_runtime_grant" {
			t.Fatalf("MCP grant failure was not fail-closed: request=%#v response=%#v", request, response)
		}
	}
}

func TestDaemonMCPGrantKeepsCanonicalDenyPrecedence(t *testing.T) {
	manager := newMCPGrantManager(t)
	activateDaemonMCPGrant(t, manager, grant.SessionScope())
	_, socket := newMCPGrantDaemon(t, manager, nil, nil)
	response := sendRequest(t, socket, mcpHookRequest("/denied", nil))
	if response.Action != "deny" || response.PolicyAction != "deny" || response.Adapter == "mcp_runtime_grant" {
		t.Fatalf("canonical deny was changed by grant boundary: %#v", response)
	}
}

func TestDaemonMCPGrantRequiresConfiguredConnectorUseProof(t *testing.T) {
	manager := newMCPGrantManager(t)
	activateDaemonMCPGrant(t, manager, grant.OnceScope())
	connector := &failingConnector{}
	_, socket := newMCPGrantDaemon(t, manager, []MCPConnectorRoute{{Server: "filesystem", Connector: "browser-cdp"}}, connector)
	response := sendRequest(t, socket, mcpHookRequest("/allowed", nil))
	if connector.calls != 1 || response.Action != "deny" || response.PolicyAction != "ask" || response.EffectiveAction != "deny" || response.Adapter != "mcp_runtime_grant" {
		t.Fatalf("connector failure was not enforced at boundary: calls=%d response=%#v", connector.calls, response)
	}
}

func TestDaemonMCPGrantConfiguredConnectorWithoutDataPlaneLeaseStaysDenied(t *testing.T) {
	manager := newMCPGrantManager(t)
	activateDaemonMCPGrant(t, manager, grant.OnceScope())
	_, socket := newMCPGrantDaemon(t, manager, []MCPConnectorRoute{{Server: "filesystem", Connector: "filesystem"}}, nil)
	response := sendRequest(t, socket, mcpHookRequest("/allowed", nil))
	if response.Action != "deny" || response.PolicyAction != "ask" || response.EffectiveAction != "deny" || response.Adapter != "mcp_runtime_grant" {
		t.Fatalf("configured connector without a grant-aware data-plane lease was allowed: %#v", response)
	}
}

func TestDaemonMCPGrantReloadEpochInvalidatesSharedAuthority(t *testing.T) {
	manager := newMCPGrantManager(t)
	activateDaemonMCPGrant(t, manager, grant.SessionScope())
	srv, socket := newMCPGrantDaemon(t, manager, nil, nil)
	srv.policyEpoch.Store(8)
	response := sendRequest(t, socket, mcpHookRequest("/allowed", nil))
	if response.Action != "deny" || response.PolicyAction != "ask" || response.EffectiveAction != "deny" || response.Adapter != "mcp_runtime_grant" {
		t.Fatalf("reload epoch did not invalidate MCP grant: %#v", response)
	}
}
