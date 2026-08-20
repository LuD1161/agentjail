package test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/hostconnector"
	"github.com/LuD1161/agentjail/internal/mcpgrant"
)

// This is a deterministic composition fixture for the shipped boundaries.
// See ADR 0141-runtime-grants.
type grantsE2EClock struct{ now time.Time }

func (c *grantsE2EClock) Now() time.Time { return c.now }

type grantsE2EAudit struct{}

func (grantsE2EAudit) EmitLifecycle(context.Context, grant.LifecycleEvent) error { return nil }

type grantsE2EConnectorAudit struct{}

func (grantsE2EConnectorAudit) Record(context.Context, hostconnector.Transition) error { return nil }

type exactNetworkAdapter struct{}

func (exactNetworkAdapter) Kind() grant.ResourceKind                              { return grant.ResourceNetwork }
func (exactNetworkAdapter) Canonicalize(r grant.Resource) (grant.Resource, error) { return r, nil }
func (exactNetworkAdapter) Equivalent(left, right grant.Resource) bool {
	return left.Kind() == right.Kind() && left.ID() == right.ID()
}
func (a exactNetworkAdapter) Covers(granted, requested grant.Resource) bool {
	return a.Equivalent(granted, requested)
}
func (exactNetworkAdapter) ActivationFor(grant.Action, grant.Resource) (grant.ActivationRequirement, error) {
	return grant.ActivationRequired, nil
}

type connectorAccessFactory struct {
	principal grant.Principal
	epoch     grant.PolicyEpoch
}

func (f connectorAccessFactory) Access(binding hostconnector.Binding, id hostconnector.ConnectorID) (grant.Access, error) {
	if binding.Principal().ID() != f.principal.ID() || binding.Principal().SessionID() != f.principal.SessionID() || id != "chrome-cdp" {
		return grant.Access{}, errors.New("unexpected connector binding")
	}
	resource, err := grant.NewResource(grant.ResourceNetwork, "connector:chrome-cdp")
	if err != nil {
		return grant.Access{}, err
	}
	return grant.NewAccess(f.principal, grant.ActionConnect, resource, f.epoch)
}

type fixedUpstream bool

func (u fixedUpstream) Available(context.Context, mcpgrant.ServerID) bool { return bool(u) }

func newGrantsE2EManager(t *testing.T, clock grant.Clock) *grant.Manager {
	t.Helper()
	manager, err := grant.NewManager(grant.ManagerConfig{
		Clock: clock, Audit: grantsE2EAudit{}, Capacity: grant.Capacity{Global: 32, PerSession: 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func approveMCP(t *testing.T, manager *grant.Manager, principal grant.Principal, call mcpgrant.Call, scope grant.Scope, epoch grant.PolicyEpoch, now time.Time) grant.Grant {
	t.Helper()
	control := mcpgrant.NewControl(manager)
	pending, err := control.Request(context.Background(), principal, call, scope, epoch, now)
	if err != nil {
		t.Fatal(err)
	}
	active, err := control.ApproveAndActivate(context.Background(), pending.ID(), "trusted-operator")
	if err != nil {
		t.Fatal(err)
	}
	if active.State() != grant.StateActive {
		t.Fatalf("trusted approval did not activate MCP grant: %q", active.State())
	}
	return active
}

func approveConnector(t *testing.T, manager *grant.Manager, principal grant.Principal, scope grant.Scope, epoch grant.PolicyEpoch, now time.Time) {
	t.Helper()
	resource, err := grant.NewResource(grant.ResourceNetwork, "connector:chrome-cdp")
	if err != nil {
		t.Fatal(err)
	}
	adapted, err := grant.AdaptResource(exactNetworkAdapter{}, grant.ActionConnect, resource)
	if err != nil {
		t.Fatal(err)
	}
	request, err := grant.NewRequest(principal, grant.ActionConnect, adapted, scope, epoch, now)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := grant.NewCanonicalDecision(grant.VerdictAsk, grant.DenyNone)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := manager.Request(context.Background(), request, decision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Approve(context.Background(), pending.ID(), "trusted-operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), pending.ID()); err != nil {
		t.Fatal(err)
	}
}

func newGrantsE2EGate(t *testing.T, manager *grant.Manager) mcpgrant.Gate {
	t.Helper()
	servers, err := mcpgrant.NewStaticServers("filesystem")
	if err != nil {
		t.Fatal(err)
	}
	return mcpgrant.NewGate(servers, fixedUpstream(true), mcpgrant.NewManagerAuthority(manager))
}

func TestRuntimeGrantProductionLikeFlow(t *testing.T) {
	ctx := context.Background()
	clock := &grantsE2EClock{now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	manager := newGrantsE2EManager(t, clock)
	principal, err := grant.NewPrincipal("codex", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	call, err := mcpgrant.NewCall("filesystem", "read_file", []byte(`{"path":"/work/a"}`))
	if err != nil {
		t.Fatal(err)
	}
	gate := newGrantsE2EGate(t, manager)

	if got := gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, call); got.Final != mcpgrant.FinalDenied || got.Effective != mcpgrant.EffectiveGrantMissing {
		t.Fatalf("initial configured MCP ask = %#v, want unavailable", got)
	}

	approveMCP(t, manager, principal, call, grant.OnceScope(), 7, clock.Now())

	cdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/version" {
			t.Fatalf("CDP probe path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"Browser":"Chrome/1","webSocketDebuggerUrl":"ws://127.0.0.1/devtools/browser/fixed"}`))
	}))
	defer cdp.Close()
	host, portText, err := net.SplitHostPort(cdp.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := hostconnector.NewDestination(host, uint16(port), "/json/version")
	if err != nil {
		t.Fatal(err)
	}
	connector, err := hostconnector.NewConnector("chrome-cdp", hostconnector.TransportCDP, destination, hostconnector.ProbeChromeCDP)
	if err != nil {
		t.Fatal(err)
	}
	wrongDestination, err := hostconnector.NewDestination("192.0.2.10", 9225, "/json/version")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostconnector.NewConnector("wrong-cdp", hostconnector.TransportCDP, wrongDestination, hostconnector.ProbeChromeCDP); err == nil {
		t.Fatal("non-loopback CDP destination was accepted")
	}
	registry, err := hostconnector.NewRegistry([]hostconnector.Connector{connector})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := hostconnector.NewBinding(principal)
	if err != nil {
		t.Fatal(err)
	}
	approveConnector(t, manager, principal, grant.SessionScope(), 7, clock.Now())
	authorizer, err := hostconnector.NewGrantAuthorizer(manager, connectorAccessFactory{principal: principal, epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	connectors, err := hostconnector.NewManager(registry, authorizer, hostconnector.NewSameHostBackend(), grantsE2EConnectorAudit{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectors.Activate(ctx, binding, "chrome-cdp", grant.SessionScope()); err != nil {
		t.Fatalf("connector readiness activation: %v", err)
	}
	if _, err := connectors.Use(ctx, binding, "chrome-cdp"); err != nil {
		t.Fatalf("active connector use: %v", err)
	}
	if _, err := connectors.Use(ctx, binding, "other-connector"); !errors.Is(err, hostconnector.ErrInactive) {
		t.Fatalf("wrong connector use = %v, want inactive", err)
	}

	allowed := gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, call)
	if allowed.Final != mcpgrant.FinalForwardAuthorized || allowed.Effective != mcpgrant.EffectiveGrantAllow || allowed.Lease == nil {
		t.Fatalf("active exact grant = %#v", allowed)
	}
	if err := allowed.Lease.Confirm(ctx, mcpgrant.ForwardingBegan); err != nil {
		t.Fatal(err)
	}
	if replay := gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, call); replay.Effective != mcpgrant.EffectiveGrantReplay || replay.Final != mcpgrant.FinalDenied {
		t.Fatalf("once reuse = %#v", replay)
	}

	wrongArgs, _ := mcpgrant.NewCall("filesystem", "read_file", []byte(`{"path":"/work/b"}`))
	wrongServer, _ := mcpgrant.NewCall("unknown", "read_file", []byte(`{"path":"/work/a"}`))
	other, _ := grant.NewPrincipal("codex", "session-b")
	for name, got := range map[string]mcpgrant.Result{
		"arguments": gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, wrongArgs),
		"server":    gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, wrongServer),
		"session":   gate.Check(ctx, other, 7, mcpgrant.PolicyAsk, call),
		"epoch":     gate.Check(ctx, principal, 8, mcpgrant.PolicyAsk, call),
		"locked":    gate.Check(ctx, principal, 7, mcpgrant.PolicyDeny, call),
	} {
		if got.Final == mcpgrant.FinalForwardAuthorized {
			t.Fatalf("%s mismatch authorized: %#v", name, got)
		}
	}

	ttl, err := grant.NewTTLScope(clock.Now(), clock.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ttlCall, _ := mcpgrant.NewCall("filesystem", "read_file", []byte(`{"path":"/work/ttl"}`))
	approveMCP(t, manager, principal, ttlCall, ttl, 7, clock.Now())
	clock.now = clock.now.Add(2 * time.Second)
	if expired := gate.Check(ctx, principal, 7, mcpgrant.PolicyAsk, ttlCall); expired.Effective != mcpgrant.EffectiveGrantExpired || expired.Final != mcpgrant.FinalDenied {
		t.Fatalf("TTL expiry = %#v", expired)
	}
	if err := connectors.EndSession(ctx, principal.SessionID()); err != nil {
		t.Fatal(err)
	}
	if _, err := connectors.Use(ctx, binding, "chrome-cdp"); !errors.Is(err, hostconnector.ErrRevoked) {
		t.Fatalf("connector session expiry use = %v, want revoked", err)
	}
}
