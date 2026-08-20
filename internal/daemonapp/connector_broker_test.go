package daemonapp

import (
	"context"
	"testing"

	"github.com/LuD1161/agentjail/internal/grant"
	"github.com/LuD1161/agentjail/internal/hostconnector"
)

func TestConnectorBrokerEndSessionRemovesRecordedRoute(t *testing.T) {
	tracker := newActiveTracker(t.TempDir())
	tracker.sessions["provider"] = &sessionState{Root: "/repo", Path: "/bin/agent", ConnectorCapability: "opaque", NetproxySessionID: "shield"}
	var removed []string
	broker := &connectorCapabilityBroker{sessions: tracker, used: map[string]map[hostconnector.ConnectorID]struct{}{"provider": {"filesystem": {}}}, remove: func(capability, session, id string) error {
		removed = append(removed, capability+":"+session+":"+id)
		return nil
	}}
	broker.EndSession(context.Background(), "provider")
	if len(removed) != 1 || removed[0] != "opaque:shield:filesystem" {
		t.Fatalf("remove calls = %v", removed)
	}
	principal, err := grant.NewPrincipal("agent", "provider")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := hostconnector.NewBinding(principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Use(context.Background(), binding, "filesystem"); err == nil {
		t.Fatal("use succeeded after session end")
	}
}
