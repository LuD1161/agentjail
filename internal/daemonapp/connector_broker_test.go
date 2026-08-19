package daemonapp

import (
	"context"
	"os"
	"strings"
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

func TestActiveSessionJSONDoesNotPersistConnectorCapability(t *testing.T) {
	tracker := newActiveTracker(t.TempDir())
	tracker.sessions["provider"] = &sessionState{PID: 42, CWD: "/repo", ConnectorCapability: "opaque-capability", NetproxySessionID: "shield-session"}
	tracker.flush()
	data, err := os.ReadFile(tracker.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "opaque-capability") || strings.Contains(string(data), "shield-session") {
		t.Fatalf("active session JSON leaked connector metadata: %s", data)
	}
}

func TestConnectorBrokerPreBindEndCannotLaterUse(t *testing.T) {
	tracker := newActiveTracker(t.TempDir())
	broker := &connectorCapabilityBroker{sessions: tracker}
	broker.EndSession(context.Background(), "provider")
	tracker.sessions["provider"] = &sessionState{Root: "/repo", Path: "/bin/agent", ConnectorCapability: "opaque", NetproxySessionID: "shield"}
	principal, err := grant.NewPrincipal("agent", "provider")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := hostconnector.NewBinding(principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Use(context.Background(), binding, "filesystem"); err == nil {
		t.Fatal("use succeeded after pre-bind teardown")
	}
}
