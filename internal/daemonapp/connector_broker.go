package daemonapp

import (
	"context"
	"sync"
	"time"

	"github.com/LuD1161/agentjail/internal/hostconnector"
	"github.com/LuD1161/agentjail/internal/proxyctl"
)

type connectorCapabilityBroker struct {
	sessions *activeTracker
	mu       sync.Mutex
	used     map[string]map[hostconnector.ConnectorID]struct{}
	ended    map[string]struct{}
	remove   func(string, string, string) error
}

func (b *connectorCapabilityBroker) Use(_ context.Context, binding hostconnector.Binding, id hostconnector.ConnectorID) (hostconnector.Use, error) {
	if b.sessions == nil {
		return hostconnector.Use{}, hostconnector.ErrInactive
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ended := b.ended[string(binding.Principal().SessionID())]; ended {
		return hostconnector.Use{}, hostconnector.ErrInactive
	}
	capability, netproxySessionID, ok := b.sessions.connectorCapability(string(binding.Principal().SessionID()))
	if !ok {
		return hostconnector.Use{}, hostconnector.ErrInactive
	}
	if err := proxyctl.UseConnectorCapability(proxyctl.ControlSocketPath(), capability, netproxySessionID, string(id), time.Second); err != nil {
		return hostconnector.Use{}, err
	}
	if b.used == nil {
		b.used = make(map[string]map[hostconnector.ConnectorID]struct{})
	}
	if b.used[string(binding.Principal().SessionID())] == nil {
		b.used[string(binding.Principal().SessionID())] = make(map[hostconnector.ConnectorID]struct{})
	}
	b.used[string(binding.Principal().SessionID())][id] = struct{}{}
	return hostconnector.Use{ConnectorID: id, Transport: hostconnector.TransportMCP}, nil
}

func (b *connectorCapabilityBroker) EndSession(_ context.Context, sessionID string) {
	b.mu.Lock()
	if b.ended == nil {
		b.ended = make(map[string]struct{})
	}
	b.ended[sessionID] = struct{}{}
	b.mu.Unlock()
	if b.sessions == nil {
		return
	}
	capability, netproxySessionID, ok := b.sessions.connectorCapability(sessionID)
	if !ok {
		return
	}
	b.mu.Lock()
	ids := b.used[sessionID]
	delete(b.used, sessionID)
	b.mu.Unlock()
	for id := range ids {
		if b.remove != nil {
			_ = b.remove(capability, netproxySessionID, string(id))
			continue
		}
		_ = proxyctl.RemoveConnectorCapability(proxyctl.ControlSocketPath(), capability, netproxySessionID, string(id), time.Second)
	}
}
