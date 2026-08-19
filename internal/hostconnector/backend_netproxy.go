package hostconnector

import (
	"context"
	"fmt"
	"time"

	"github.com/LuD1161/agentjail/internal/proxyctl"
)

// NetproxyBackend installs an exact configured connector route through the
// host-owned netproxy control plane. The data plane accepts only the synthetic
// ConnectorID authority and resolves the actual host dial here, never from an
// isolated client request.
type NetproxyBackend struct {
	socketPath string
	ctlToken   string
	probe      *SameHostBackend
	timeout    time.Duration
}

func NewNetproxyBackend(socketPath, ctlToken string) (*NetproxyBackend, error) {
	if socketPath == "" || ctlToken == "" {
		return nil, ErrPlatformUnavailable
	}
	return &NetproxyBackend{socketPath: socketPath, ctlToken: ctlToken, probe: NewSameHostBackend(), timeout: time.Second}, nil
}

func (b *NetproxyBackend) Activate(ctx context.Context, activation Activation) (Adapter, error) {
	if _, err := b.probe.Activate(ctx, activation); err != nil {
		return nil, err
	}
	destination := activation.connector.Destination()
	route := proxyctl.ConnectorRoute{
		SessionID: string(activation.Binding().Principal().SessionID()), ConnectorID: string(activation.ConnectorID()),
		Host: destination.Host(), Port: destination.Port(),
	}
	if err := proxyctl.InstallConnector(b.socketPath, b.ctlToken, route, b.timeout); err != nil {
		return nil, fmt.Errorf("install configured connector route: %w", err)
	}
	return connectorRouteAdapter{socketPath: b.socketPath, ctlToken: b.ctlToken, sessionID: route.SessionID, connectorID: route.ConnectorID, timeout: b.timeout}, nil
}

type connectorRouteAdapter struct {
	socketPath  string
	ctlToken    string
	sessionID   string
	connectorID string
	timeout     time.Duration
}

func (a connectorRouteAdapter) Close() error {
	return proxyctl.RemoveConnector(a.socketPath, a.ctlToken, a.sessionID, a.connectorID, a.timeout)
}
