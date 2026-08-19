package hostconnector

import (
	"context"
	"fmt"

	"github.com/LuD1161/agentjail/internal/audit"
)

// AuditEmitter adapts the repository's durable audit seam. It never includes
// the configured destination, readiness response, or bridge credentials.
type AuditEmitter struct {
	Emitter audit.Emitter
}

func (a AuditEmitter) Record(ctx context.Context, transition Transition) error {
	if a.Emitter == nil {
		return ErrAudit
	}
	eventType, err := connectorEvent(transition.State)
	if err != nil {
		return err
	}
	return a.Emitter.Emit(ctx, audit.Event{
		EventType: eventType,
		Actor:     "hostconnector",
		SessionID: string(transition.Binding.Principal().SessionID()),
		RefID:     string(transition.ConnectorID),
		Detail:    map[string]string{"state": string(transition.State)},
	})
}

func connectorEvent(state LifecycleState) (string, error) {
	switch state {
	case StateActivating:
		return audit.HostConnectorActivationRequested, nil
	case StateActive:
		return audit.HostConnectorActivated, nil
	case StateActivationFailed:
		return audit.HostConnectorActivationFailed, nil
	case StateConsumed:
		return audit.HostConnectorConsumed, nil
	case StateExpired:
		return audit.HostConnectorExpired, nil
	case StateRevoked:
		return audit.HostConnectorRevoked, nil
	default:
		return "", fmt.Errorf("%w: unknown lifecycle state", ErrAudit)
	}
}
