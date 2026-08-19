package hostconnector

import (
	"context"
	"errors"

	"github.com/LuD1161/agentjail/internal/grant"
)

var ErrPlatformUnavailable = errors.New("host connector isolation bridge is unavailable on this platform")

// Backend is the consumer-owned isolation seam. Implementations install the
// configured bridge, dial from the host side, and run the fixed readiness
// probe before returning an Adapter. It never receives agent-selected input.
type Backend interface {
	Activate(context.Context, Activation) (Adapter, error)
}

// Activation is constructed from a configured Connector after authorization.
// Destination stays package-private for the OS backend implementation.
type Activation struct {
	connector Connector
	binding   Binding
}

func (a Activation) ConnectorID() ConnectorID { return a.connector.ID() }

func (a Activation) Transport() Transport { return a.connector.Transport() }

func (a Activation) Binding() Binding { return a.binding }

// Adapter owns installed bridge state. Close must tear down the bridge and
// any active host-side dial; a cleanup failure never restores authority.
type Adapter interface {
	Close() error
}

// Authorizer is implemented by the runtime grant lifecycle. It verifies the
// exact principal, session, connector, and scope before activation begins.
type Authorizer interface {
	Authorize(context.Context, Binding, ConnectorID, grant.Scope) error
}

// Auditor records connector lifecycle events durably. Activation refuses to
// expose authority when this seam returns an error.
type Auditor interface {
	Record(context.Context, Transition) error
}

type Transition struct {
	ConnectorID ConnectorID
	Binding     Binding
	State       LifecycleState
}
