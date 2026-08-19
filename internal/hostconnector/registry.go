package hostconnector

// Registry owns the fixed connector configuration visible to a session.
// It accepts configuration at startup; runtime callers can look up by ID only.
type Registry struct {
	connectors map[ConnectorID]Connector
}

func NewRegistry(connectors []Connector) (*Registry, error) {
	registry := &Registry{connectors: make(map[ConnectorID]Connector, len(connectors))}
	for _, connector := range connectors {
		if !connector.valid() {
			return nil, ErrInvalidConnector
		}
		if _, exists := registry.connectors[connector.ID()]; exists {
			return nil, ErrInvalidConnector
		}
		registry.connectors[connector.ID()] = connector
	}
	return registry, nil
}

func (r *Registry) Lookup(id ConnectorID) (Connector, error) {
	if r == nil {
		return Connector{}, ErrUnknownConnector
	}
	connector, ok := r.connectors[id]
	if !ok {
		return Connector{}, ErrUnknownConnector
	}
	return connector, nil
}
