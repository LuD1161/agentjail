package shieldapp

import "github.com/LuD1161/agentjail/internal/hostconnector"

// connectorTransportCapabilities is the shield-side view of the one shared
// connector transport contract. A launch path may inject an endpoint only when
// this report says its isolation boundary is available.
func connectorTransportCapabilities() []hostconnector.TransportCapability {
	return hostconnector.TransportCapabilities()
}
