package hostconnector

import "github.com/LuD1161/agentjail/internal/grant"

// Isolation identifies where the connector client runs. It is supplied by a
// trusted launcher, never by a connector request from the agent.
type Isolation string

const (
	IsolationSameHost       Isolation = "same_host"
	IsolationLinuxContainer Isolation = "linux_container"
	IsolationMicroVM        Isolation = "microvm"
	IsolationMacOSSandbox   Isolation = "macos_sandbox"
	IsolationMacOSGuest     Isolation = "macos_guest"
)

// TransportState distinguishes a working route from an intentional refusal.
// A route is usable only when StateAvailable is reported by the trusted
// launcher and the connector activation completes.
type TransportState string

const (
	StateAvailable   TransportState = "available"
	StateUnavailable TransportState = "unavailable"
)

// TransportCapability is the OS/isolation report shared by connector
// activation, shield launch diagnostics, and doctor. Detail is intentionally
// operational rather than an endpoint: endpoints are session capabilities and
// are injected only by a trusted launcher.
type TransportCapability struct {
	Isolation Isolation
	State     TransportState
	Detail    string
}

// GuestEndpoint is the trusted launcher-owned endpoint injected into an
// isolated guest's configured connector. It deliberately carries no host
// destination, control credential, or token.
type GuestEndpoint struct {
	isolation Isolation
	socket    string
}

func (e GuestEndpoint) Isolation() Isolation { return e.isolation }

// SocketPath is the guest-visible AF_UNIX socket path. Only a shield/container
// launcher may pass it into the guest configuration; agents do not construct
// endpoint values.
func (e GuestEndpoint) SocketPath() string { return e.socket }

func (e GuestEndpoint) validFor(isolation Isolation) bool {
	return e.isolation == isolation && e.socket != ""
}

// EndpointProvider is implemented by a transport adapter that has installed a
// guest-visible endpoint. The Manager exposes it only after successful active
// transition, so authorization and socket availability cannot be confused.
type EndpointProvider interface {
	Adapter
	GuestEndpoint() GuestEndpoint
}

// TransportCapabilities reports only transports this build can actually
// create. A future launcher must not turn an unavailable result into a route
// by substituting guest loopback or an arbitrary host address.
func TransportCapabilities() []TransportCapability {
	return platformTransportCapabilities()
}

// TransportCapabilityFor returns the single report used for an activation.
func TransportCapabilityFor(isolation Isolation) TransportCapability {
	for _, report := range TransportCapabilities() {
		if report.Isolation == isolation {
			return report
		}
	}
	return TransportCapability{
		Isolation: isolation,
		State:     StateUnavailable,
		Detail:    "no connector transport is implemented for this isolation boundary",
	}
}

// Endpoint returns the endpoint installed for one active binding. This method
// does not authorize a use; the caller must still use Manager.Use at the MCP
// forwarding boundary. It exists solely for a trusted launcher to inject the
// preconfigured route before guest exec.
func (m *Manager) Endpoint(binding Binding, id ConnectorID) (GuestEndpoint, error) {
	if !binding.valid() {
		return GuestEndpoint{}, ErrInactive
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[keyFor(binding, id)]
	if !ok || !record.binding.equal(binding) || record.state != StateActive {
		return GuestEndpoint{}, ErrInactive
	}
	provider, ok := record.adapter.(EndpointProvider)
	if !ok {
		return GuestEndpoint{}, ErrPlatformUnavailable
	}
	endpoint := provider.GuestEndpoint()
	if !endpoint.validFor(IsolationLinuxContainer) {
		return GuestEndpoint{}, ErrActivation
	}
	return endpoint, nil
}

// SessionID is retained here so launcher-facing constructors can require an
// exact session without exposing the concrete grant principal implementation.
type SessionID = grant.SessionID
