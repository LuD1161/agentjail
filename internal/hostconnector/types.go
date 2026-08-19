// Package hostconnector owns configured host-service connector authority.
// See ADR 0141-runtime-grants.
package hostconnector

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/LuD1161/agentjail/internal/grant"
)

var (
	ErrInvalidConnector  = errors.New("invalid host connector")
	ErrUnknownConnector  = errors.New("unknown host connector")
	ErrInvalidBinding    = errors.New("invalid host connector binding")
	ErrInactive          = errors.New("host connector is not active")
	ErrExpired           = errors.New("host connector grant expired")
	ErrRevoked           = errors.New("host connector grant revoked")
	ErrAlreadyActivating = errors.New("host connector activation already in progress")
	ErrAudit             = errors.New("host connector durable audit failed")
	ErrActivation        = errors.New("host connector activation failed")
	ErrCleanup           = errors.New("host connector cleanup failed")
)

// ConnectorID identifies a host-configured connector. It is never a host,
// port, or guest supplied endpoint.
type ConnectorID string

type Transport string

const (
	TransportMCP Transport = "mcp"
	TransportCDP Transport = "cdp"
)

type ReadinessProbe string

const (
	ProbeReachable ReadinessProbe = "reachable"
	ProbeChromeCDP ReadinessProbe = "chrome_cdp"
)

// Destination is host-owned configuration. Its fields remain private so an
// isolated caller can request an ID but cannot turn this package into a raw
// destination dialer.
type Destination struct {
	host string
	port uint16
	path string
}

func NewDestination(host string, port uint16, path string) (Destination, error) {
	host = strings.TrimSpace(host)
	if host == "" || port == 0 || strings.Contains(host, "://") ||
		strings.ContainsAny(host, " \t\r\n/@?#*") || net.ParseIP(host) == nil && strings.Contains(host, ":") {
		return Destination{}, ErrInvalidConnector
	}
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") ||
		strings.Contains(path, "//") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") ||
		strings.Contains(path, "%") {
		return Destination{}, ErrInvalidConnector
	}
	return Destination{host: host, port: port, path: path}, nil
}

func (d Destination) valid() bool {
	_, err := NewDestination(d.host, d.port, d.path)
	return err == nil
}

func (d Destination) Host() string { return d.host }

func (d Destination) Port() uint16 { return d.port }

func (d Destination) Path() string { return d.path }

func (d Destination) loopback() bool {
	ip := net.ParseIP(d.host)
	return ip != nil && ip.IsLoopback()
}

// Connector is a preconfigured host resource. Agent-side requests name only
// ID; configuration loaders construct the destination before session start.
type Connector struct {
	id          ConnectorID
	transport   Transport
	destination Destination
	probe       ReadinessProbe
}

func NewConnector(id ConnectorID, transport Transport, destination Destination, probe ReadinessProbe) (Connector, error) {
	if !validConnectorID(id) || !transport.valid() || !destination.valid() || !probe.valid() {
		return Connector{}, ErrInvalidConnector
	}
	if transport == TransportCDP && probe != ProbeChromeCDP {
		return Connector{}, fmt.Errorf("%w: CDP requires Chrome CDP readiness", ErrInvalidConnector)
	}
	if transport == TransportCDP && !destination.loopback() {
		return Connector{}, fmt.Errorf("%w: CDP destination must be loopback", ErrInvalidConnector)
	}
	if transport == TransportCDP && destination.path != "/json/version" {
		return Connector{}, fmt.Errorf("%w: CDP probe path must be /json/version", ErrInvalidConnector)
	}
	return Connector{id: id, transport: transport, destination: destination, probe: probe}, nil
}

func validConnectorID(id ConnectorID) bool {
	if strings.TrimSpace(string(id)) == "" {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func (c Connector) ID() ConnectorID { return c.id }

func (c Connector) Transport() Transport { return c.transport }

func (c Connector) Destination() Destination { return c.destination }

func (c Connector) Probe() ReadinessProbe { return c.probe }

func (c Connector) valid() bool {
	_, err := NewConnector(c.id, c.transport, c.destination, c.probe)
	return err == nil
}

func (t Transport) valid() bool {
	return t == TransportMCP || t == TransportCDP
}

func (p ReadinessProbe) valid() bool {
	return p == ProbeReachable || p == ProbeChromeCDP
}

// Binding carries the canonical principal and session that may use one
// connector. The principal type is shared with the runtime grant domain.
type Binding struct {
	principal grant.Principal
}

func NewBinding(principal grant.Principal) (Binding, error) {
	if !principal.Valid() {
		return Binding{}, ErrInvalidBinding
	}
	return Binding{principal: principal}, nil
}

func (b Binding) Principal() grant.Principal { return b.principal }

func (b Binding) valid() bool { return b.principal.Valid() }

func (b Binding) equal(other Binding) bool {
	return b.principal.ID() == other.principal.ID() && b.principal.SessionID() == other.principal.SessionID()
}

type LifecycleState string

const (
	StateActivating       LifecycleState = "activating"
	StateActive           LifecycleState = "active"
	StateActivationFailed LifecycleState = "activation_failed"
	StateConsumed         LifecycleState = "consumed"
	StateExpired          LifecycleState = "expired"
	StateRevoked          LifecycleState = "revoked"
)

// Snapshot gives diagnostics a state report without exposing the host
// destination or bridge endpoint.
type Snapshot struct {
	ConnectorID ConnectorID
	Binding     Binding
	State       LifecycleState
}

// Use is proof that this exact binding was active at the authorization point.
// It deliberately contains no socket, address, or raw forwarding capability.
type Use struct {
	ConnectorID ConnectorID
	Transport   Transport
}
