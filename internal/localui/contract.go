// Package localui owns the shared loopback contract for AgentJail's web UI.
package localui

const (
	// DefaultAddr is the only implicit listen/probe address used by the CLI,
	// shield, and status line.
	DefaultAddr = "127.0.0.1:9101"
	DefaultURL  = "http://" + DefaultAddr
)
