// Package localui owns the shared loopback contract for AgentJail's web UI.
package localui

import (
	"context"
	"net"
	"time"
)

const (
	// DefaultAddr is the only implicit listen/probe address used by the CLI,
	// shield, and status line.
	DefaultAddr = "127.0.0.1:9101"
	DefaultURL  = "http://" + DefaultAddr
)

// Reachable reports whether a listener accepts loopback connections before the
// supplied deadline. It identifies availability, not server identity.
func Reachable(addr string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
