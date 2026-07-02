//go:build !linux

// Package netns creates unprivileged Linux network + mount namespaces for
// agent isolation. On non-Linux platforms all operations return
// ErrUnsupported.
package netns

import "fmt"

// ErrUnsupported is returned on non-Linux platforms.
var ErrUnsupported = fmt.Errorf("network namespaces require Linux")

// Veth IP addressing constants (needed for compilation on all platforms).
const (
	VethHostIP = "10.77.0.1"
	VethNsIP   = "10.77.0.2"
	VethCIDR   = "/30"
)

// Namespace is a stub on non-Linux platforms.
type Namespace struct{}

// Create returns ErrUnsupported on non-Linux.
func Create() (*Namespace, error) {
	return nil, ErrUnsupported
}

// PID returns 0 on non-Linux.
func (ns *Namespace) PID() int { return 0 }

// SetupVeth returns ErrUnsupported on non-Linux.
func (ns *Namespace) SetupVeth() (string, string, error) {
	return "", "", ErrUnsupported
}

// Close is a no-op on non-Linux.
func (ns *Namespace) Close() error { return nil }
