//go:build !linux

package netns

import (
	"fmt"
	"os/exec"
)

// ErrUnsupported is returned on platforms that don't support network namespaces.
var ErrUnsupported = fmt.Errorf("network namespaces not supported on this platform")

// Namespace is a stub on non-Linux platforms.
type Namespace struct{}

// Create returns ErrUnsupported on non-Linux platforms.
func Create() (*Namespace, error) { return nil, ErrUnsupported }

// ExecIn returns ErrUnsupported on non-Linux platforms.
func (ns *Namespace) ExecIn(_ *exec.Cmd) error { return ErrUnsupported }

// ExecInCombinedOutput returns ErrUnsupported on non-Linux platforms.
func (ns *Namespace) ExecInCombinedOutput(_ *exec.Cmd) ([]byte, error) {
	return nil, ErrUnsupported
}

// InjectCA returns ErrUnsupported on non-Linux platforms.
func (ns *Namespace) InjectCA(_ string) error { return ErrUnsupported }

// SetupVeth returns ErrUnsupported on non-Linux platforms.
func (ns *Namespace) SetupVeth() (string, string, error) { return "", "", ErrUnsupported }

// PID returns 0 on non-Linux platforms.
func (ns *Namespace) PID() int { return 0 }

// Close is a no-op on non-Linux platforms.
func (ns *Namespace) Close() error { return nil }
