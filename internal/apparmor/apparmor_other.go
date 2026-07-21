//go:build !linux

package apparmor

// unsupportedManager is the stub for non-Linux hosts. AppArmor is Linux-only,
// so Available/Install report ErrNotSupported; Render still works (pure text)
// via the embedded renderer, which keeps the profile testable everywhere.
type unsupportedManager struct {
	renderer
}

// New returns the non-Linux stub Manager.
func New() Manager { return unsupportedManager{} }

// Available reports nothing supported on non-Linux hosts.
func (unsupportedManager) Available() (Availability, error) {
	return Availability{}, ErrNotSupported
}

// Install is unsupported on non-Linux hosts.
func (unsupportedManager) Install(_ string) error { return ErrNotSupported }
