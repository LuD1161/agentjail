//go:build !darwin && !linux

package proctree

// parentOf is a stub for unsupported platforms. The package returns
// ErrUnsupported so the daemon's peer-auth gate can fail-closed cleanly
// rather than silently accept everything.
func parentOf(pid int) (int, error) {
	return 0, ErrUnsupported
}
