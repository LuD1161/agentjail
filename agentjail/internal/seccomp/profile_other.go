//go:build !linux

package seccomp

// Apply on non-Linux platforms is a no-op that returns ErrUnsupported.
// The package still compiles so that the agentjail-host toolchain on a
// macOS developer workstation can import seccomp without #ifdef-style
// build tag churn at every call site.
//
// The host process MUST check the error and refuse to start an
// "enforced" guest when running off-Linux — the seccomp filter is the
// only thing keeping the guest from issuing arbitrary syscalls.
func (p Profile) Apply() error {
	return ErrUnsupported
}
