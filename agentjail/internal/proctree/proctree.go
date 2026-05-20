// Package proctree resolves Unix process parent/child relationships so the
// daemon can decide whether a peer connection originates inside or outside
// the wrapped-agent's process tree (the gate behind the Phase 2 trust
// model).
//
// The package is deliberately tiny: two exported helpers, no state, no
// goroutines. Tests can substitute their own ProcessLookup function via
// the test-only seam in proctree_testing.go without touching real
// processes.
//
// Platform support:
//
//   - macOS: libproc.proc_pidinfo when cgo is available (proctree_darwin_cgo.go).
//     Pure-Go fallback that shells out to `ps -o ppid= -p <pid>` ships in
//     proctree_darwin.go for CGO_ENABLED=0 builds and tests.
//   - Linux: /proc/<pid>/stat parser in proctree_linux.go.
//   - Other GOOSes return ErrUnsupported.
package proctree

import "errors"

// MaxDepth bounds the IsDescendant walk so a corrupted /proc entry or a
// post-wraparound PID cycle cannot wedge the daemon. 64 is well above any
// realistic shell/agent process depth.
const MaxDepth = 64

// ErrUnsupported is returned by the platform helpers on GOOSes we don't
// support. Callers should treat this as a fatal misconfiguration on the
// hot path — fail-closed for cred ops, not fail-open.
var ErrUnsupported = errors.New("proctree: unsupported platform")

// ParentOf returns the parent PID of pid, or an error if the lookup
// failed. A PID of 0 or 1 is its own root and returns (pid, nil); callers
// that want to detect the root should compare against the input.
func ParentOf(pid int) (int, error) {
	if pid <= 1 {
		return pid, nil
	}
	return lookup(pid)
}

// IsDescendant reports whether pid is in the descendant tree rooted at
// ancestor (inclusive — pid == ancestor is true). Walks parent chains up
// to MaxDepth steps; deeper or cyclic chains return false. A lookup error
// at any step terminates the walk and returns false — fail-closed for
// the auth gate.
func IsDescendant(pid, ancestor int) bool {
	if pid <= 0 || ancestor <= 0 {
		return false
	}
	cur := pid
	for i := 0; i < MaxDepth; i++ {
		if cur == ancestor {
			return true
		}
		if cur <= 1 {
			return false
		}
		parent, err := lookup(cur)
		if err != nil {
			return false
		}
		if parent == cur {
			// Defensive: a process should never be its own parent. Treat
			// as a cycle and bail.
			return false
		}
		cur = parent
	}
	return false
}
