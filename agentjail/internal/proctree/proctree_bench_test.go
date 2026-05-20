package proctree

import (
	"os"
	"testing"
)

// BenchmarkParentOf_Self measures one round-trip through the platform
// parentOf for the current process. Useful for sizing the daemon's
// peer-auth budget — IsDescendant calls this in a loop up to MaxDepth.
func BenchmarkParentOf_Self(b *testing.B) {
	pid := os.Getpid()
	for i := 0; i < b.N; i++ {
		if _, err := ParentOf(pid); err != nil {
			b.Fatalf("ParentOf: %v", err)
		}
	}
}

// BenchmarkIsDescendant_Self walks the full ancestor chain from the
// current process to PID 1. Approximates the worst-case auth-gate cost
// at a typical shell/agent depth (8–15 hops on macOS).
func BenchmarkIsDescendant_Self(b *testing.B) {
	pid := os.Getpid()
	for i := 0; i < b.N; i++ {
		// 1 is always an ancestor — forces a full walk.
		_ = IsDescendant(pid, 1)
	}
}
