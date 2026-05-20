package proctree

// lookup is the indirection unit tests substitute for parentOf. The
// default delegates to the platform-tagged parentOf in
// proctree_{darwin,linux,other}.go. Tests call withLookup to install a
// deterministic fake for the duration of a test.
var lookup = func(pid int) (int, error) { return parentOf(pid) }

// withLookup swaps in a deterministic parentOf for the duration of a
// test. Returns a restore closure. Test-only — the public API never
// surfaces this seam.
func withLookup(f func(int) (int, error)) (restore func()) {
	prev := lookup
	lookup = f
	return func() { lookup = prev }
}

// SetLookupForTest replaces the parentOf indirection so external
// packages can drive IsDescendant deterministically in their tests.
// Returns a restore closure. Production callers MUST NOT call this —
// it lives in the public surface only because Go has no friend-package
// concept. Calls are not safe for concurrent use; tests typically pin
// it for the duration of one t.Run.
func SetLookupForTest(f func(int) (int, error)) (restore func()) {
	return withLookup(f)
}
