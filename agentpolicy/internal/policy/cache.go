package policy

// Cache stores policy decisions keyed on the static portion of an Input.
// Dynamic fields (session_id, timestamps, cwd) are excluded from the key so
// that semantically-equivalent inputs from different sessions share cache
// entries.
//
// Inspiration: Linux page cache + Envoy RDS cache (static/dynamic key split).
// See docs/ENGINEERING.md §2 "Decision caching".
type Cache interface {
	// Get returns the cached Decision for the given key, and whether it was
	// found. Callers must treat a miss as authoritative: evaluate via OPA and
	// call Set with the result.
	Get(key CacheKey) (Decision, bool)

	// Set stores d under key. If the cache is full, the least-recently-used
	// entry is evicted.
	Set(key CacheKey, d Decision)

	// Invalidate drops every cached entry. Called on policy reload so stale
	// verdicts from a previous rule set cannot leak.
	Invalidate()

	// Stats returns a point-in-time snapshot of hit/miss counters and the
	// current entry count.
	Stats() CacheStats
}

// CacheKey identifies the static portion of a policy input.
//
// Two inputs that produce the same CacheKey are considered equivalent for
// policy evaluation — they may differ in session_id, timestamp, cwd, or
// other per-invocation fields that do not affect the decision.
type CacheKey struct {
	// ToolName is the agent tool being invoked (e.g. "Bash", "Write", "Read").
	// Included verbatim because the first-level dispatch in default.rego
	// branches on input.hook / tool name.
	ToolName string

	// InputHash is the hex-encoded SHA-256 of the normalized static input
	// fields (tool name + command/path pattern, with session-specific fields
	// stripped). Computed by StaticKey.
	InputHash string
}

// CacheStats is a point-in-time snapshot of Cache counters.
type CacheStats struct {
	// Hits is the number of Get calls that returned a cached entry.
	Hits int64

	// Misses is the number of Get calls that returned nothing.
	Misses int64

	// Size is the current number of entries in the cache.
	Size int
}

// StaticKey derives a CacheKey from in by retaining only the fields that
// affect the policy decision and discarding fields that vary per-invocation
// (session_id, cwd, timestamps, environment).
//
// Static fields kept:
//   - Hook  (exec / file / http — determines which rule block fires)
//   - Program / Op / Method (the tool's operation verb)
//   - Path / Host (the resource being acted on, path-normalized)
//   - Action (read / write / fetch / exec)
//   - Flags (sorted) — e.g. ["-r", "-f"] for rm
//   - Positional[0] (the primary argument, path-normalized)
//
// Dynamic fields stripped:
//   - SessionID (per-request, in Context["session_id"])
//   - Cwd (normalized to a stable placeholder; same command from /tmp or
//     /home/alice are equivalent for most rules)
//   - Timestamps (not part of Input today, but excluded by convention)
//   - ArgvRaw (redundant with Program + Flags + Positional; also contains
//     the full path which may embed the session tmpdir)
//
// The result is stable across Go process restarts (SHA-256 of a canonical
// JSON blob with sorted map keys).
func StaticKey(in Input) CacheKey {
	return CacheKey{
		ToolName:  in.Hook,
		InputHash: staticInputHash(in),
	}
}
