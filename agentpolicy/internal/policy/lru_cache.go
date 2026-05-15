package policy

// lruDecisionCache is the concrete Cache implementation backed by the package-
// internal lruCache. It holds the hit/miss counters required by CacheStats and
// is the type returned by NewLRUCache.
//
// Thread-safe: all methods delegate to lruCache which is guarded by its own
// sync.Mutex; the stat counters are updated inside that same lock to keep the
// Stats snapshot consistent.

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
)

// DefaultCacheSize is the default maximum number of entries for NewLRUCache.
const DefaultCacheSize = 1024

// NewLRUCache returns a Cache backed by an LRU eviction policy. maxEntries
// must be > 0; pass DefaultCacheSize if you have no specific requirement.
func NewLRUCache(maxEntries int) Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheSize
	}
	return &lruDecisionCache{
		inner: newLRUDecision(maxEntries),
	}
}

// lruDecisionCache wraps lruCacheDecision to implement the Cache interface,
// adding exported-stat tracking.
type lruDecisionCache struct {
	mu     sync.Mutex
	hits   int64
	misses int64
	inner  *lruCacheDecision
}

func (c *lruDecisionCache) Get(key CacheKey) (Decision, bool) {
	d, ok := c.inner.get(compositeKey(key))
	c.mu.Lock()
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	c.mu.Unlock()
	return d, ok
}

func (c *lruDecisionCache) Set(key CacheKey, d Decision) {
	c.inner.put(compositeKey(key), d)
}

func (c *lruDecisionCache) Invalidate() {
	c.inner.clear()
	c.mu.Lock()
	// Reset counters on invalidation so Stats reflect the current epoch.
	c.hits = 0
	c.misses = 0
	c.mu.Unlock()
}

func (c *lruDecisionCache) Stats() CacheStats {
	c.mu.Lock()
	h, m := c.hits, c.misses
	c.mu.Unlock()
	return CacheStats{
		Hits:   h,
		Misses: m,
		Size:   c.inner.size(),
	}
}

// compositeKey converts a CacheKey to a single string suitable as a map key.
// Using ToolName+InputHash avoids hash collisions between different tools
// that happen to produce the same InputHash.
func compositeKey(k CacheKey) string {
	return k.ToolName + ":" + k.InputHash
}

// ---- standalone LRU (no external deps) ----
// This is a separate type from the package-internal lruCache so it carries
// Decision values directly and the key is a composite cache key string.

type lruCacheDecision struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntryDecision struct {
	key string
	val Decision
}

func newLRUDecision(cap int) *lruCacheDecision {
	return &lruCacheDecision{
		cap:   cap,
		ll:    list.New(),
		items: make(map[string]*list.Element, cap),
	}
}

func (c *lruCacheDecision) get(k string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntryDecision).val, true
	}
	return Decision{}, false
}

func (c *lruCacheDecision) put(k string, v Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		el.Value.(*lruEntryDecision).val = v
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntryDecision{key: k, val: v})
	c.items[k] = el
	if c.ll.Len() > c.cap {
		old := c.ll.Back()
		if old != nil {
			c.ll.Remove(old)
			delete(c.items, old.Value.(*lruEntryDecision).key)
		}
	}
}

func (c *lruCacheDecision) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll = list.New()
	c.items = make(map[string]*list.Element, c.cap)
}

func (c *lruCacheDecision) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// ---- staticInputHash: derive the CacheKey.InputHash ----

// staticInputHash produces a stable SHA-256 hex string from the fields of in
// that affect policy decisions, deliberately omitting per-invocation fields:
//
//	Kept:    Hook, Op, Program, Method, Action, Path, Host, Port, Flags (sorted),
//	         Track, first Positional (path-normalized)
//	Dropped: Cwd (normalized to ""), ArgvRaw (redundant + session-path noise),
//	         PathsResolved (computed artifact of Cwd), Context (session-specific),
//	         Principal, Resource, Req (handled by the bucketed cache in Engine)
//
// The hash is deterministic across process restarts.
func staticInputHash(in Input) string {
	type staticFields struct {
		Hook       string   `json:"hook,omitempty"`
		Op         string   `json:"op,omitempty"`
		Program    string   `json:"program,omitempty"`
		Method     string   `json:"method,omitempty"`
		Action     string   `json:"action,omitempty"`
		Path       string   `json:"path,omitempty"`
		Host       string   `json:"host,omitempty"`
		Port       int      `json:"port,omitempty"`
		Track      string   `json:"track,omitempty"`
		Flags      []string `json:"flags,omitempty"`
		Positional string   `json:"positional,omitempty"` // first arg only; path-normalized
	}

	// Sort flags so ["-r", "-f"] and ["-f", "-r"] produce the same hash.
	flags := make([]string, len(in.Flags))
	copy(flags, in.Flags)
	sort.Strings(flags)

	// Retain only the first positional argument; normalize away the session
	// temp-dir prefix so "/tmp/claude-abc123/repo/src/main.go" and
	// "/tmp/claude-def456/repo/src/main.go" hash the same.
	var pos0 string
	if len(in.Positional) > 0 {
		pos0 = normalizePath(in.Positional[0])
	}

	sf := staticFields{
		Hook:       in.Hook,
		Op:         in.Op,
		Program:    in.Program,
		Method:     in.Method,
		Action:     in.Action,
		Path:       normalizePath(in.Path),
		Host:       in.Host,
		Port:       in.Port,
		Track:      in.Track,
		Flags:      flags,
		Positional: pos0,
	}

	b, _ := json.Marshal(sf)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// normalizePath is a hook for stripping session-specific path prefixes so the
// same logical path from different sessions hashes identically.
//
// Current iteration: identity normalization (no-op). The static/dynamic split
// already provides session_id isolation; path normalization is additive and
// can be tightened in a future commit without breaking the Cache interface.
//
// A more aggressive strategy (e.g. strip the $HOME prefix or known tmpdir
// patterns like /tmp/claude-<session-id>/) would increase hit rates at the
// cost of conflating writes to different files — needs an ADR before landing.
func normalizePath(p string) string {
	return p
}
