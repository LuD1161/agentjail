// Package policy embeds OPA as a Go library and evaluates the default
// agentjail decision policy against a normalized event input.
//
// Phase 2: audit-only. Decisions are emitted as OTel events; nothing is
// blocked. The engine is created once at daemon startup.
package policy

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// Input is the canonical policy input record shared across all capture tracks.
// Optional fields are zero-valued; the Rego policy treats absence as "rule
// not applicable" via type/field checks.
//
// Phase 1 / Stream B.1 extension: the Cerbos-shape principal/resource/
// action fields live alongside the legacy flat ones so existing rules in
// policies/default.rego continue to match on input.program / input.path /
// input.host UNCHANGED. New rules in policies/experimental/ can match on
// input.principal, input.resource, input.action, or — for the full
// Cerbos request shape — input.req.
type Input struct {
	Hook          string         `json:"hook"`
	Op            string         `json:"op,omitempty"`
	Program       string         `json:"program,omitempty"`
	ProgramPath   string         `json:"program_path,omitempty"`
	Flags         []string       `json:"flags,omitempty"`
	Positional    []string       `json:"positional,omitempty"`
	ArgvRaw       []string       `json:"argv_raw,omitempty"`
	Cwd           string         `json:"cwd,omitempty"`
	PathsResolved []string       `json:"paths_resolved,omitempty"`
	Path          string         `json:"path,omitempty"`
	Host          string         `json:"host,omitempty"`
	Port          int            `json:"port,omitempty"`
	Method        string         `json:"method,omitempty"`
	Track         string         `json:"track,omitempty"`
	Context       map[string]any `json:"context,omitempty"`

	// Cerbos-shape additions (Phase 1). Optional — legacy callers leave
	// them nil and the existing default rules ignore them. Typed as
	// map[string]any and `any` to avoid an import cycle on internal/perm.
	Principal map[string]any `json:"principal,omitempty"`
	Resource  map[string]any `json:"resource,omitempty"`
	Action    string         `json:"action,omitempty"`
	Req       any            `json:"req,omitempty"`
}

// Decision is the policy evaluator's verdict.
type Decision struct {
	Action string `json:"action"`            // "allow" | "deny" | "ask"
	Reason string `json:"reason,omitempty"`  // human-readable, shown to the agent
	RuleID string `json:"rule_id,omitempty"` // e.g. "file_policy/sensitive_path"
	Impact string `json:"impact,omitempty"`  // consequence-of-allowing text; policy-declared via impact field in Rego
}

// OPAEngine wraps a compiled Rego query plus a decision LRU. It is the
// concrete in-process OPA implementation; the Engine interface (engine.go)
// is the abstraction new callers should depend on.
type OPAEngine struct {
	// qMu guards the prepared query so Reload can swap it atomically while
	// Eval is in flight on another goroutine. Reads take RLock, Reload Lock.
	qMu sync.RWMutex
	q   rego.PreparedEvalQuery

	// dir is remembered so Reload() can re-read the same policy directory
	// without the caller having to thread the path back through.
	dir string

	// cache is the legacy flat LRU. Still used as a backstop and by the
	// existing fast-path tests. New traffic flows through bucketed below.
	cache *lruCache

	// bucketed is the Phase 1 cache-key split (codex blocker resolved):
	// outer level is keyed by staticKey (principal slug+user+agent+enforce
	// — slow-changing), inner LRU is keyed by dynamicKey (resource path/
	// host + action). When the principal half changes (slug rebind,
	// enforce flip) only the affected bucket is invalidated; the dynamic
	// hit rate for every OTHER principal stays intact.
	bucketed *bucketedCache

	mu       sync.Mutex
	hits     uint64
	misses   uint64
}

// Stats reports cache hits/misses. Used by a future audit event; stub for now.
type Stats struct {
	Hits   uint64
	Misses uint64
}

// NewEngine loads every *.rego file under policyDir (recursively at the top
// level — flat layout is fine) and compiles a query for the canonical
// decision rule, package agentjail.default.
func NewEngine(ctx context.Context, policyDir string) (*OPAEngine, error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", policyDir, err)
	}
	var modules []func(*rego.Rego)
	var loaded int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") {
			continue
		}
		// Skip test files at runtime — they're only for `opa test`.
		if strings.HasSuffix(name, "_test.rego") {
			continue
		}
		full := filepath.Join(policyDir, name)
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", full, rerr)
		}
		modules = append(modules, rego.Module(full, string(b)))
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no .rego policies found in %s", policyDir)
	}
	opts := append(modules,
		rego.Query("data.agentjail.default.decision"),
	)
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile rego: %w", err)
	}
	return &OPAEngine{
		q:        q,
		dir:      policyDir,
		cache:    newLRU(4096),
		bucketed: newBucketedCache(64, 256),
	}, nil
}

// Reload re-reads every *.rego file under the engine's policy directory and
// swaps the prepared query atomically. The decision LRU is cleared so stale
// verdicts from the previous rule set cannot leak. Wired to SIGUSR1 in the
// daemon (Phase 2.5 — cache invalidation on policy reload).
//
// If reload fails (bad rego, missing dir) the existing query is left in
// place and the error is returned. Callers should log and continue.
func (e *OPAEngine) Reload(ctx context.Context) error {
	if e.dir == "" {
		return fmt.Errorf("engine has no policy dir to reload from")
	}
	// Build a fresh prepared query off-path; only swap if it succeeds.
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return fmt.Errorf("read policy dir %s: %w", e.dir, err)
	}
	var modules []func(*rego.Rego)
	var loaded int
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".rego") {
			continue
		}
		if strings.HasSuffix(name, "_test.rego") {
			continue
		}
		full := filepath.Join(e.dir, name)
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", full, rerr)
		}
		modules = append(modules, rego.Module(full, string(b)))
		loaded++
	}
	if loaded == 0 {
		return fmt.Errorf("no .rego policies found in %s", e.dir)
	}
	opts := append(modules, rego.Query("data.agentjail.default.decision"))
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("compile rego: %w", err)
	}
	e.qMu.Lock()
	e.q = q
	e.qMu.Unlock()
	e.ClearCache()
	return nil
}

// ClearCache drops every cached decision. Called by Reload; also exposed so
// tests and the SIGUSR1 handler can flush without rebuilding the query.
func (e *OPAEngine) ClearCache() {
	e.cache.clear()
	if e.bucketed != nil {
		e.bucketed.clear()
	}
}

// InvalidatePrincipal drops every cached decision for the given staticKey
// — used when a session's principal attrs change mid-flight (slug rebind,
// enforce flip). The other principals' caches are untouched.
func (e *OPAEngine) InvalidatePrincipal(staticKey string) {
	if e.bucketed != nil {
		e.bucketed.clearBucket(staticKey)
	}
}

// Eval normalizes and evaluates the input. On any error it returns a default
// allow decision and the error — caller decides whether to surface it.
//
// Cache strategy (Phase 1 / Stream B.1 cache-key split):
//
//   - When in.Principal is populated, route through the bucketed cache:
//     outer key = staticKey(principal) and inner key = dynamicKey(rest).
//     This keeps hit rate intact when per-request principal data flows
//     through (slug rebind no longer invalidates everything).
//   - When in.Principal is nil (legacy callers), fall back to the flat
//     LRU so existing tests + callers see exactly the previous behavior.
//
// Either way the audit-level Stats() counters are bumped uniformly.
func (e *OPAEngine) Eval(ctx context.Context, in Input) (Decision, error) {
	useBucketed := e.bucketed != nil && len(in.Principal) > 0

	if useBucketed {
		sk := PrincipalStaticKey(in.Principal)
		dk := DynamicKey(in)
		if d, ok := e.bucketed.get(sk, dk); ok {
			e.mu.Lock()
			e.hits++
			e.mu.Unlock()
			return d, nil
		}
		e.mu.Lock()
		e.misses++
		e.mu.Unlock()
		d, err := e.evalOnce(ctx, in)
		if err == nil {
			e.bucketed.put(sk, dk, d)
		}
		return d, err
	}

	key := hashInput(in)
	if d, ok := e.cache.get(key); ok {
		e.mu.Lock()
		e.hits++
		e.mu.Unlock()
		return d, nil
	}
	e.mu.Lock()
	e.misses++
	e.mu.Unlock()
	d, err := e.evalOnce(ctx, in)
	if err == nil {
		e.cache.put(key, d)
	}
	return d, err
}

// EvalQuery runs against a non-default decision rule (e.g. the
// experimental package). Lets perm.Service compare verdicts between
// data.agentjail.default.decision and data.agentjail.experimental.decision
// without bypassing the prepared-query Reload story.
//
// No caching: side-by-side disagreement detection is an observability
// concern, not a hot path. Adding it later behind a feature flag is fine.
func (e *OPAEngine) EvalQuery(ctx context.Context, query string, in Input) (Decision, error) {
	e.qMu.RLock()
	defer e.qMu.RUnlock()
	if e.dir == "" {
		return Decision{Action: "allow"}, fmt.Errorf("engine has no policy dir for ad-hoc query")
	}
	// Re-load modules from disk for the ad-hoc query. Cheap enough
	// (disagreement-log is opt-in via env) and avoids holding a second
	// PreparedEvalQuery for every alternate rule package we might want
	// to inspect.
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return Decision{Action: "allow"}, fmt.Errorf("read policy dir: %w", err)
	}
	var modules []func(*rego.Rego)
	for _, ent := range entries {
		if ent.IsDir() {
			// Recurse one level so policies/experimental/*.rego is picked up.
			sub, _ := os.ReadDir(filepath.Join(e.dir, ent.Name()))
			for _, sub2 := range sub {
				if sub2.IsDir() {
					continue
				}
				name := sub2.Name()
				if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
					continue
				}
				full := filepath.Join(e.dir, ent.Name(), name)
				b, rerr := os.ReadFile(full)
				if rerr != nil {
					return Decision{Action: "allow"}, fmt.Errorf("read %s: %w", full, rerr)
				}
				modules = append(modules, rego.Module(full, string(b)))
			}
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		full := filepath.Join(e.dir, name)
		b, rerr := os.ReadFile(full)
		if rerr != nil {
			return Decision{Action: "allow"}, fmt.Errorf("read %s: %w", full, rerr)
		}
		modules = append(modules, rego.Module(full, string(b)))
	}
	opts := append(modules, rego.Query(query))
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return Decision{Action: "allow"}, fmt.Errorf("compile ad-hoc query %q: %w", query, err)
	}
	rs, err := q.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{Action: "allow"}, fmt.Errorf("eval ad-hoc query: %w", err)
	}
	return decisionFromResults(rs), nil
}

// evalOnce runs the prepared default query and turns the result into a
// Decision. Shared between the cached fast path and any future bypass.
func (e *OPAEngine) evalOnce(ctx context.Context, in Input) (Decision, error) {
	e.qMu.RLock()
	q := e.q
	e.qMu.RUnlock()
	rs, err := q.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{Action: "allow"}, fmt.Errorf("rego eval: %w", err)
	}
	return decisionFromResults(rs), nil
}

func decisionFromResults(rs rego.ResultSet) Decision {
	d := Decision{Action: "allow"}
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		if m, ok := rs[0].Expressions[0].Value.(map[string]any); ok {
			if a, _ := m["action"].(string); a != "" {
				d.Action = a
			}
			if r, _ := m["rule_id"].(string); r != "" {
				d.RuleID = r
			}
		}
	}
	return d
}

// Stats returns hit/miss counters (snapshot).
func (e *OPAEngine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Hits: e.hits, Misses: e.misses}
}

// ---- input hashing for cache key ----

// hashInput produces a stable hash across maps by JSON-encoding the input
// with sorted keys. The Input struct has stable field order, but
// Context is a map — we canonicalize it.
func hashInput(in Input) string {
	type canonical struct {
		Input
		CtxKV [][2]string `json:"ctx_kv,omitempty"`
	}
	c := canonical{Input: in}
	if len(in.Context) > 0 {
		keys := make([]string, 0, len(in.Context))
		for k := range in.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		c.CtxKV = make([][2]string, 0, len(keys))
		for _, k := range keys {
			c.CtxKV = append(c.CtxKV, [2]string{k, fmt.Sprintf("%v", in.Context[k])})
		}
		c.Input.Context = nil // already represented in CtxKV
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- tiny LRU (no external deps) ----

type lruCache struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntry struct {
	key string
	val Decision
}

func newLRU(cap int) *lruCache {
	return &lruCache{cap: cap, ll: list.New(), items: make(map[string]*list.Element, cap)}
}

func (c *lruCache) get(k string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry).val, true
	}
	return Decision{}, false
}

// clear drops every entry. Used by Engine.Reload (and SIGUSR1) to invalidate
// cached decisions when the underlying rule set changes.
func (c *lruCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll = list.New()
	c.items = make(map[string]*list.Element, c.cap)
}

func (c *lruCache) put(k string, v Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		el.Value.(*lruEntry).val = v
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: k, val: v})
	c.items[k] = el
	if c.ll.Len() > c.cap {
		old := c.ll.Back()
		if old != nil {
			c.ll.Remove(old)
			delete(c.items, old.Value.(*lruEntry).key)
		}
	}
}

// ---- Phase 1 cache-key split: staticKey + dynamicKey ----
//
// The previous cache hashed the entire Input. When per-request principal
// attrs flow through (slug, user, enforce flag), the key changes on every
// request and the LRU hit rate collapses. The split below pins the
// slow-changing principal fields under their own bucket so the
// dynamic-key sub-cache keeps doing its job per principal.
//
// staticKey  = sha256(principal.agent + principal.user + principal.enforce
//                     + principal.cwd_repo)
// dynamicKey = sha256(action + resource.id + resource.kind + a small set
//                     of resource attr keys that affect rule matching)

// PrincipalStaticKey hashes the slow-changing principal half of an Input.
// Exposed (capital-letter) so perm.Service and tests can compute it without
// duplicating the canonicalization rules.
//
// Renamed from StaticKey to make room for the new StaticKey(Input)
// CacheKey function defined in cache.go, which keys on the static tool-input
// fields (hook, command pattern, path) rather than principal attributes.
func PrincipalStaticKey(principal map[string]any) string {
	if len(principal) == 0 {
		return "no-principal"
	}
	h := sha256.New()
	attr, _ := principal["attr"].(map[string]any)
	if attr == nil {
		attr = principal
	}
	for _, k := range []string{"agent", "user", "enforce", "cwd_repo", "home", "trust_tier"} {
		_, _ = fmt.Fprintf(h, "%s=%v|", k, attr[k])
	}
	if id, ok := principal["id"].(string); ok {
		// Include the session-scoped id ONLY at low priority — we want
		// two sessions for the same (agent,user) to share the bucket
		// boundary but not the inner key space. Including it here means
		// the BUCKETS are per-session, which is what we want: session
		// teardown drops only its own bucket.
		_, _ = fmt.Fprintf(h, "sid=%s", id)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// DynamicKey hashes the fast-changing half: action + resource id + the
// resource attrs that the legacy rules match on. Order is deterministic.
func DynamicKey(in Input) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "action=%s|", in.Action)
	if in.Resource != nil {
		kind, _ := in.Resource["kind"].(string)
		id, _ := in.Resource["id"].(string)
		_, _ = fmt.Fprintf(h, "kind=%s|id=%s|", kind, id)
		if attr, ok := in.Resource["attr"].(map[string]any); ok {
			keys := make([]string, 0, len(attr))
			for k := range attr {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				_, _ = fmt.Fprintf(h, "%s=%v|", k, attr[k])
			}
		}
	}
	// Fall back to legacy fields so rules that only set Principal still
	// produce a discriminating key (e.g. an exec frame with no Resource
	// map but a populated Program / Path).
	_, _ = fmt.Fprintf(h, "hook=%s|op=%s|program=%s|path=%s|host=%s|method=%s|",
		in.Hook, in.Op, in.Program, in.Path, in.Host, in.Method)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// bucketedCache is a two-level LRU: a top-level map of staticKey ->
// inner *lruCache. Each bucket holds dynamicKey -> Decision entries.
// Invalidating one principal clears only that bucket, never the others.
type bucketedCache struct {
	mu        sync.Mutex
	bucketCap int // max entries inside each inner LRU
	maxBuckets int
	buckets   map[string]*lruCache
}

func newBucketedCache(maxBuckets, bucketCap int) *bucketedCache {
	return &bucketedCache{
		bucketCap:  bucketCap,
		maxBuckets: maxBuckets,
		buckets:    make(map[string]*lruCache, maxBuckets),
	}
}

func (b *bucketedCache) get(staticKey, dynamicKey string) (Decision, bool) {
	b.mu.Lock()
	bucket, ok := b.buckets[staticKey]
	b.mu.Unlock()
	if !ok {
		return Decision{}, false
	}
	return bucket.get(dynamicKey)
}

func (b *bucketedCache) put(staticKey, dynamicKey string, d Decision) {
	b.mu.Lock()
	bucket, ok := b.buckets[staticKey]
	if !ok {
		// Crude eviction: when we hit the bucket-count cap drop the
		// largest bucket. Phase 1 traffic is single-session so we don't
		// expect to exercise this branch in practice; the safeguard is
		// here so a long-lived daemon with many short sessions doesn't
		// leak memory.
		if len(b.buckets) >= b.maxBuckets {
			var victim string
			var biggest int
			for k, v := range b.buckets {
				if v.ll.Len() > biggest {
					biggest = v.ll.Len()
					victim = k
				}
			}
			if victim != "" {
				delete(b.buckets, victim)
			}
		}
		bucket = newLRU(b.bucketCap)
		b.buckets[staticKey] = bucket
	}
	b.mu.Unlock()
	bucket.put(dynamicKey, d)
}

// clear drops every bucket.
func (b *bucketedCache) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buckets = make(map[string]*lruCache, b.maxBuckets)
}

// clearBucket drops a single principal's bucket; other principals keep
// their dynamic-key hit rate.
func (b *bucketedCache) clearBucket(staticKey string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.buckets, staticKey)
}

// bucketCount is for test instrumentation only.
func (b *bucketedCache) bucketCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}
