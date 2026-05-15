// Package policy is the public facade for the agentpolicy decision
// engine. It re-exports the small set of symbols that callers outside
// the agentpolicy module need (Input, Decision, Engine, NewEngine, plus
// the hook-wire-format types).
//
// The implementation lives at agentpolicy/internal/policy. Putting the
// real types there keeps the engine's internals (LRU cache, hashing,
// bucketed cache) unreachable from outside the agentpolicy module while
// still letting downstream modules consume the supported surface
// through this thin alias layer.
//
// Wire-shape note: Input and Decision are type aliases (not new
// structs) so the JSON representation on the sync decision RPC channel
// from commit 264eadd stays byte-identical.
package policy

import (
	"context"

	internalpolicy "github.com/LuD1161/agentjail/agentpolicy/internal/policy"
)

// Input is the canonical policy input record. See
// agentpolicy/internal/policy for full field documentation.
type Input = internalpolicy.Input

// Decision is the policy evaluator's verdict.
type Decision = internalpolicy.Decision

// Engine is the concrete OPA engine implementation. It wraps a compiled
// Rego query plus a decision LRU. New callers should depend on the
// internalpolicy.Engine interface; this alias is kept for backwards compat.
type Engine = internalpolicy.OPAEngine

// HookEngine is the interface satisfied by hookOPAEngine. New
// callers — particularly agentjail-daemon — should depend on this
// interface rather than the concrete *OPAEngine so the backend can be
// swapped in tests without touching the daemon.
type HookEngine = internalpolicy.Engine

// HookInput is the hook-wire-format input record. Fields match
// the Claude Code PreToolUse JSON payload exactly (snake_case).
type HookInput = internalpolicy.HookInput

// Cache is the decision-cache interface. Implementations must be
// safe for concurrent use.
type Cache = internalpolicy.Cache

// CacheKey identifies the static portion of a hook input for cache lookup.
type CacheKey = internalpolicy.CacheKey

// DefaultCacheSize is the default maximum LRU cache entry count.
const DefaultCacheSize = internalpolicy.DefaultCacheSize

// NewEngine loads every *.rego file under policyDir and compiles a
// query for the canonical decision rule (package agentjail.default).
func NewEngine(ctx context.Context, policyDir string) (*Engine, error) {
	return internalpolicy.NewEngine(ctx, policyDir)
}

// NewHookOPAEngine compiles the given Rego modules into a PreparedEvalQuery
// and returns a ready-to-use HookEngine. Each element of modules is a
// (filename, rego-source) pair.
func NewHookOPAEngine(ctx context.Context, modules [][2]string) (HookEngine, error) {
	return internalpolicy.NewHookOPAEngine(ctx, modules)
}

// NewHookOPAEngineWithData compiles the given Rego modules and wires the
// provided data document into OPA as data.agentjail.<keys>.  Pass
// cfg.ToOPAData() as agentjailData to project a PolicyConfig into the engine.
// Pass nil agentjailData to skip data injection (equivalent to NewHookOPAEngine).
func NewHookOPAEngineWithData(ctx context.Context, modules [][2]string, agentjailData map[string]interface{}) (HookEngine, error) {
	return internalpolicy.NewHookOPAEngineWithData(ctx, modules, agentjailData)
}

// NewLRUCache returns a Cache backed by an LRU eviction policy.
// maxEntries must be > 0; pass DefaultCacheSize if you have no specific
// requirement.
func NewLRUCache(maxEntries int) Cache {
	return internalpolicy.NewLRUCache(maxEntries)
}
