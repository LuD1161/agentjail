package policyeval

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
)

// projectEngine holds a compiled OPA engine for a specific project's merged
// config. The configHash allows cheap invalidation when the project's
// policy.yaml changes on disk.
type projectEngine struct {
	eng        policy.HookEngine
	cache      policy.Cache
	configHash string // hex SHA-256 of project policy.yaml content
}

// resolveProjectEngine checks for a per-project policy file at
// <repoRoot>/.agentjail/policy.yaml. The overlay is applied ONLY if the
// project directory is TRUSTED (direnv-style: `agentjail trust`) via the same
// ~/.agentjail/trusted.yaml store used by the shield's netproxy path and the
// daemon's grant-persistence path (see internal/projectpolicy). An untrusted
// or malformed overlay is ignored and this returns (nil, nil), which causes
// the caller to fall back to the global engine.
//
// When trusted, the overlay is merged additively via
// agentconfig.MergeProjectOverlay -- it can only WIDEN allowlists
// (network hosts, MCP allowed/blocked), and can never touch disabled_rules
// or otherwise narrow the global policy. This mirrors internal/projectpolicy
// .Resolve; do not use agentconfig.Merge here, which lets an overlay REPLACE
// disabled_rules and neuter the whole rule set.
//
// Results are cached by repo root and invalidated when the overlay content
// changes (content-hash check) or trust is revoked. Returns (nil, nil) when
// no project policy exists, it isn't trusted, or on any error (fail-open to
// global).
func (e *evaluator) resolveProjectEngine(ctx context.Context, repoRoot string) (policy.HookEngine, policy.Cache) {
	if repoRoot == "" {
		return nil, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	// FindOverlay is called with repoRoot as the start dir: since repoRoot is
	// already the git root, this checks exactly <repoRoot>/.agentjail/policy.yaml
	// (its own ceiling), matching the previous single-path lookup.
	overlay, err := projectpolicy.FindOverlay(repoRoot, homeDir)
	if err != nil || overlay == nil {
		return nil, nil // no project policy, or discovery error -> fail open to global
	}

	trustPath := projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
	ts, err := projectpolicy.LoadTrustStore(trustPath)
	if err != nil {
		slog.Warn("project trust store unreadable - ignoring project overlay",
			"path", trustPath, "err", err)
		return nil, nil // fail safe: treat as untrusted
	}
	if !ts.IsTrusted(overlay) {
		// Untrusted (or trusted-then-edited) overlay: never applied. The global
		// engine is used instead -- an attacker-controlled policy.yaml cannot
		// weaken (or widen) enforcement until a human runs `agentjail trust`.
		return nil, nil
	}

	hash := overlay.ContentHash

	// Check cache (read lock - fast path).
	e.projectEngMu.RLock()
	if pe, ok := e.projectEngines[repoRoot]; ok && pe.configHash == hash {
		e.projectEngMu.RUnlock()
		return pe.eng, pe.cache
	}
	e.projectEngMu.RUnlock()

	// Build merged config: global base + trusted project overlay.
	e.engineMu.RLock()
	globalCfg := e.cfg
	mods := e.modules
	e.engineMu.RUnlock()

	if globalCfg == nil {
		return nil, nil // not yet initialized
	}

	projectCfg, err := agentconfig.Load(overlay.Path)
	if err != nil {
		slog.Warn("project policy.yaml malformed - falling back to global",
			"path", overlay.Path, "err", err)
		return nil, nil
	}

	// Additive-only merge: can only widen allowlists, never disable rules.
	mergedCfg := agentconfig.MergeProjectOverlay(globalCfg, projectCfg)
	mergedCfg.File.TempRoots = BuildTempRoots()

	opaData := map[string]interface{}{
		"config": mergedCfg.ToOPAData(),
	}

	eng, err := policy.NewHookOPAEngineWithData(ctx, mods, opaData)
	if err != nil {
		slog.Warn("project policy engine compilation failed - falling back to global",
			"path", overlay.Path, "err", err)
		return nil, nil
	}

	newCache := policy.NewLRUCache(1024)

	// Store in cache (write lock).
	e.projectEngMu.Lock()
	if e.projectEngines == nil {
		e.projectEngines = make(map[string]*projectEngine)
	}
	e.projectEngines[repoRoot] = &projectEngine{
		eng:        eng,
		cache:      newCache,
		configHash: hash,
	}
	e.projectEngMu.Unlock()

	return eng, newCache
}
