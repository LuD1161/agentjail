package policyeval

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
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
// <repoRoot>/.agentjail/policy.yaml. If found, it returns a compiled OPA
// engine with the project config merged over the global config, plus a
// per-project LRU cache. Results are cached by repo root and invalidated
// when the file content changes (SHA-256 hash check). Returns (nil, nil)
// when no project policy exists or on any error (fail-open to global).
func (e *evaluator) resolveProjectEngine(ctx context.Context, repoRoot string) (policy.HookEngine, policy.Cache) {
	if repoRoot == "" {
		return nil, nil
	}

	projectPolicyPath := filepath.Join(repoRoot, ".agentjail", "policy.yaml")

	// Quick check: does the file exist?
	content, err := os.ReadFile(projectPolicyPath)
	if err != nil {
		return nil, nil // no project policy
	}

	hash := Sha256Hex(content)

	// Check cache (read lock - fast path).
	e.projectEngMu.RLock()
	if pe, ok := e.projectEngines[repoRoot]; ok && pe.configHash == hash {
		e.projectEngMu.RUnlock()
		return pe.eng, pe.cache
	}
	e.projectEngMu.RUnlock()

	// Build merged config: global base + project overlay.
	e.engineMu.RLock()
	globalCfg := e.cfg
	mods := e.modules
	e.engineMu.RUnlock()

	if globalCfg == nil {
		return nil, nil // not yet initialized
	}

	projectCfg, err := agentconfig.Load(projectPolicyPath)
	if err != nil {
		slog.Warn("project policy.yaml malformed - falling back to global",
			"path", projectPolicyPath, "err", err)
		return nil, nil
	}

	mergedCfg := agentconfig.Merge(globalCfg, projectCfg)
	mergedCfg.File.TempRoots = BuildTempRoots()

	opaData := map[string]interface{}{
		"config": mergedCfg.ToOPAData(),
	}

	eng, err := policy.NewHookOPAEngineWithData(ctx, mods, opaData)
	if err != nil {
		slog.Warn("project policy engine compilation failed - falling back to global",
			"path", projectPolicyPath, "err", err)
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
