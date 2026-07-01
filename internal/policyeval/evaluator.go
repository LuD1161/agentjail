// Package policyeval encapsulates OPA policy evaluation for agentjail.
//
// It owns the HookEngine, LRU cache, generation counter, per-project engine
// map, repo-root cache, AWS profile cache, and ask-promotion tracking — all
// of which were previously embedded in the daemon's server struct. The daemon
// now holds an Evaluator and delegates Eval/Reload to it.
package policyeval

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/shellparse"
)

// Request is the canonical eval request shape, mirroring wire.Request.
type Request struct {
	ID        string                 `json:"id"`
	HookEvent string                 `json:"hook_event"`
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	SessionID string                 `json:"session_id"`
	CWD       string                 `json:"cwd"`
	Agent     string                 `json:"agent,omitempty"`
	AgentPID  int                    `json:"agent_pid,omitempty"`
}

// Response is the canonical eval response shape, mirroring wire.Response.
type Response struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	RuleID string `json:"rule_id,omitempty"`
	Impact string `json:"impact,omitempty"`
}

// Evaluator evaluates policy requests and manages OPA engine lifecycle.
type Evaluator interface {
	Eval(ctx context.Context, req Request) (Response, error)
	Reload(ctx context.Context, modules [][2]string, cfg *agentconfig.PolicyConfig) error
}

// evaluator is the concrete implementation of Evaluator.
type evaluator struct {
	engineMu sync.RWMutex
	engine   policy.HookEngine
	cache    policy.Cache
	gen      atomic.Uint64

	// cfg and modules are guarded by engineMu.
	cfg     *agentconfig.PolicyConfig
	modules [][2]string

	// repoRootCache maps canonical cwd -> git repo root (or "" for non-git dirs).
	repoRootMu    sync.RWMutex
	repoRootCache map[string]string

	// awsProfiles is a lazily-parsed view of ~/.aws/config.
	awsCfgMu    sync.Mutex
	awsProfiles map[string]awsProfileInfo

	// sessionAskSeen tracks (sessionID, ruleID) pairs for ask-promotion.
	sessionAskMu   sync.RWMutex
	sessionAskSeen map[string]map[string]bool

	// Per-project policy engine cache keyed by repo root path.
	projectEngMu   sync.RWMutex
	projectEngines map[string]*projectEngine
}

// New creates a new Evaluator with the given initial engine, cache, modules,
// and config. The caller (daemon) builds the initial OPA engine and passes it
// in; subsequent reloads go through Reload().
func New(engine policy.HookEngine, cache policy.Cache, modules [][2]string, cfg *agentconfig.PolicyConfig) Evaluator {
	return &evaluator{
		engine:  engine,
		cache:   cache,
		modules: modules,
		cfg:     cfg,
	}
}

// Eval evaluates a single request and returns the decision. The cache check
// happens before calling the engine so warm decisions are returned in < 1 ms.
func (e *evaluator) Eval(ctx context.Context, req Request) (Response, error) {
	// Normalize cwd and path fields BEFORE eval so all policies see canonical
	// absolute paths.
	canonCWD := CanonicalizeCWD(req.CWD)
	normalizedInput := NormalizeToolInput(req.ToolInput, canonCWD)

	input := policy.HookInput{
		HookEvent: req.HookEvent,
		ToolName:  req.ToolName,
		ToolInput: normalizedInput,
		SessionID: req.SessionID,
		CWD:       canonCWD,
		RepoRoot:  e.resolveRepoRoot(canonCWD),
	}

	// AWS account resolution (ADR 0017): for `aws --profile <name>` CLI
	// commands, resolve the targeted account id from ~/.aws/config and inject
	// it as input.aws_account so aws_policy/posture can apply per-account
	// posture.
	if req.ToolName == "Bash" {
		if cmd, ok := normalizedInput["command"].(string); ok && IsAWSCLICommand(cmd) {
			input.AWSAccount = e.resolveAWSAccount(cmd)
		}
	}

	// Shell command parsing (ADR 0025): for Bash tool calls, parse the
	// command string into structured components so Rego rules can check
	// command binaries without regex matching on the raw string.
	if req.ToolName == "Bash" {
		if cmd, ok := normalizedInput["command"].(string); ok {
			parsed := shellparse.Parse(cmd)
			input.CommandBinaries = parsed.Binaries
		}
	}

	// Cache key includes the canonical cwd so a file decision that varies by
	// cwd is never served from the wrong entry.
	cacheKey := HookCacheKey(input)

	// Per-project policy: check <RepoRoot>/.agentjail/policy.yaml
	eng, cache := e.resolveProjectEngine(ctx, input.RepoRoot)
	isProjectEng := eng != nil
	var genAtStart uint64
	if !isProjectEng {
		// No project config -> use global engine.
		e.engineMu.RLock()
		eng = e.engine
		cache = e.cache
		genAtStart = e.gen.Load()
		e.engineMu.RUnlock()
	}

	if d, ok := cache.Get(cacheKey); ok {
		return Response{
			ID:     req.ID,
			Action: d.Action,
			Reason: d.Reason,
			RuleID: d.RuleID,
			Impact: d.Impact,
		}, nil
	}

	d, err := eng.Eval(ctx, input)
	if err != nil {
		return Response{
			ID:     req.ID,
			Action: "ask",
			Reason: "policy evaluation error: " + err.Error(),
		}, err
	}

	// For ask verdicts: if this (session, ruleID) was already asked before,
	// the user approved it. Promote to allow on the second+ occurrence.
	if d.Action == "ask" && e.checkAndRecordAsk(req.SessionID, d.RuleID) {
		return Response{
			ID:     req.ID,
			Action: "allow",
			Reason: "approved earlier in this session",
			RuleID: "session/grant",
		}, nil
	}

	// Only cache non-ask decisions.
	if d.Action != "ask" {
		if isProjectEng || e.gen.Load() == genAtStart {
			cache.Set(cacheKey, d)
		}
	}

	return Response{
		ID:     req.ID,
		Action: d.Action,
		Reason: d.Reason,
		RuleID: d.RuleID,
		Impact: d.Impact,
	}, nil
}

// Reload rebuilds the OPA engine from the given Rego modules and atomically
// swaps it in under the write lock. The cache is invalidated so stale
// verdicts from the old rule set cannot leak.
func (e *evaluator) Reload(ctx context.Context, modules [][2]string, cfg *agentconfig.PolicyConfig) error {
	opaData := map[string]interface{}{
		"config": cfg.ToOPAData(),
	}

	eng, err := policy.NewHookOPAEngineWithData(ctx, modules, opaData)
	if err != nil {
		return fmt.Errorf("compile rego: %w", err)
	}
	e.engineMu.Lock()
	e.engine = eng
	e.cfg = cfg
	e.modules = modules
	e.gen.Add(1)
	e.cache.Invalidate()
	e.engineMu.Unlock()

	// Invalidate the AWS profile cache so edits to ~/.aws/config take effect.
	e.awsCfgMu.Lock()
	e.awsProfiles = nil
	e.awsCfgMu.Unlock()

	// Invalidate all project engine caches so project policies are
	// re-merged against the new global config on next eval.
	e.projectEngMu.Lock()
	e.projectEngines = nil
	e.projectEngMu.Unlock()

	return nil
}

// checkAndRecordAsk checks whether this (session, ruleID) has been asked before.
// If yes, returns true (the user approved last time -> promote to allow).
// If no, records it and returns false (first time -> ask the user).
func (e *evaluator) checkAndRecordAsk(sessionID, ruleID string) bool {
	if sessionID == "" || ruleID == "" {
		return false
	}
	e.sessionAskMu.Lock()
	defer e.sessionAskMu.Unlock()
	if e.sessionAskSeen == nil {
		e.sessionAskSeen = make(map[string]map[string]bool)
	}
	if e.sessionAskSeen[sessionID] == nil {
		e.sessionAskSeen[sessionID] = make(map[string]bool)
	}
	if e.sessionAskSeen[sessionID][ruleID] {
		return true
	}
	e.sessionAskSeen[sessionID][ruleID] = true
	return false
}

// BuildTempRoots returns the set of temp-dir roots that the Rego policy should
// treat as scratch space.
func BuildTempRoots() []string {
	roots := make([]string, 0, 4)

	tmpDir := os.TempDir()
	if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
		tmpDir = resolved
	}
	roots = append(roots, tmpDir)

	for _, structural := range []string{"/tmp", "/private/tmp"} {
		if resolved, err := filepath.EvalSymlinks(structural); err == nil {
			structural = resolved
		}
		roots = dedupAppend(roots, structural)
	}

	return roots
}

// dedupAppend appends s to slice only if not already present.
func dedupAppend(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// SummarizeToolInput returns a short, log-safe identifier for a tool call.
// Bash -> the command (truncated). File tools -> the file_path. MCP/others ->
// fall back to the most informative single string field. Empty if nothing
// useful is available. Truncated to 200 bytes; multi-line collapsed to one.
func SummarizeToolInput(tool string, in map[string]interface{}) string {
	if in == nil {
		return ""
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := in[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	var s string
	switch tool {
	case "Bash":
		s = pick("command")
	case "Write", "Edit", "Read", "NotebookEdit":
		s = pick("file_path", "path", "notebook_path")
	default:
		s = pick("file_path", "path", "command", "query", "url", "pattern")
	}
	if s == "" {
		return ""
	}
	// One line, bounded length.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}

// resolveRepoRoot returns the git repo root for the given canonical cwd.
// Results are cached.
func (e *evaluator) resolveRepoRoot(cwd string) string {
	if cwd == "" {
		return ""
	}

	e.repoRootMu.RLock()
	if root, ok := e.repoRootCache[cwd]; ok {
		e.repoRootMu.RUnlock()
		return root
	}
	e.repoRootMu.RUnlock()

	// Run git rev-parse --show-toplevel with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", cwd, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	root := ""
	if err == nil {
		root = strings.TrimSpace(string(out))
		if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
			root = resolved
		}
	}

	e.repoRootMu.Lock()
	if e.repoRootCache == nil {
		e.repoRootCache = make(map[string]string)
	}
	e.repoRootCache[cwd] = root
	e.repoRootMu.Unlock()

	return root
}

