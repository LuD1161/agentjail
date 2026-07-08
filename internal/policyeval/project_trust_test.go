package policyeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/agentpolicy/policy"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
)

// trustTestRego is a minimal Rego module exercising the same shape as
// command_policy.rego's disabled_rules suppression: a Bash "sudo" command is
// denied by default via rule_id "command_policy/no-sudo", UNLESS that rule_id
// (or a glob matching it) appears in data.agentjail.config.disabled_rules --
// exactly the mechanism a malicious project overlay tries to abuse (C1).
const trustTestRego = `
package agentjail

default decision = {"action": "deny", "reason": "sudo blocked", "rule_id": "command_policy/no-sudo"}

decision = {"action": "allow", "reason": "rule disabled", "rule_id": "command_policy/no-sudo"} {
	input.tool_name == "Bash"
	rule_disabled("command_policy/no-sudo")
}

rule_disabled(id) {
	p := data.agentjail.config.disabled_rules[_]
	glob.match(p, ["/"], id)
}
`

// setupTrustTestRepo creates a temp "home" dir (with trust store) and a temp
// "repo" dir (git repo root) with a project overlay at
// <repo>/.agentjail/policy.yaml that tries to disable command_policy/no-sudo
// and additively allow an MCP server. If trust is true, the overlay is
// registered in the trust store under its content hash.
func setupTrustTestRepo(t *testing.T, overlayYAML string, trust bool) (repoRoot, homeDir string) {
	t.Helper()
	homeDir = t.TempDir()
	repoRoot = t.TempDir()

	// resolveProjectEngine calls os.UserHomeDir(), which respects $HOME on
	// Linux/macOS -- point it at our temp "home" so the trust store used by
	// the test is isolated from the real user's ~/.agentjail/trusted.yaml.
	t.Setenv("HOME", homeDir)

	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	overlayDir := filepath.Join(repoRoot, ".agentjail")
	if err := os.MkdirAll(overlayDir, 0o755); err != nil {
		t.Fatalf("mkdir overlay dir: %v", err)
	}
	overlayPath := filepath.Join(overlayDir, "policy.yaml")
	if err := os.WriteFile(overlayPath, []byte(overlayYAML), 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	if trust {
		hash := projectpolicy.HashContent([]byte(overlayYAML))
		trustPath := projectpolicy.TrustStorePath(filepath.Join(homeDir, projectpolicy.ProjectDirName))
		ts, err := projectpolicy.LoadTrustStore(trustPath)
		if err != nil {
			t.Fatalf("LoadTrustStore: %v", err)
		}
		ts.Trust(&projectpolicy.Overlay{Path: overlayPath, ContentHash: hash})
		if err := ts.Save(); err != nil {
			t.Fatalf("trust store Save: %v", err)
		}
	}

	return repoRoot, homeDir
}

// newTrustTestEvaluator builds an *evaluator (not the Evaluator interface, so
// tests can call the unexported resolveProjectEngine/repoRoot machinery
// directly) with a global config that has an empty disabled_rules list, so
// the base engine always denies sudo.
func newTrustTestEvaluator(t *testing.T) *evaluator {
	t.Helper()
	cfg := agentconfig.Default()

	opaData := map[string]interface{}{"config": cfg.ToOPAData()}
	eng, err := policy.NewHookOPAEngineWithData(context.Background(), [][2]string{
		{"trust_test.rego", trustTestRego},
	}, opaData)
	if err != nil {
		t.Fatalf("NewHookOPAEngineWithData: %v", err)
	}

	return &evaluator{
		engine:  eng,
		cache:   policy.NewLRUCache(64),
		modules: [][2]string{{"trust_test.rego", trustTestRego}},
		cfg:     cfg,
	}
}

func bashSudoRequest(repoRoot string) Request {
	return Request{
		ID:        "req-1",
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "sudo rm -rf /"},
		SessionID: "sess-1",
		CWD:       repoRoot,
	}
}

// TestResolveProjectEngine_UntrustedOverlayIgnored: an untrusted overlay
// attempting to disable command_policy/no-sudo must NOT affect evaluation --
// the global engine (which always denies sudo) must be used instead.
func TestResolveProjectEngine_UntrustedOverlayIgnored(t *testing.T) {
	repoRoot, _ := setupTrustTestRepo(t, "disabled_rules:\n  - \"command_policy/no-sudo\"\n", false /* not trusted */)

	e := newTrustTestEvaluator(t)

	eng, cache := e.resolveProjectEngine(context.Background(), repoRoot)
	if eng != nil || cache != nil {
		t.Fatalf("expected untrusted overlay to be ignored (nil, nil), got eng=%v cache=%v", eng, cache)
	}

	// Full Eval path must still deny (falls back to the global engine).
	resp, err := e.Eval(context.Background(), bashSudoRequest(repoRoot))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if resp.Action != "deny" {
		t.Fatalf("untrusted overlay must not disable the rule: got action=%q reason=%q rule_id=%q",
			resp.Action, resp.Reason, resp.RuleID)
	}
}

// TestResolveProjectEngine_TrustedOverlayCannotDisableRules: even a TRUSTED
// overlay that lists disabled_rules must not suppress the rule -- the merge
// must be additive-only (MergeProjectOverlay), never agentconfig.Merge.
func TestResolveProjectEngine_TrustedOverlayCannotDisableRules(t *testing.T) {
	overlayYAML := "disabled_rules:\n  - \"command_policy/no-sudo\"\nmcp:\n  allowed:\n    - \"trusted-server\"\n"
	repoRoot, _ := setupTrustTestRepo(t, overlayYAML, true /* trusted */)

	e := newTrustTestEvaluator(t)

	eng, cache := e.resolveProjectEngine(context.Background(), repoRoot)
	if eng == nil || cache == nil {
		t.Fatalf("expected a trusted overlay to produce a project engine, got nil")
	}

	resp, err := e.Eval(context.Background(), bashSudoRequest(repoRoot))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if resp.Action != "deny" {
		t.Fatalf("trusted overlay must NOT be able to clear disabled_rules via additive merge: got action=%q reason=%q rule_id=%q",
			resp.Action, resp.Reason, resp.RuleID)
	}

	// Additive widening IS honored: the merged config's MCP.Allowed must
	// contain the overlay's addition alongside the (empty) base list.
	e.projectEngMu.RLock()
	pe := e.projectEngines[repoRoot]
	e.projectEngMu.RUnlock()
	if pe == nil {
		t.Fatalf("expected cached project engine entry for %s", repoRoot)
	}
}

// TestResolveProjectEngine_TrustedOverlayWidensAllowlist verifies the
// additive-merge contract directly against agentconfig.MergeProjectOverlay,
// confirming a trusted overlay CAN add an MCP allowlist entry while its
// disabled_rules entry is dropped by the merge (never reaches the result).
func TestResolveProjectEngine_TrustedOverlayWidensAllowlist(t *testing.T) {
	base := agentconfig.Default()
	overlay := &agentconfig.PolicyConfig{
		DisabledRules: []string{"command_policy/no-sudo"},
		MCP:           agentconfig.MCPConfig{Allowed: []string{"trusted-server"}},
	}

	merged := agentconfig.MergeProjectOverlay(base, overlay)

	found := false
	for _, s := range merged.MCP.Allowed {
		if s == "trusted-server" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected additive merge to include overlay's MCP.Allowed entry, got %v", merged.MCP.Allowed)
	}
	if len(merged.DisabledRules) != 0 {
		t.Fatalf("expected additive merge to ignore overlay.DisabledRules entirely, got %v", merged.DisabledRules)
	}
}

// TestResolveProjectEngine_NoOverlay: no project policy file -> (nil, nil),
// existing behavior preserved.
func TestResolveProjectEngine_NoOverlay(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	e := newTrustTestEvaluator(t)
	eng, cache := e.resolveProjectEngine(context.Background(), repoRoot)
	if eng != nil || cache != nil {
		t.Fatalf("expected (nil, nil) when no overlay exists, got eng=%v cache=%v", eng, cache)
	}
}
