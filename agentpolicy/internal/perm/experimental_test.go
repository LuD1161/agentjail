package perm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/policy"
)

// repoPolicies walks up looking for the agentpolicy/policies/ dir at the
// repo root. Robust against worktree layouts.
func repoPolicies(t *testing.T) string {
	t.Helper()
	cwd, _ := os.Getwd()
	dir := cwd
	for {
		cand := filepath.Join(dir, "agentpolicy", "policies", "default.rego")
		if _, err := os.Stat(cand); err == nil {
			return filepath.Join(dir, "agentpolicy", "policies")
		}
		// Allow the test to run from inside agentpolicy/ as well.
		if _, err := os.Stat(filepath.Join(dir, "policies", "default.rego")); err == nil {
			return filepath.Join(dir, "policies")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not locate repo policies")
		}
		dir = parent
	}
}

// TestExperimentalRuleFiresEndToEnd loads the REAL policies directory
// (default + experimental/principal_shape.rego) and proves the new
// principal-shape rule fires for agent comp-intel + resource.kind=file
// + action=read under cwd_repo.
func TestExperimentalRuleFiresEndToEnd(t *testing.T) {
	policyDir := repoPolicies(t)
	eng, err := policy.NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	sess := &SessionRef{ID: "sid", AgentSlug: "comp-intel", User: "alice"}
	pctx := PrincipalCtx{Home: "/Users/alice", CwdRepo: "/Users/alice/repo"}
	req := FromFrame(FrameInput{Hook: "file", Op: "readFile", Attrs: map[string]any{
		"path": "/Users/alice/repo/main.go",
	}}, sess, pctx)

	dec, err := eng.EvalQuery(context.Background(), ExperimentalDecisionQuery, BuildPolicyInput(req))
	if err != nil {
		t.Fatalf("exp eval: %v", err)
	}
	if dec.Action != "allow" || dec.RuleID != "comp-intel-read-in-cwd-repo" {
		t.Errorf("expected experimental ALLOW with rule comp-intel-read-in-cwd-repo, got %+v", dec)
	}
}

// TestExperimentalRuleDeniesWriteOutsideRepo pins the second example
// rule fires correctly.
func TestExperimentalRuleDeniesWriteOutsideRepo(t *testing.T) {
	policyDir := repoPolicies(t)
	eng, err := policy.NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	sess := &SessionRef{ID: "sid", AgentSlug: "comp-intel", User: "alice"}
	pctx := PrincipalCtx{Home: "/Users/alice", CwdRepo: "/Users/alice/repo"}
	req := FromFrame(FrameInput{Hook: "file", Op: "writeFile", Attrs: map[string]any{
		"path": "/etc/passwd",
	}}, sess, pctx)

	dec, err := eng.EvalQuery(context.Background(), ExperimentalDecisionQuery, BuildPolicyInput(req))
	if err != nil {
		t.Fatalf("exp eval: %v", err)
	}
	if dec.Action != "deny" || dec.RuleID != "comp-intel-no-write-outside-cwd-repo" {
		t.Errorf("expected DENY comp-intel-no-write-outside-cwd-repo, got %+v", dec)
	}
}

// TestExperimentalRuleLeavesOtherAgentsAlone — non-comp-intel agents
// must not be affected by the experimental gating.
func TestExperimentalRuleLeavesOtherAgentsAlone(t *testing.T) {
	policyDir := repoPolicies(t)
	eng, err := policy.NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	sess := &SessionRef{ID: "sid", AgentSlug: "claude-code-mbp", User: "alice"}
	pctx := PrincipalCtx{Home: "/Users/alice", CwdRepo: "/Users/alice/repo"}
	req := FromFrame(FrameInput{Hook: "file", Op: "writeFile", Attrs: map[string]any{"path": "/tmp/x"}},
		sess, pctx)
	dec, err := eng.EvalQuery(context.Background(), ExperimentalDecisionQuery, BuildPolicyInput(req))
	if err != nil {
		t.Fatalf("exp eval: %v", err)
	}
	if dec.Action != "allow" {
		t.Errorf("other agent should fall through to default allow, got %+v", dec)
	}
}
