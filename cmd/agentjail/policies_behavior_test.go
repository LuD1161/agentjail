// policies_behavior_test.go — enforcement tests for the EMBED MIRROR policy tree
// (cmd/agentjail/policies/*.rego) using the OPA Go SDK directly.
//
// After R1 the mirror is byte-identical to agentpolicy/policies/ (candidate +
// resolver pattern), so no source-tree substitution is needed.  All modules are
// loaded purely from the embedded bytes: allCoreRuleBytes() for the four core
// files (command_policy, file_policy, mcp_policy, resolver) and
// libraryRuleContent("no_destructive_git") for the library rule.
//
// Query path: data.agentjail.decision  (resolver.rego is the sole producer).
//
// Resolver tie-breaking: within a priority class (deny > ask > allow) the
// candidate with the lexicographically smallest rule_id wins, so the same input
// always returns the same action — the action cannot be weakened by adding more
// rules of the same tier.
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

// buildMirrorOpts constructs the OPA rego options from the mirror embed only:
// all four core rules (command_policy, file_policy, mcp_policy, resolver) plus
// the no_destructive_git library rule.  No source-tree files are read.
func buildMirrorOpts(t *testing.T) []func(*rego.Rego) {
	t.Helper()

	opts := []func(*rego.Rego){
		rego.Query("data.agentjail.decision"),
	}

	// Load all four core rules from the mirror embed (candidate + resolver).
	for name, content := range allCoreRuleBytes() {
		opts = append(opts, rego.Module(name+".rego", string(content)))
	}

	// Library rule from the mirror embed.
	libContent := libraryRuleContent("no_destructive_git")
	if libContent == nil {
		t.Fatal("libraryRuleContent(no_destructive_git) returned nil")
	}
	opts = append(opts, rego.Module("no_destructive_git.rego", string(libContent)))

	return opts
}

// evalDecision evaluates data.agentjail.decision for the given HookInput and
// returns the action string ("deny", "ask", or "allow").
func evalDecision(t *testing.T, pq rego.PreparedEvalQuery, input map[string]interface{}) string {
	t.Helper()
	ctx := context.Background()
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	// Default mirrors hookDefaultDecision (ask) when no candidate fires.
	action := "ask"
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		m, ok := rs[0].Expressions[0].Value.(map[string]interface{})
		if ok && m != nil {
			if a, _ := m["action"].(string); a != "" {
				action = a
			}
		}
	}
	return action
}

// TestMirrorPolicyDecisions exercises the embedded mirror policies via the OPA
// Go SDK.  All modules are loaded purely from allCoreRuleBytes() and
// libraryRuleContent — no source-tree files are read.
func TestMirrorPolicyDecisions(t *testing.T) {
	t.Parallel()

	const cwd = "/Users/dev/project"

	type testCase struct {
		name      string
		toolName  string
		toolInput map[string]interface{}
		want      string // exact "action" value; empty → use notDeny
		notDeny   bool   // when true, assert action != "deny"
	}

	cases := []testCase{
		// ----- file_policy -----
		{
			name:      "Read sensitive ~/.npmrc → deny",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/.npmrc"},
			want:      "deny",
		},
		{
			name:      "Read sensitive ~/.docker/config.json → deny",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/.docker/config.json"},
			want:      "deny",
		},
		{
			name:      "Read project-local .npmrc → allow",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/project/.npmrc"},
			want:      "allow",
		},
		{
			name:      "Read out-of-project non-sensitive path → not deny (ask)",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/.npmrc.bak"},
			notDeny:   true,
		},
		// ----- command_policy: ASK -----
		{
			name:      "Bash docker push → ask",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "docker push myimg"},
			want:      "ask",
		},
		{
			name:      "Bash npm install → allow",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "npm install"},
			want:      "allow",
		},
		// ----- no_destructive_git library rule (THE CRITICAL FIX) -----
		// git reset --hard must now deny because the mirror uses candidate+resolver
		// and no longer bypasses library rule candidates.
		{
			name:      "Bash git reset --hard → deny (no_destructive_git library rule enforces)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "git reset --hard HEAD~2"},
			want:      "deny",
		},
		{
			name:      "Bash git restore single-file → allow (not denied by no_destructive_git)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "git restore README.md"},
			want:      "allow",
		},
		// ----- core-equivalence: prove no weakening vs old else-chain -----
		{
			name:      "Bash sudo apt install → deny (core no-sudo)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "sudo apt install x"},
			want:      "deny",
		},
		{
			name:      "Bash rm -rf / → deny (core no-rm-rf-absolute)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "rm -rf /"},
			want:      "deny",
		},
		{
			name:      "Read ~/.ssh/id_rsa → deny (file_policy/sensitive_credential)",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/.ssh/id_rsa"},
			want:      "deny",
		},
		{
			name:      "Read project file under cwd → allow",
			toolName:  "Read",
			toolInput: map[string]interface{}{"path": "/Users/dev/project/main.go"},
			want:      "allow",
		},
		{
			name:      "Bash npm publish → ask (confirm-publish)",
			toolName:  "Bash",
			toolInput: map[string]interface{}{"command": "npm publish"},
			want:      "ask",
		},
	}

	ctx := context.Background()
	opts := buildMirrorOpts(t)
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		t.Fatalf("PrepareForEval: %v", err)
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := map[string]interface{}{
				"hook_event": "PreToolUse",
				"tool_name":  tc.toolName,
				"tool_input": tc.toolInput,
				"cwd":        cwd,
			}
			action := evalDecision(t, pq, input)
			if tc.notDeny {
				if action == "deny" {
					t.Errorf("got action=%q, want != %q", action, "deny")
				}
				return
			}
			if action != tc.want {
				t.Errorf("got action=%q, want %q", action, tc.want)
			}
		})
	}
}

// TestUpgradeSimulation proves that installCoreRules replaces a stale else-chain
// core file, and that after replacement the OPA evaluation correctly enforces
// both core rules (sudo → deny) and library rules (git reset --hard → deny).
//
// This is the end-to-end proof that the fail-open bug is fixed: a user upgrading
// from an old agentjail binary will have their stale command_policy.rego replaced,
// causing the daemon to use the candidate+resolver model and honour library rules.
func TestUpgradeSimulation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// 1. Simulate stale install: write old else-chain command_policy to tempdir.
	staleCmdPolicy := `package agentjail
import future.keywords.if
decision := r if { startswith(trim_space(input.tool_input.command), "sudo "); r := {"action":"deny","rule_id":"no-sudo","reason":"legacy"} } else := {"action":"allow","rule_id":"default","reason":"old"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "command_policy.rego"), []byte(staleCmdPolicy), 0o640); err != nil {
		t.Fatal(err)
	}

	// 2. Also install the library rule (simulates user having it enabled).
	libContent := libraryRuleContent("no_destructive_git")
	if libContent == nil {
		t.Fatal("libraryRuleContent(no_destructive_git) returned nil")
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "no_destructive_git.rego"), libContent, 0o640); err != nil {
		t.Fatal(err)
	}

	// 3. Run installCoreRules — must replace stale command_policy and add resolver.
	if err := installCoreRules(tmpDir); err != nil {
		t.Fatalf("installCoreRules: %v", err)
	}

	// 4. Read all *.rego from tempdir and compile via OPA SDK.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	opts := []func(*rego.Rego){
		rego.Query("data.agentjail.decision"),
	}
	for _, e := range entries {
		if e.IsDir() || !isRegoFile(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(tmpDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, rego.Module(e.Name(), string(b)))
	}

	ctx := context.Background()
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		t.Fatalf("PrepareForEval after upgrade simulation: %v", err)
	}

	const cwd = "/Users/dev/project"

	// 5a. Library rule must enforce: git reset --hard → deny.
	{
		input := map[string]interface{}{
			"hook_event": "PreToolUse",
			"tool_name":  "Bash",
			"tool_input": map[string]interface{}{"command": "git reset --hard HEAD~1"},
			"cwd":        cwd,
		}
		action := evalDecision(t, pq, input)
		if action != "deny" {
			t.Errorf("upgrade sim: git reset --hard: got action=%q, want %q (library rule must enforce after migration)", action, "deny")
		}
	}

	// 5b. Core rule must enforce: sudo apt install → deny.
	{
		input := map[string]interface{}{
			"hook_event": "PreToolUse",
			"tool_name":  "Bash",
			"tool_input": map[string]interface{}{"command": "sudo apt install x"},
			"cwd":        cwd,
		}
		action := evalDecision(t, pq, input)
		if action != "deny" {
			t.Errorf("upgrade sim: sudo: got action=%q, want %q (core rule must enforce after migration)", action, "deny")
		}
	}
}

// isRegoFile reports whether filename ends with .rego (excluding _test.rego which
// OPA cannot evaluate outside opa test context).
func isRegoFile(name string) bool {
	return len(name) > 5 && name[len(name)-5:] == ".rego" &&
		!(len(name) > 10 && name[len(name)-10:] == "_test.rego")
}
