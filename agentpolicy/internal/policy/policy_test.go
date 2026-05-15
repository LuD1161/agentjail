package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// loadRepoPolicies returns an engine compiled from policies/default.rego
// in the repo root. Tests that need the production rule set use this so
// any rule rewrite that breaks an existing fixture is caught here too.
func loadRepoPolicies(t *testing.T) *OPAEngine {
	t.Helper()
	// Walk up looking for a "policies" dir with default.rego (worktree
	// layouts complicate a relative path; this is more robust).
	cwd, _ := os.Getwd()
	dir := cwd
	for {
		cand := filepath.Join(dir, "policies", "default.rego")
		if _, err := os.Stat(cand); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not locate policies/default.rego")
		}
		dir = parent
	}
	eng, err := NewEngine(context.Background(), filepath.Join(dir, "policies"))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

// TestLegacyInputShapeStillMatches pins that the existing default.rego
// rules continue to fire against the LEGACY flat Input shape. If this
// breaks, policies/default.rego or policy.Eval has drifted.
func TestLegacyInputShapeStillMatches(t *testing.T) {
	eng := loadRepoPolicies(t)
	in := Input{
		Hook:          "exec",
		Program:       "rm",
		Flags:         []string{"-r", "-f"},
		Positional:    []string{"/Users/me"},
		ArgvRaw:       []string{"rm", "-rf", "~"},
		PathsResolved: []string{"/Users/me"},
		Context:       map[string]any{"home": "/Users/me"},
	}
	d, err := eng.Eval(context.Background(), in)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if d.Action != "deny" {
		t.Errorf("legacy rm -rf must still DENY, got %q", d.Action)
	}
	if d.RuleID != "no-recursive-delete-of-protected-paths" {
		t.Errorf("rule_id: %q", d.RuleID)
	}
}

// TestStaticDynamicKeySplit pins the split: two requests differing ONLY
// in the principal half land in different buckets; two requests
// differing ONLY in the resource half land in different dynamic keys
// inside the SAME bucket.
func TestStaticDynamicKeySplit(t *testing.T) {
	pA := map[string]any{"id": "comp-intel:s1", "attr": map[string]any{"agent": "comp-intel", "user": "alice"}}
	pB := map[string]any{"id": "comp-intel:s2", "attr": map[string]any{"agent": "comp-intel", "user": "bob"}}
	rA := map[string]any{"kind": "file", "id": "file:/a"}
	rB := map[string]any{"kind": "file", "id": "file:/b"}

	skA := PrincipalStaticKey(pA)
	skB := PrincipalStaticKey(pB)
	if skA == skB {
		t.Errorf("distinct principals must hash to distinct static keys: %q == %q", skA, skB)
	}

	dkA := DynamicKey(Input{Action: "write", Resource: rA})
	dkB := DynamicKey(Input{Action: "write", Resource: rB})
	if dkA == dkB {
		t.Errorf("distinct resources must hash to distinct dynamic keys: %q == %q", dkA, dkB)
	}

	// Same principal + same resource + same action -> identical keys (cache hit).
	dkA2 := DynamicKey(Input{Action: "write", Resource: rA})
	if dkA != dkA2 {
		t.Errorf("dynamic key must be deterministic for identical inputs")
	}
}

// TestBucketedCacheIsolation: invalidating one principal's bucket must
// NOT drop another principal's cached entries.
func TestBucketedCacheIsolation(t *testing.T) {
	c := newBucketedCache(16, 16)
	c.put("p1", "d1", Decision{Action: "deny", RuleID: "r1"})
	c.put("p2", "d2", Decision{Action: "allow"})

	if _, ok := c.get("p1", "d1"); !ok {
		t.Fatalf("p1 entry missing")
	}
	if _, ok := c.get("p2", "d2"); !ok {
		t.Fatalf("p2 entry missing")
	}

	c.clearBucket("p1")
	if _, ok := c.get("p1", "d1"); ok {
		t.Errorf("p1 entry should have been evicted")
	}
	if _, ok := c.get("p2", "d2"); !ok {
		t.Errorf("p2 entry must survive p1 invalidation")
	}
}

// TestBucketedHitRateUnderVaryingResource exercises the regression the
// cache-key split was designed to prevent: 1 principal + N distinct
// resource paths must not blow up cache misses on REPEATED requests for
// the same (principal, resource) pair.
func TestBucketedHitRateUnderVaryingResource(t *testing.T) {
	eng := loadRepoPolicies(t)

	principal := map[string]any{"id": "comp-intel:s1", "attr": map[string]any{"agent": "comp-intel", "user": "alice", "enforce": false}}

	// Issue 100 distinct (resource, action) combos twice each.
	const distinctResources = 100
	const passes = 2
	for pass := 0; pass < passes; pass++ {
		for i := 0; i < distinctResources; i++ {
			in := Input{
				Hook:      "http",
				Host:      "api.anthropic.com",
				Method:    "POST",
				Principal: principal,
				Resource: map[string]any{
					"kind": "http_request",
					"id":   "http:POST:api.anthropic.com/v1/messages/" + string(rune('a'+(i%26))) + string(rune('a'+(i/26))),
				},
				Action: "fetch",
			}
			if _, err := eng.Eval(context.Background(), in); err != nil {
				t.Fatalf("eval: %v", err)
			}
		}
	}
	stats := eng.Stats()
	// On the second pass every (principal, resource) pair should hit
	// the cache. Hit count must be at least the number of distinct
	// resources × (passes-1) for the test to mean anything.
	wantMinHits := uint64(distinctResources * (passes - 1))
	if stats.Hits < wantMinHits {
		t.Errorf("cache hits %d below expected minimum %d (passes=%d, distinct=%d): bucketed cache regressed",
			stats.Hits, wantMinHits, passes, distinctResources)
	}
}

// TestEvalQueryAdHoc exercises the perm.Service entry point. We compile
// an experimental package on the fly and assert the alternate query
// returns its own decision without touching the default LRU.
func TestEvalQueryAdHoc(t *testing.T) {
	tmp := t.TempDir()
	policyDir := filepath.Join(tmp, "policies")
	expDir := filepath.Join(policyDir, "experimental")
	if err := os.MkdirAll(expDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Default: allow everything (so we can be sure the deny verdict
	// below came from the experimental query).
	const defaultRego = `package agentjail.default
default decision := {"action": "allow"}
`
	const expRego = `package agentjail.experimental
import future.keywords.if
default decision := {"action": "allow"}
decision := {"action": "deny", "rule_id": "exp-deny-all-comp-intel-writes"} if {
	input.principal.attr.agent == "comp-intel"
	input.action == "write"
}
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.rego"), []byte(defaultRego), 0o600); err != nil {
		t.Fatalf("write default: %v", err)
	}
	if err := os.WriteFile(filepath.Join(expDir, "exp.rego"), []byte(expRego), 0o600); err != nil {
		t.Fatalf("write exp: %v", err)
	}
	eng, err := NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	in := Input{
		Action:    "write",
		Principal: map[string]any{"attr": map[string]any{"agent": "comp-intel"}},
		Resource:  map[string]any{"kind": "file", "id": "file:/x"},
	}
	defaultDec, err := eng.Eval(context.Background(), in)
	if err != nil {
		t.Fatalf("default eval: %v", err)
	}
	if defaultDec.Action != "allow" {
		t.Errorf("default expected allow, got %q", defaultDec.Action)
	}
	expDec, err := eng.EvalQuery(context.Background(), "data.agentjail.experimental.decision", in)
	if err != nil {
		t.Fatalf("exp eval: %v", err)
	}
	if expDec.Action != "deny" || expDec.RuleID != "exp-deny-all-comp-intel-writes" {
		t.Errorf("exp expected deny: got %+v", expDec)
	}
}
