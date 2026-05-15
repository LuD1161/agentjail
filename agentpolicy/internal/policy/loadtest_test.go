package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestCacheHitRateUnderSyntheticLoad is the brief's "5-min synthetic
// load test" collapsed into a deterministic, fast-running variant: we
// issue 10 K frames with a CONSTANT principal and CONSTANT resource
// path-set so the bucketed cache should hit on every request after the
// first 1 K (cold).
//
// Run with `go test ./internal/policy/ -run CacheHitRate -v` to see the
// measured rate; the test fails only if hit rate falls below 95 %.
func TestCacheHitRateUnderSyntheticLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("synthetic load test skipped in -short mode")
	}
	tmp := t.TempDir()
	policyDir := filepath.Join(tmp, "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const rego = `package agentjail.default
default decision := {"action": "allow"}
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.rego"), []byte(rego), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	eng, err := NewEngine(context.Background(), policyDir)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	principal := map[string]any{
		"id": "comp-intel:sid",
		"attr": map[string]any{
			"agent":   "comp-intel",
			"user":    "alice",
			"enforce": false,
		},
	}

	// 100 distinct resource ids the cold cache must miss on (100 × 256
	// cap fits in the per-bucket inner LRU).
	const distinctResources = 100
	const iterations = 10_000

	resources := make([]map[string]any, distinctResources)
	for i := 0; i < distinctResources; i++ {
		resources[i] = map[string]any{
			"kind": "http_request",
			"id":   fmt.Sprintf("http:POST:api.anthropic.com/v1/messages/%d", i),
		}
	}

	for i := 0; i < iterations; i++ {
		in := Input{
			Hook:      "http",
			Host:      "api.anthropic.com",
			Method:    "POST",
			Principal: principal,
			Resource:  resources[i%distinctResources],
			Action:    "fetch",
		}
		if _, err := eng.Eval(context.Background(), in); err != nil {
			t.Fatalf("eval: %v", err)
		}
	}

	stats := eng.Stats()
	hitRate := float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	t.Logf("synthetic load: iterations=%d distinct_resources=%d hits=%d misses=%d hit_rate=%.4f",
		iterations, distinctResources, stats.Hits, stats.Misses, hitRate)
	// First 100 iterations are cold (1 miss each); rest should hit.
	wantMinRate := float64(iterations-distinctResources) / float64(iterations)
	wantMinRate -= 0.01 // 1% slack
	if hitRate < wantMinRate {
		t.Errorf("cache hit rate %.4f below expected minimum %.4f — bucketed split regressed",
			hitRate, wantMinRate)
	}
}
