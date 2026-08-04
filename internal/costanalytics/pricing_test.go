package costanalytics

import "testing"

func TestComputeCostFromTokensCurrentAgentModels(t *testing.T) {
	t.Parallel()

	for _, model := range []Model{
		"claude-sonnet-4-6",
		"claude-opus-4-6",
		"claude-opus-4-8",
		"claude-opus-5",
		"gpt-5.4",
		"gpt-5.6",
		"gpt-5.6-sol",
		"gpt-5.6-terra",
		"gpt-5.6-luna",
	} {
		if cost := ComputeCostFromTokens(model, 1_000_000, 1_000_000, 0, 0); cost <= 0 {
			t.Errorf("ComputeCostFromTokens(%q) = %f, want a positive bundled price", model, cost)
		}
	}
}

func TestComputeCostFromTokensUsesVerifiedCurrentRates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		model Model
		want  float64
	}{
		{model: "claude-opus-4-6", want: 36.75},
		{model: "claude-opus-4-8", want: 36.75},
		{model: "claude-opus-5", want: 36.75},
		{model: "gpt-5.6-sol", want: 41.75},
		{model: "gpt-5.6-terra", want: 20.875},
		{model: "gpt-5.6-luna", want: 8.35},
	}
	for _, test := range tests {
		t.Run(string(test.model), func(t *testing.T) {
			t.Parallel()
			got := ComputeCostFromTokens(test.model, 1_000_000, 1_000_000, 1_000_000, 1_000_000)
			if got != test.want {
				t.Fatalf("ComputeCostFromTokens(%q) = %f, want %f", test.model, got, test.want)
			}
		})
	}
}

func TestComputeBaseCostDistinguishesClaudeCacheWriteTTLs(t *testing.T) {
	t.Parallel()

	usage := TokenUsage{
		Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000,
		CacheWrite: 2_000_000, CacheWrite5m: 1_000_000, CacheWrite1h: 1_000_000,
	}
	if got, want := ComputeBaseCost("claude-opus-4-8", usage), 46.75; got != want {
		t.Fatalf("ComputeBaseCost() = %.2f, want %.2f", got, want)
	}
}

func TestComputeRequestCostAppliesGPT56LongContextTier(t *testing.T) {
	t.Parallel()

	usage := TokenUsage{Input: 100_000, CacheRead: 200_000, Output: 1_000_000}
	if got, want := ComputeBaseCost("gpt-5.6-sol", usage), 30.6; got != want {
		t.Fatalf("ComputeBaseCost() = %.2f, want %.2f", got, want)
	}
	if got, want := ComputeRequestCost("gpt-5.6-sol", usage), 46.2; got != want {
		t.Fatalf("ComputeRequestCost() = %.2f, want %.2f", got, want)
	}
}

func TestOverlaySupplementalPricingPreservesCatalogRatesAndAddsRules(t *testing.T) {
	t.Parallel()

	base := tokenPricing{input: 7, output: 35, cacheRead: 0.7, cacheWrite: 8.75}
	rules := supplementalPricing[Model("gpt-5.6-sol")]
	got := overlaySupplementalPricing(base, rules)
	if got.input != 7 || got.output != 35 || got.cacheRead != 0.7 || got.cacheWrite != 8.75 {
		t.Fatalf("catalog rates were replaced: %+v", got)
	}
	if got.longContextThreshold != 272_000 || got.longContextInputMultiple != 2 || got.longContextOutputMultiple != 1.5 {
		t.Fatalf("supplemental rules were not overlaid: %+v", got)
	}
}

func TestComputeCostFromTokensUnknownModel(t *testing.T) {
	t.Parallel()

	if cost := ComputeCostFromTokens("not-a-real-model", 1_000_000, 1_000_000, 0, 0); cost != 0 {
		t.Fatalf("ComputeCostFromTokens() = %f, want zero for an unknown model", cost)
	}
}
