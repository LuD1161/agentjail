package costanalytics

import "testing"

func TestComputeCostFromTokensCurrentAgentModels(t *testing.T) {
	t.Parallel()

	for _, model := range []Model{"claude-sonnet-4-6", "gpt-5.4"} {
		if cost := ComputeCostFromTokens(model, 1_000_000, 1_000_000, 0, 0); cost <= 0 {
			t.Errorf("ComputeCostFromTokens(%q) = %f, want a positive bundled price", model, cost)
		}
	}
}

func TestComputeCostFromTokensUnknownModel(t *testing.T) {
	t.Parallel()

	if cost := ComputeCostFromTokens("not-a-real-model", 1_000_000, 1_000_000, 0, 0); cost != 0 {
		t.Fatalf("ComputeCostFromTokens() = %f, want zero for an unknown model", cost)
	}
}
