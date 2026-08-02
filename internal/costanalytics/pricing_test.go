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

func TestComputeCostFromTokensUnknownModel(t *testing.T) {
	t.Parallel()

	if cost := ComputeCostFromTokens("not-a-real-model", 1_000_000, 1_000_000, 0, 0); cost != 0 {
		t.Fatalf("ComputeCostFromTokens() = %f, want zero for an unknown model", cost)
	}
}
