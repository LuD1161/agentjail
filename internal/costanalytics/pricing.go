package costanalytics

import (
	"sync"

	"github.com/safedep/gryph/pricing"
)

type modelPricing struct {
	input      float64
	output     float64
	cacheRead  float64
	cacheWrite float64
}

// Gryph remains the general catalog; this supplement covers current agent
// models until its bundled data catches up. See ADR 0121-current-model-pricing.
var currentModelPricing = map[Model]modelPricing{
	"claude-opus-4-6": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"claude-opus-4-8": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"claude-opus-5":   {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"gpt-5.6-sol":     {input: 5, output: 30, cacheRead: 0.5, cacheWrite: 6.25},
	"gpt-5.6-terra":   {input: 2.5, output: 15, cacheRead: 0.25, cacheWrite: 3.125},
}

var (
	pricingOnce     sync.Once
	pricingProvider *pricing.BundledProvider
	pricingErr      error
)

// GetPricingProvider returns a singleton BundledProvider instance.
func GetPricingProvider() (*pricing.BundledProvider, error) {
	pricingOnce.Do(func() {
		pricingProvider, pricingErr = pricing.NewBundledProvider()
	})
	return pricingProvider, pricingErr
}

// ComputeCostFromTokens calculates the USD cost for a given model and token counts
// using gryph's bundled pricing data.
func ComputeCostFromTokens(model Model, input, output, cacheRead, cacheWrite int64) float64 {
	if mp, ok := currentModelPricing[model]; ok {
		return tokenCost(mp, input, output, cacheRead, cacheWrite)
	}

	provider, err := GetPricingProvider()
	if err != nil || provider == nil {
		return 0
	}

	mp, err := provider.GetPricing(string(model))
	if err != nil || mp == nil {
		return 0
	}

	return tokenCost(modelPricing{
		input:      mp.InputPer1M,
		output:     mp.OutputPer1M,
		cacheRead:  mp.CacheRead,
		cacheWrite: mp.CacheWrite,
	}, input, output, cacheRead, cacheWrite)
}

func tokenCost(mp modelPricing, input, output, cacheRead, cacheWrite int64) float64 {
	return (float64(input)*mp.input +
		float64(output)*mp.output +
		float64(cacheRead)*mp.cacheRead +
		float64(cacheWrite)*mp.cacheWrite) / 1_000_000
}
