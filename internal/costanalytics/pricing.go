package costanalytics

import (
	"sync"

	"github.com/safedep/gryph/pricing"
)

type tokenPricing struct {
	input      float64
	output     float64
	cacheRead  float64
	cacheWrite float64
}

// Gryph remains the general catalog; this supplement covers current agent
// models until its bundled data catches up. See ADR 0121-current-model-pricing.
var supplementalPricing = map[Model]tokenPricing{
	"claude-opus-4-6": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"claude-opus-4-8": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"claude-opus-5":   {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25},
	"gpt-5.6":         {input: 5, output: 30, cacheRead: 0.5, cacheWrite: 6.25},
	"gpt-5.6-sol":     {input: 5, output: 30, cacheRead: 0.5, cacheWrite: 6.25},
	"gpt-5.6-terra":   {input: 2.5, output: 15, cacheRead: 0.25, cacheWrite: 3.125},
	"gpt-5.6-luna":    {input: 1, output: 6, cacheRead: 0.1, cacheWrite: 1.25},
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

// ComputeCostFromTokens calculates the USD cost for a model from the offline
// pricing catalogs.
func ComputeCostFromTokens(model Model, input, output, cacheRead, cacheWrite int64) float64 {
	verified, ok := pricingForModel(model)
	if !ok {
		return 0
	}
	return tokenCost(input, output, cacheRead, cacheWrite, verified)
}

// HasPricing reports whether the offline catalogs can price a model.
func HasPricing(model Model) bool {
	_, ok := pricingForModel(model)
	return ok
}

func pricingForModel(model Model) (tokenPricing, bool) {
	if verified, ok := supplementalPricing[model]; ok {
		return verified, true
	}
	provider, err := GetPricingProvider()
	if err != nil || provider == nil {
		return tokenPricing{}, false
	}

	mp, err := provider.GetPricing(string(model))
	if err != nil || mp == nil {
		return tokenPricing{}, false
	}
	return tokenPricing{
		input:      mp.InputPer1M,
		output:     mp.OutputPer1M,
		cacheRead:  mp.CacheRead,
		cacheWrite: mp.CacheWrite,
	}, true
}

func tokenCost(input, output, cacheRead, cacheWrite int64, pricing tokenPricing) float64 {
	return (float64(input)*pricing.input +
		float64(output)*pricing.output +
		float64(cacheRead)*pricing.cacheRead +
		float64(cacheWrite)*pricing.cacheWrite) / 1_000_000
}
