package costanalytics

import (
	"sync"

	"github.com/safedep/gryph/pricing"
)

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
	provider, err := GetPricingProvider()
	if err != nil || provider == nil {
		return 0
	}

	mp, err := provider.GetPricing(string(model))
	if err != nil || mp == nil {
		return 0
	}

	cost := (float64(input)*mp.InputPer1M +
		float64(output)*mp.OutputPer1M +
		float64(cacheRead)*mp.CacheRead +
		float64(cacheWrite)*mp.CacheWrite) / 1_000_000

	return cost
}
