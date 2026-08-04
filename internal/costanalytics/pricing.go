package costanalytics

import (
	"strings"
	"sync"

	"github.com/safedep/gryph/pricing"
)

type tokenPricing struct {
	input                     float64
	output                    float64
	cacheRead                 float64
	cacheWrite                float64
	cacheWrite1hMultiple      float64
	longContextThreshold      int64
	longContextInputMultiple  float64
	longContextOutputMultiple float64
}

// Gryph remains the general catalog; this supplement covers current agent
// models until its bundled data catches up. See ADR 0121-current-model-pricing.
var supplementalPricing = map[Model]tokenPricing{
	"claude-opus-4-6": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25, cacheWrite1hMultiple: 2},
	"claude-opus-4-8": {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25, cacheWrite1hMultiple: 2},
	"claude-opus-5":   {input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25, cacheWrite1hMultiple: 2},
	"gpt-5.6":         {input: 5, output: 30, cacheRead: 0.5, cacheWrite: 6.25, longContextThreshold: 272_000, longContextInputMultiple: 2, longContextOutputMultiple: 1.5},
	"gpt-5.6-sol":     {input: 5, output: 30, cacheRead: 0.5, cacheWrite: 6.25, longContextThreshold: 272_000, longContextInputMultiple: 2, longContextOutputMultiple: 1.5},
	"gpt-5.6-terra":   {input: 2.5, output: 15, cacheRead: 0.25, cacheWrite: 3.125, longContextThreshold: 272_000, longContextInputMultiple: 2, longContextOutputMultiple: 1.5},
	"gpt-5.6-luna":    {input: 1, output: 6, cacheRead: 0.1, cacheWrite: 1.25, longContextThreshold: 272_000, longContextInputMultiple: 2, longContextOutputMultiple: 1.5},
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
	return ComputeBaseCost(model, TokenUsage{Input: input, Output: output, CacheRead: cacheRead, CacheWrite: cacheWrite})
}

// ComputeBaseCost calculates an aggregate at base rates. It intentionally does
// not infer request-level tiers from session-wide cumulative usage.
func ComputeBaseCost(model Model, usage TokenUsage) float64 {
	verified, ok := pricingForModel(model)
	if !ok {
		return 0
	}
	return tokenCost(usage, verified, false)
}

// ComputeRequestCost calculates one request and applies documented request-level
// pricing tiers when its input size crosses the model threshold.
func ComputeRequestCost(model Model, usage TokenUsage) float64 {
	verified, ok := pricingForModel(model)
	if !ok {
		return 0
	}
	return tokenCost(usage, verified, true)
}

// HasPricing reports whether the offline catalogs can price a model.
func HasPricing(model Model) bool {
	_, ok := pricingForModel(model)
	return ok
}

func pricingForModel(model Model) (tokenPricing, bool) {
	provider, err := GetPricingProvider()
	if err != nil || provider == nil {
		return tokenPricing{}, false
	}

	mp, err := provider.GetPricing(string(model))
	if err != nil {
		return tokenPricing{}, false
	}
	supplemental, supplemented := supplementalPricing[model]
	if mp == nil {
		return supplemental, supplemented
	}
	resolved := tokenPricing{
		input:      mp.InputPer1M,
		output:     mp.OutputPer1M,
		cacheRead:  mp.CacheRead,
		cacheWrite: mp.CacheWrite,
	}
	if strings.Contains(strings.ToLower(string(model)), "claude") {
		// Anthropic prices 1h writes at 2x base input. See ADR 0122-supplemental-model-pricing.
		resolved.cacheWrite1hMultiple = 2
	}
	if supplemented {
		resolved = overlaySupplementalPricing(resolved, supplemental)
	}
	return resolved, true
}

func overlaySupplementalPricing(base, supplemental tokenPricing) tokenPricing {
	if base.input == 0 {
		base.input = supplemental.input
	}
	if base.output == 0 {
		base.output = supplemental.output
	}
	if base.cacheRead == 0 {
		base.cacheRead = supplemental.cacheRead
	}
	if base.cacheWrite == 0 {
		base.cacheWrite = supplemental.cacheWrite
	}
	if supplemental.cacheWrite1hMultiple != 0 {
		base.cacheWrite1hMultiple = supplemental.cacheWrite1hMultiple
	}
	if supplemental.longContextThreshold != 0 {
		base.longContextThreshold = supplemental.longContextThreshold
		base.longContextInputMultiple = supplemental.longContextInputMultiple
		base.longContextOutputMultiple = supplemental.longContextOutputMultiple
	}
	return base
}

func tokenCost(usage TokenUsage, pricing tokenPricing, requestAware bool) float64 {
	inputMultiple, outputMultiple := 1.0, 1.0
	requestInput := usage.Input + usage.CacheRead + usage.CacheWrite
	if requestAware && pricing.longContextThreshold > 0 && requestInput > pricing.longContextThreshold {
		inputMultiple = pricing.longContextInputMultiple
		outputMultiple = pricing.longContextOutputMultiple
	}
	classifiedWrites := usage.CacheWrite5m + usage.CacheWrite1h
	unclassifiedWrites := usage.CacheWrite - classifiedWrites
	if unclassifiedWrites < 0 {
		unclassifiedWrites = 0
	}
	cacheWrite1h := pricing.cacheWrite
	if pricing.cacheWrite1hMultiple != 0 {
		cacheWrite1h = pricing.input * pricing.cacheWrite1hMultiple
	}
	return (float64(usage.Input)*pricing.input*inputMultiple +
		float64(usage.Output)*pricing.output*outputMultiple +
		float64(usage.CacheRead)*pricing.cacheRead*inputMultiple +
		float64(unclassifiedWrites+usage.CacheWrite5m)*pricing.cacheWrite*inputMultiple +
		float64(usage.CacheWrite1h)*cacheWrite1h*inputMultiple) / 1_000_000
}

func requiresRequestPricing(model Model) bool {
	p, ok := pricingForModel(model)
	return ok && p.longContextThreshold > 0
}
