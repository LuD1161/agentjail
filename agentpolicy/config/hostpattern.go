package config

import "strings"

// HostPattern classifies a single entry from an allowed-hosts list as either
// an exact hostname or a leading-wildcard pattern (e.g. "*.claude.ai").
//
// This exists so callers that need to treat the two cases differently (most
// notably DNS resolution at shield startup -- see resolveAllowedHosts in
// shield_darwin.go) have a single, typed way to ask "is this literal or a
// wildcard," instead of re-deriving strings.HasPrefix(h, "*.") at each call
// site. It intentionally does NOT ripple through every consumer of
// EffectiveAllowedHosts: netproxy and OPA still consume []string at the
// serialization boundary (see EffectiveAllowedHosts doc comment) -- this type
// is scoped to classification and the DNS-resolution decision only.
type HostPattern struct {
	// Pattern is the original host string, unmodified.
	Pattern string

	// Wildcard is true iff Pattern has a "*." prefix (a leading-label
	// wildcard, e.g. "*.claude.ai"). A bare "*" or a wildcard elsewhere in
	// the string (neither of which appears in the shipped host lists) is
	// NOT classified as Wildcard here -- only the "*.<suffix>" form actually
	// occurs in EssentialAllowedHosts/ExtendedDefaultAllowedHosts/
	// HostedMCPRegistry, and only that form can never resolve as a literal
	// DNS name.
	Wildcard bool
}

// ClassifyHost classifies a single host entry from an allowed-hosts list.
func ClassifyHost(h string) HostPattern {
	return HostPattern{
		Pattern:  h,
		Wildcard: strings.HasPrefix(h, "*."),
	}
}
