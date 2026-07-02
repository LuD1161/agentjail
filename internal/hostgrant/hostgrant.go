// Package hostgrant validates hosts that a human grants at runtime (e.g. via
// a TUI prompt or CLI flag), before they are merged into a session's
// allowed-hosts list. It is deliberately pure and deterministic -- no DNS
// lookups, no I/O -- so it can be unit tested exhaustively and reused by any
// caller that needs to turn free-text human input into a normalized host
// suitable for agentpolicy.HostPattern / netproxy's matchHost.
//
// Normalization matches the conventions already used by
// cmd/agentjail-netproxy (lowercase, trailing-dot stripped, "*."-prefixed
// leading-wildcard) so a validated host round-trips cleanly through the rest
// of the host-matching pipeline.
package hostgrant

import (
	"fmt"
	"slices"
	"strings"
)

// rejectedWildcardSuffixes are public-suffix-only apexes that would make a
// leading-wildcard grant ("*.<suffix>") match nearly the entire internet.
// This is not an exhaustive public-suffix list -- it is a small, hardcoded
// set of the most common ones, backstopped by the general "wildcard must
// have >=2 labels after *." rule below, which rejects any single-label
// suffix regardless of whether it appears in this set.
var rejectedWildcardSuffixes = map[string]bool{
	"com":    true,
	"org":    true,
	"net":    true,
	"io":     true,
	"co":     true,
	"ai":     true,
	"dev":    true,
	"app":    true,
	"gov":    true,
	"edu":    true,
	"info":   true,
	"biz":    true,
	"me":     true,
	"co.uk":  true,
	"org.uk": true,
	"com.au": true,
}

// Validate validates a host a human may grant at runtime and returns the
// normalized host, or a descriptive error explaining why it was rejected.
//
// Accepted forms:
//   - a bare hostname, e.g. "api.example.com"
//   - a leading-wildcard pattern with at least two labels after "*.",
//     e.g. "*.claude.ai"
//
// Rejected forms (see individual checks below for the exact message):
//   - empty / whitespace-only input
//   - a URL (contains a scheme, e.g. "https://")
//   - a host with a path, query, or fragment component
//   - a host with an embedded port (e.g. "api.example.com:443")
//   - a host with a leading dot (e.g. ".example.com")
//   - a bare "*", "*.", or a wildcard whose suffix is a known public-suffix
//     apex or has fewer than two labels (e.g. "*.com")
//
// A single trailing dot (the DNS root label, e.g. "example.com.") is
// stripped rather than rejected, matching normalizeHost in
// cmd/agentjail-netproxy.
func Validate(raw string) (host string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("host must not be empty")
	}

	if strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("provide a bare host, not a URL: %q", raw)
	}

	if strings.ContainsAny(trimmed, "/?#") {
		return "", fmt.Errorf("host must not contain a path, query, or fragment: %q", raw)
	}

	// Strip a single trailing dot (DNS root label) before further checks.
	trimmed = strings.TrimSuffix(trimmed, ".")
	if trimmed == "" {
		return "", fmt.Errorf("host must not be empty")
	}

	if strings.HasPrefix(trimmed, ".") {
		return "", fmt.Errorf("host must not start with a dot: %q", raw)
	}

	// Reject an embedded port. A bare IPv6 literal would also contain
	// colons, but this validator only accepts hostnames, so any colon is
	// treated as a port separator and rejected.
	if strings.Contains(trimmed, ":") {
		return "", fmt.Errorf("host must not include a port, omit the port: %q", raw)
	}

	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "*.") {
		suffix := lower[2:]
		if suffix == "" {
			return "", fmt.Errorf("wildcard host must have a domain after \"*.\": %q", raw)
		}
		labels := strings.Split(suffix, ".")
		if len(labels) < 2 {
			return "", fmt.Errorf("wildcard host is too broad, must have at least two labels after \"*.\": %q", raw)
		}
		if rejectedWildcardSuffixes[suffix] {
			return "", fmt.Errorf("wildcard host is too broad, %q is a public suffix: %q", suffix, raw)
		}
		if slices.Contains(labels, "") {
			return "", fmt.Errorf("wildcard host must not contain empty labels: %q", raw)
		}
		return lower, nil
	}

	if strings.Contains(lower, "*") {
		return "", fmt.Errorf("wildcard must be a leading \"*.\" pattern, e.g. \"*.example.com\": %q", raw)
	}

	if !strings.Contains(lower, ".") {
		return "", fmt.Errorf("host must contain at least one dot, bare hostnames are not accepted: %q", raw)
	}

	if slices.Contains(strings.Split(lower, "."), "") {
		return "", fmt.Errorf("host must not contain empty labels: %q", raw)
	}

	return lower, nil
}
