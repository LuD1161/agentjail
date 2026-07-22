package captureproxy

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// gatewayNoncePrefix marks a path as one of our own gateway URLs. Structural
// marker only, not a secret -- the nonce that follows it is the secret.
const gatewayNoncePrefix = "/aj~"

// IsOwnGatewayURL reports whether u was minted by this package (loopback host
// + nonce-marker path). Guards against an inherited base-URL env var chaining
// into our own gateway (e.g. a leaked prior instance's URL).
func IsOwnGatewayURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	if !isLoopbackHost(u.Hostname()) {
		return false
	}
	return strings.HasPrefix(u.Path, gatewayNoncePrefix)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResolveForwardTarget decides where the gateway forwards traffic for
// provider p. inherited is the agent's pre-existing base-URL env var value
// (may be empty, falls back to the provider default); its path is kept as a
// prefix ahead of the request path.
//
// A self-referential inherited value (see IsOwnGatewayURL) is not chained --
// that would loop the gateway or, after the prior instance exits, forward
// into a dead port -- so it falls back to the provider default instead of
// erroring.
//
// allowlist is the egress guard: extra hosts (beyond the provider's own
// upstream) permitted as a forward target, matched case-insensitively.
// Loopback targets are only accepted via the allowlist, never implicitly.
func ResolveForwardTarget(inherited string, p Provider, allowlist []string) (*url.URL, error) {
	if inherited == "" {
		return providerDefaultURL(p), nil
	}

	u, err := url.Parse(inherited)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid inherited base URL %q: %w", inherited, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("gateway: inherited base URL %q has unsupported scheme %q", inherited, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("gateway: inherited base URL %q has no host", inherited)
	}
	if u.User != nil {
		return nil, fmt.Errorf("gateway: inherited base URL %q carries credentials in userinfo, refusing", inherited)
	}

	if IsOwnGatewayURL(u) {
		return providerDefaultURL(p), nil
	}

	if !targetHostAllowed(u.Hostname(), p, allowlist) {
		return nil, fmt.Errorf("gateway: inherited base URL host %q is not the provider upstream (%q) and not in the egress allowlist", u.Hostname(), p.UpstreamHost)
	}

	return u, nil
}

// providerDefaultURL builds the provider's default upstream target URL:
// https://<UpstreamHost>, no path prefix.
func providerDefaultURL(p Provider) *url.URL {
	return &url.URL{Scheme: "https", Host: p.UpstreamHost}
}

// targetHostAllowed is the egress guard: host must be the provider's own
// upstream, or present in allowlist.
func targetHostAllowed(host string, p Provider, allowlist []string) bool {
	lowerHost := strings.ToLower(host)
	if lowerHost == strings.ToLower(p.UpstreamHost) {
		return true
	}
	for _, a := range allowlist {
		if strings.EqualFold(a, host) {
			return true
		}
	}
	return false
}
