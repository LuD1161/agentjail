package config

import "path"

// HostedMCP describes one vetted hosted MCP server: the canonical name it is
// known by, the concrete aliases it appears under in mcp.allowed/mcp.blocked
// (bare name, "plugin_<x>_<x>" style plugin ids, "<x>-server" style ids,
// etc.), and the network hosts its traffic actually flows through.
//
// This is the single source of truth for "which hosts does allowing this MCP
// server imply." ExtendedDefaultAllowedHosts's "Hosted MCP servers" section
// and PolicyConfig.EffectiveAllowedHosts (via MCPDerivedAllowedHosts) both
// derive from this registry -- neither hardcodes the host list itself. See
// ADR 0040.
type HostedMCP struct {
	// Name is the canonical id for this hosted MCP, e.g. "linear".
	Name string

	// ServerPatterns are the concrete server-name aliases this MCP is known
	// to appear under in mcp.allowed / mcp.blocked globs (matched against,
	// not glob patterns themselves) -- e.g. {"linear", "linear-server"}.
	ServerPatterns []string

	// Hosts are the vetted network hosts this MCP's traffic flows through,
	// e.g. {"mcp.linear.app", "api.linear.app"}.
	Hosts []string
}

// HostedMCPRegistry returns the single source of truth for vetted hosted MCP
// servers and the hosts their traffic flows through.
//
// Returns a defensive (deep) copy; callers may freely mutate the result.
func HostedMCPRegistry() []HostedMCP {
	src := []HostedMCP{
		{
			Name:           "linear",
			ServerPatterns: []string{"linear", "linear-server"},
			Hosts:          []string{"mcp.linear.app", "api.linear.app"},
		},
		{
			Name:           "typefully",
			ServerPatterns: []string{"typefully", "typefully-server", "plugin_typefully_typefully"},
			Hosts:          []string{"api.typefully.com"},
		},
		{
			Name:           "posthog",
			ServerPatterns: []string{"posthog", "posthog-server", "plugin_posthog_posthog"},
			Hosts:          []string{"*.posthog.com"},
		},
		{
			Name:           "context7",
			ServerPatterns: []string{"context7", "context7-server", "plugin_context7_context7"},
			Hosts:          []string{"mcp.context7.com"},
		},
		{
			Name:           "notion",
			ServerPatterns: []string{"notion", "notion-server", "plugin_notion_notion"},
			Hosts:          []string{"mcp.notion.com"},
		},
		{
			Name:           "deepwiki",
			ServerPatterns: []string{"deepwiki", "deepwiki-server", "plugin_deepwiki_deepwiki"},
			Hosts:          []string{"mcp.deepwiki.com"},
		},
		{
			Name:           "cloudflare",
			ServerPatterns: []string{"cloudflare", "cloudflare-server", "plugin_cloudflare_cloudflare"},
			Hosts:          []string{"mcp.cloudflare.com"},
		},
		{
			Name:           "githubcopilot",
			ServerPatterns: []string{"githubcopilot", "github-copilot", "copilot", "plugin_githubcopilot_githubcopilot"},
			Hosts:          []string{"api.githubcopilot.com"},
		},
		{
			Name:           "huggingface",
			ServerPatterns: []string{"huggingface", "huggingface-server", "hf", "plugin_huggingface_huggingface"},
			Hosts:          []string{"hf.co"},
		},
	}

	out := make([]HostedMCP, len(src))
	for i, e := range src {
		out[i] = HostedMCP{
			Name:           e.Name,
			ServerPatterns: append([]string(nil), e.ServerPatterns...),
			Hosts:          append([]string(nil), e.Hosts...),
		}
	}
	return out
}

// HostedMCPAllowedHosts flattens the Hosts of every registry entry into a
// single deduplicated, order-stable list (registry order, first occurrence
// wins). This is what ExtendedDefaultAllowedHosts's "Hosted MCP servers"
// section is built from -- the hosts live only in HostedMCPRegistry, not
// duplicated as literals elsewhere.
//
// Returns a defensive copy; callers may freely mutate the result.
func HostedMCPAllowedHosts() []string {
	registry := HostedMCPRegistry()
	seen := make(map[string]struct{})
	out := make([]string, 0, len(registry)*2)
	for _, e := range registry {
		for _, h := range e.Hosts {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

// globMatch reports whether pattern matches s, using path.Match semantics
// (server names never contain "/", so this is equivalent to Rego's
// glob.match(pattern, [], s) for this domain -- the same equivalence
// documented for DisabledRules glob validation).
//
// A malformed pattern (path.Match returning ErrBadPattern) is treated
// defensively as "no match" rather than panicking or propagating the error --
// malformed mcp.allowed/mcp.blocked patterns are rejected at Load time (see
// validateMCPGlobs), so a well-formed *loaded* config should never reach this
// path with a bad pattern; this is a last-resort safety net for callers that
// construct an MCPConfig without going through Load.
func globMatch(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	if err != nil {
		return false
	}
	return ok
}

// matchesAny reports whether any pattern in patterns matches any alias in
// aliases.
func matchesAny(patterns, aliases []string) bool {
	for _, p := range patterns {
		for _, a := range aliases {
			if globMatch(p, a) {
				return true
			}
		}
	}
	return false
}

// MCPDerivedAllowedHosts returns the hosts implied by the hosted MCP servers
// that are EFFECTIVELY ALLOWED under mcp: some ServerPatterns alias of the
// registry entry matches an mcp.Allowed glob, AND no ServerPatterns alias
// matches an mcp.Blocked glob. This mirrors mcp_policy.rego's precedence
// exactly (blocked always wins over allowed).
//
// The returned hosts are non-removable WHILE the corresponding MCP stays
// allowed (see PolicyConfig.EffectiveAllowedHosts) -- removing the server
// from mcp.allowed, or adding a pattern to mcp.blocked that matches it,
// removes its hosts from the effective allowlist on the next load.
//
// Returns a deduplicated, order-stable (registry order) list; never nil.
func MCPDerivedAllowedHosts(mcp MCPConfig) []string {
	registry := HostedMCPRegistry()
	seen := make(map[string]struct{})
	out := make([]string, 0, len(registry)*2)
	for _, e := range registry {
		if !matchesAny(mcp.Allowed, e.ServerPatterns) {
			continue
		}
		if matchesAny(mcp.Blocked, e.ServerPatterns) {
			continue
		}
		for _, h := range e.Hosts {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}
