// Package gateway is a per-session local reverse-proxy the agent is pointed
// at via its provider base-URL env var (e.g. ANTHROPIC_BASE_URL); it forwards
// to the real upstream over TLS and records traffic. Works where a
// transparent MITM can't (Claude Code's Bun/undici trusts the keychain, not
// env-injected CAs). See ADR 0109-baseurl-capture-gateway.
package captureproxy

// Caps describes what a provider integration supports. Data, not a class
// enum: a new provider is a new registry row, not a new switch arm. See
// AGENTS.md "Prefer interfaces over hardcoding".
type Caps struct {
	// BaseURLEnv: agent honors a base-URL env var override.
	BaseURLEnv bool
	// ConfigFile: agent also reads a base URL from a config file, which
	// BaseURLEnv alone would not override.
	ConfigFile bool
	// TunnelOnly: no base-URL override exists; observable only via tunnel/MITM.
	TunnelOnly bool
	// SupportsOAuth: agent can auth through the gateway via its normal
	// OAuth/keychain flow.
	SupportsOAuth bool
	// SupportsPathPrefix: upstream API tolerates an arbitrary path prefix
	// (needed to carry the nonce marker).
	SupportsPathPrefix bool
	// Verified: proven end-to-end via live capture. Unverified entries are
	// data for future work; callers must not route to them without an ADR.
	Verified bool
}

// Provider is one coding agent's LLM API integration.
type Provider struct {
	// Name identifies the provider, e.g. "claude-code".
	Name string
	// AgentBaseName is the exec base name to match against, e.g. "claude".
	AgentBaseName string
	// UpstreamHost is the real LLM API host this provider talks to,
	// e.g. "api.anthropic.com".
	UpstreamHost string
	// BaseURLEnvVar is the env var the agent reads its base URL from,
	// e.g. "ANTHROPIC_BASE_URL".
	BaseURLEnvVar string
	// AuthEnvVars are the env vars that may carry credentials, in the order
	// the agent is documented to check them.
	AuthEnvVars []string
	// Caps are this integration's capability flags.
	Caps Caps
}

// registry is the Phase 1 provider list. Cursor is absent: proprietary,
// tunnel-only backend, no base-URL override to represent here.
var registry = []Provider{
	{
		Name:          "claude-code",
		AgentBaseName: "claude",
		UpstreamHost:  "api.anthropic.com",
		BaseURLEnvVar: "ANTHROPIC_BASE_URL",
		AuthEnvVars:   []string{"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"},
		Caps: Caps{
			BaseURLEnv:         true,
			SupportsOAuth:      true,
			SupportsPathPrefix: true,
			Verified:           true,
		},
	},
	{
		Name:          "codex",
		AgentBaseName: "codex",
		UpstreamHost:  "api.openai.com",
		BaseURLEnvVar: "OPENAI_BASE_URL",
		AuthEnvVars:   []string{"OPENAI_API_KEY"},
		Caps: Caps{
			BaseURLEnv:         true,
			SupportsPathPrefix: true,
			Verified:           false, // inert: not yet proven end-to-end
		},
	},
	{
		Name:          "gemini",
		AgentBaseName: "gemini",
		UpstreamHost:  "generativelanguage.googleapis.com",
		BaseURLEnvVar: "GOOGLE_GEMINI_BASE_URL",
		AuthEnvVars:   []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"},
		Caps: Caps{
			BaseURLEnv:         true,
			SupportsPathPrefix: true,
			Verified:           false, // inert: not yet proven end-to-end
		},
	},
}

// Lookup returns the provider whose AgentBaseName matches agentBaseName.
// It returns unverified entries too (Caps.Verified=false); the caller (the
// shield) decides whether to route traffic to an unverified provider.
func Lookup(agentBaseName string) (Provider, bool) {
	for _, p := range registry {
		if p.AgentBaseName == agentBaseName {
			return p, true
		}
	}
	return Provider{}, false
}
