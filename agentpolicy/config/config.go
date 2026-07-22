// Package config defines the schema for ~/.agentjail/policy.yaml and the
// helpers to load, validate, and default-construct a PolicyConfig.
//
// The config is fed into OPA as data.agentjail.config so Rego rules can
// reference user-supplied allow/block lists without hard-coding values.
//
// Load/Validate flow:
//
//	cfg, err := config.Load(path)  // strict: unknown fields → error
//	warns := config.Validate(cfg)  // advisory: empty allowed list warns
//
// Integration note: the daemon calls Load at startup and re-calls on SIGHUP.
// Rego rules read the resulting struct via the OPA data document overlay.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// PolicyConfig is the schema for ~/.agentjail/policy.yaml.
// It is loaded by agentjail-daemon and fed into OPA as data.agentjail.config.
//
// YAML is the interchange format; json tags are omitted because this struct is
// serialised into OPA's data document via the OPA Go API (which accepts
// map[string]any, not JSON-tagged structs directly).
type PolicyConfig struct {
	MCP         MCPConfig          `yaml:"mcp"`
	File        FileConfig         `yaml:"file"`
	Commands    CommandConfig      `yaml:"commands"`
	Network     NetworkConfig      `yaml:"network"`
	Web         WebConfig          `yaml:"web"`
	AWS         AWSConfig          `yaml:"aws"`
	Secrets     SecretsConfig      `yaml:"secrets"`
	Credentials []CredentialConfig `yaml:"credentials"`
	Skills      SkillsConfig       `yaml:"skills"`
	// DisabledRules is a list of rule_id strings or glob patterns (using "/"
	// as the segment separator, so "file_policy/*" matches
	// "file_policy/sensitive_credential" but not "file_policy/x/y").
	//
	// Each entry is validated at load time: an invalid glob pattern (one that
	// path.Match would reject) causes Load/decode to return an error, so a
	// bad pattern can never silently break policy evaluation.
	//
	// Locked rule_ids (defined in resolver.rego's locked_rules constant) are
	// silently ignored at evaluation time in Rego — listing them here has no
	// effect, they will still fire. Validation does NOT reject locked ids
	// because the locked set is defined in Rego (not Go) and may evolve.
	DisabledRules []string `yaml:"disabled_rules"`

	// DaemonUnreachable selects the hook's behavior when agentjail-daemon
	// cannot be reached (crash, OOM, not-yet-started). See ADR 0050. The
	// hook itself is stdlib-only and cannot read this file directly; the
	// daemon serializes the resolved level into the hook-fallback sidecar
	// (internal/wire.HookFallbackPath) on startup and every SIGHUP reload.
	//
	// Empty string defaults to DaemonUnreachableDegraded (ADR 0074).
	// Load/decode rejects any non-empty value that is not one of the three
	// named levels.
	DaemonUnreachable DaemonUnreachableLevel `yaml:"daemon_unreachable"`

	// Enforcement selects whether a deny/ask verdict is acted on or merely
	// recorded. Empty defaults to EnforcementEnforce — monitor mode is opt-in,
	// because a default that silently stops enforcing would be the AGE-212 bug
	// class as a feature. See ADR 0091-monitor-mode-tools.
	Enforcement EnforcementMode `yaml:"enforcement"`
}

// EnforcementMode selects whether the daemon acts on a policy verdict or only
// records what it would have done. It governs the daemon-reachable path only;
// DaemonUnreachableLevel is the independent axis for when the daemon is gone.
type EnforcementMode string

const (
	// EnforcementEnforce acts on the verdict: deny blocks, ask prompts.
	// Default when unset.
	EnforcementEnforce EnforcementMode = "enforce"

	// EnforcementMonitor evaluates the full policy set and records the verdict,
	// but downgrades deny/ask to allow so nothing is blocked — the land-and-expand
	// on-ramp ("run it log-only for a day, then choose what to enforce").
	// The agent still sees a notice; the decision row records what was actually
	// allowed plus the verdict that did not fire.
	EnforcementMonitor EnforcementMode = "monitor"
)

// validateEnforcement rejects any non-empty EnforcementMode that is not one of
// the named modes. Empty is valid (defaults to enforce).
func validateEnforcement(mode EnforcementMode) error {
	switch mode {
	case "", EnforcementEnforce, EnforcementMonitor:
		return nil
	default:
		return fmt.Errorf("enforcement: invalid value %q (must be one of: enforce, monitor)", mode)
	}
}

// Monitoring reports whether verdicts are recorded but not acted on.
func (c *PolicyConfig) Monitoring() bool {
	return c != nil && c.Enforcement == EnforcementMonitor
}

// DaemonUnreachableLevel is the tiered policy for hook behavior when the
// daemon cannot be reached. See ADR 0050 and docs/adr/0050-daemon-unreachable-policy.md.
type DaemonUnreachableLevel string

const (
	// DaemonUnreachableAllow fails open: the tool call is allowed exactly as
	// before this feature existed. Opt-in since ADR 0074.
	DaemonUnreachableAllow DaemonUnreachableLevel = "allow"

	// DaemonUnreachableDegraded enforces a small offline critical denylist
	// (the locked-rule set, compiled by the daemon into the sidecar's
	// OfflineRules) via stdlib pattern-matching in the hook; everything else
	// is allowed. Reduced-but-nonzero protection, work continues.
	// Default when unset (ADR 0074).
	DaemonUnreachableDegraded DaemonUnreachableLevel = "degraded"

	// DaemonUnreachableDeny fails closed: the tool call is denied with a
	// reason that includes restart instructions.
	DaemonUnreachableDeny DaemonUnreachableLevel = "deny"
)

// validateDaemonUnreachable rejects any non-empty DaemonUnreachableLevel that
// is not one of the three named levels. Empty is valid (defaults to allow).
func validateDaemonUnreachable(level DaemonUnreachableLevel) error {
	switch level {
	case "", DaemonUnreachableAllow, DaemonUnreachableDegraded, DaemonUnreachableDeny:
		return nil
	default:
		return fmt.Errorf("daemon_unreachable: invalid value %q (must be one of: allow, degraded, deny)", level)
	}
}

// MCPConfig controls which MCP servers the agent is allowed to call.
type MCPConfig struct {
	// Allowed is a list of glob patterns for permitted MCP server names.
	// An empty list means deny all MCP calls (safe default).
	Allowed []string `yaml:"allowed"`

	// Blocked is a list of glob patterns whose matches are denied even if
	// they would otherwise match an Allowed entry.  Blocked takes precedence.
	Blocked []string `yaml:"blocked"`

	// Servers provides per-server configuration for servers in the allowlist.
	// When a server has a non-empty AllowedTools list, only the listed tools
	// may be called; all other tools are denied with rule_id
	// mcp_policy/tool_not_allowed.  When AllowedTools is absent or empty,
	// all tools of the server are permitted (backwards-compatible default).
	Servers map[string]MCPServerConfig `yaml:"servers"`
}

// MCPServerConfig holds per-server overrides for an allowed MCP server.
type MCPServerConfig struct {
	// AllowedTools is a list of tool names that may be called on this server.
	// When empty (or the key is absent from Servers), all tools are allowed.
	AllowedTools []string `yaml:"allowed_tools"`

	// BlockedTools is a list of tool names that are always denied on this server,
	// even if the server itself is allowed. BlockedTools takes precedence over
	// AllowedTools and the default allow-all behaviour.
	BlockedTools []string `yaml:"blocked_tools"`

	// AskTools is a list of tool names that require user confirmation before
	// execution on this server. AskTools fires after BlockedTools (a tool in
	// both lists is denied, not asked) and after AllowedTools filtering.
	AskTools []string `yaml:"ask_tools"`
}

// SkillsConfig controls which skills the agent may invoke.
type SkillsConfig struct {
	// Allowed is a list of skill name patterns that are permitted.
	// When empty, all skills are allowed (backwards-compatible default).
	Allowed []string `yaml:"allowed"`

	// Blocked is a list of skill name patterns that are always denied.
	// Blocked takes precedence over Allowed.
	Blocked []string `yaml:"blocked"`

	// Ask is a list of skill name patterns that require user confirmation.
	Ask []string `yaml:"ask"`
}

// FileConfig supplements the built-in macOS sensitive-path deny list.
type FileConfig struct {
	// ExtraDeny adds user-defined path patterns to the deny-list (beyond the
	// built-in ~/.ssh, ~/.aws, ~/.gnupg, /etc, /var, … list).
	ExtraDeny []string `yaml:"extra_deny"`

	// ExtraAllow adds paths that are always permitted (e.g. additional
	// project directories the agent legitimately needs to read).
	ExtraAllow []string `yaml:"extra_allow"`

	// TempRoots is NOT read from YAML; it is injected programmatically by the
	// daemon before each OPA eval so Rego rules can use it via
	// data.agentjail.config.file.temp_roots.  The daemon populates this with
	// os.TempDir() (canonicalized) plus structural fallbacks so the policy
	// never needs env access.  The yaml tag uses "-" so Marshal/Unmarshal of
	// policy.yaml is unaffected.
	TempRoots []string `yaml:"-"`
}

// CommandConfig supplements the built-in dangerous-command block list.
type CommandConfig struct {
	// ExtraBlock adds user-defined command regex patterns to block
	// (appended to the built-in rm -rf / curl|sh / sudo / … list).
	ExtraBlock []string `yaml:"extra_block"`
}

// NetworkConfig controls which hosts the agent process is allowed to reach
// over TCP.  With agentjail-netproxy running, hostname-based egress filtering
// is enforced at the proxy (the real enforcement point on both OSes); the
// shield's own resolve-and-allow-by-IP behavior (sbpl rules on macOS, a
// not-implemented warning on Linux since Landlock has no network ABI) is a
// secondary, best-effort layer kept consistent with the proxy's list.
//
// AllowedHosts here is the EDITABLE/removable list. It does not include the
// essential provider hosts (see EssentialAllowedHosts) -- those are always
// merged in via PolicyConfig.EffectiveAllowedHosts and cannot be removed by
// policy.yaml. Enforcement (netproxy) and OPA serialization (ToOPAData) both
// use the effective list, not this raw field, so callers should not read
// AllowedHosts directly when they need the enforced set.
//
// Filtering at the shield layer is IP-based, not hostname-based: if a CDN
// host rotates its IPs between sessions, the new IPs will not be in the
// allow set until the next shield launch.  This is a documented Tier 1.5
// trade-off; netproxy (hostname-based, per-request) does not share it.
type NetworkConfig struct {
	// AllowedHosts is the list of hostnames whose resolved IPs are permitted
	// for outbound TCP connections.  The resolver runs at shield startup; DNS
	// (UDP 53) and loopback are always permitted regardless of this list.
	// This is the extended/editable list -- see EffectiveAllowedHosts for the
	// enforced set, which always includes the non-removable essentials.
	AllowedHosts []string `yaml:"allowed_hosts"`

	// TunnelMITM sets this install's standing posture for TLS interception
	// under --tunnel. Tri-state: absent = on (the default), false = standing
	// opt-out, true = explicit opt-in. --mitm / --no-mitm override it per
	// launch. See ADR 0077 (D2, D3).
	TunnelMITM *bool `yaml:"tunnel_mitm"`

	// CaptureGateway routes a detected provider agent's LLM API traffic through a
	// local capture gateway (base-URL injection) instead of transparent MITM.
	// Tri-state: absent = on (default), false = opt-out, true = explicit opt-in.
	// See ADR 0109-baseurl-capture-gateway (AGE-259).
	CaptureGateway *bool `yaml:"capture_gateway"`

	// TunnelIPv6 enables the flag-gated IPv6 datapath for the macOS tunnel.
	// Tri-state: absent = off (the default), false = standing opt-out, true =
	// explicit opt-in. --tunnel-ipv6 / --no-tunnel-ipv6 override it per launch;
	// the AGENTJAIL_TUNNEL_IPV6 env var is a transitional override, one release.
	// See ADR 0110-network-flag-consolidation (AGE-262).
	TunnelIPv6 *bool `yaml:"tunnel_ipv6"`
}

// EssentialAllowedHosts returns the minimal, non-removable set of hosts an
// agent needs to authenticate and run inference against its own provider.
// These are EXACT hostnames only -- no wildcards -- to keep the always-on,
// non-removable surface as small as possible. They are merged into every
// PolicyConfig's effective allowlist (see EffectiveAllowedHosts) regardless
// of what policy.yaml says, so a user cannot accidentally (or a malicious
// policy edit cannot silently) starve or reroute the agent's own provider
// traffic. See ADR 0038.
//
// mcp-proxy.anthropic.com is included because claude.ai's hosted connectors
// (Gmail, Google Calendar, Google Drive, typefully, and other claude.ai MCP
// connectors) proxy their MCP traffic through it -- without it, those
// connectors break under the shield even though claude.ai itself is
// reachable. See ADR 0040.
//
// chat.openai.com is included because it is the legacy OpenAI/Codex backend
// URL: Codex CLI still normalizes some auth/session requests against it even
// though the primary API host is api.openai.com and chatgpt.com is the
// current web host -- without it, Codex CLI auth can break under the shield.
// See ADR 0041.
//
// Returns a defensive copy; callers may freely mutate the result.
func EssentialAllowedHosts() []string {
	return []string{
		"api.anthropic.com",
		"claude.ai",
		"platform.claude.com",
		"mcp-proxy.anthropic.com",
		"api.openai.com",
		"auth.openai.com",
		"chatgpt.com",
		"chat.openai.com",
		"accounts.google.com",
		"oauth2.googleapis.com",
	}
}

// ExtendedDefaultAllowedHosts returns the shipped default for the editable
// Network.AllowedHosts field: broad wildcards, telemetry, hosted MCP
// endpoints, package registries, git hosting, and documentation sites. This
// list is fully removable/replaceable by a user's policy.yaml -- unlike
// EssentialAllowedHosts, nothing here is required for the agent's own
// provider connection to function.
//
// Deliberately excluded: meta-proxy MCP hosts (mcp.composio.dev,
// mcp.zapier.com) and the Stripe payment MCP host (mcp.stripe.com) -- these
// remain blocked by default even though the corresponding MCP call is also
// gated by mcp.allowed.
//
// Returns a defensive copy; callers may freely mutate the result.
func ExtendedDefaultAllowedHosts() []string {
	out := []string{
		// Anthropic (non-essential / broad)
		"*.claude.ai",
		"statsig.anthropic.com",
		"sentry.io",
		"*.sentry.io",
		// Google (broad wildcard stays removable)
		"*.googleapis.com",
		// OpenAI Codex extras (core codex hosts are essential above)
		// Cursor CLI (login/update + exact API subdomains)
		"cursor.com",
		"www.cursor.com",
		"api2.cursor.sh",
		"api5.cursor.sh",
		"agent.api5.cursor.sh",
		"agentn.api5.cursor.sh",
		"authenticate.cursor.sh",
		"authenticator.cursor.sh",
		"authentication.cursor.sh",
		"prod.authentication.cursor.sh",
	}
	// Hosted MCP servers (the MCP call is still gated by mcp.allowed).
	// Sourced from HostedMCPRegistry -- see HostedMCPAllowedHosts. The hosts
	// live only in the registry, not duplicated here as literals (ADR 0040).
	out = append(out, HostedMCPAllowedHosts()...)
	out = append(out,
		// Package registries
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"pypi.org",
		"files.pythonhosted.org",
		"crates.io",
		"static.crates.io",
		"index.crates.io",
		"proxy.golang.org",
		"sum.golang.org",
		"repo1.maven.org",
		"repo.maven.apache.org",
		"plugins.gradle.org",
		"rubygems.org",
		"deno.land",
		"cdn.jsdelivr.net",
		"unpkg.com",
		"esm.sh",
		"*.huggingface.co",
		// Git hosting
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"objects.githubusercontent.com",
		"github-releases.githubusercontent.com",
		"codeload.github.com",
		"ghcr.io",
		"gitlab.com",
		"registry.gitlab.com",
		// Documentation
		"docs.python.org",
		"docs.rs",
		"doc.rust-lang.org",
		"nodejs.org",
		"go.dev",
		"pkg.go.dev",
		"developer.mozilla.org",
		"learn.microsoft.com",
		// agentjail anonymous telemetry (users may remove)
		"us.i.posthog.com",
	)
	return out
}

// EffectiveAllowedHosts returns the enforced allowlist, in three tiers,
// essentials first, order-stable, deduplicated across all three:
//
//  1. Essentials (EssentialAllowedHosts) -- always present, non-removable.
//  2. MCP-derived (MCPDerivedAllowedHosts) -- hosts for hosted MCP servers
//     that are currently allowed under c.MCP. Non-removable WHILE the MCP
//     stays allowed: removing the server from mcp.allowed, or blocking it,
//     removes its hosts here on the next load. This tier exists so a
//     curated Network.AllowedHosts that omits a hosted MCP's hosts (e.g. a
//     user trims the extended default down to just git/npm) does not
//     silently break an MCP server the user explicitly allowed.
//  3. Editable (Network.AllowedHosts) -- the user's own list, fully
//     removable/replaceable.
//
// This is what netproxy and the shield enforce, and what ToOPAData
// serializes -- never the raw Network.AllowedHosts field alone. See ADR 0038
// and ADR 0040.
//
// Returns a defensive copy; callers may freely mutate the result.
func (c *PolicyConfig) EffectiveAllowedHosts() []string {
	essentials := EssentialAllowedHosts()
	derived := MCPDerivedAllowedHosts(c.MCP)
	total := len(essentials) + len(derived) + len(c.Network.AllowedHosts)
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	appendDedup := func(hosts []string) {
		for _, h := range hosts {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	appendDedup(essentials)
	appendDedup(derived)
	appendDedup(c.Network.AllowedHosts)
	return out
}

// WebConfig governs the agent's web read tools (WebSearch / WebFetch), which
// web_policy.rego allows by default to stop them escalating to the user on every
// call. WebSearch is always allowed; WebFetch is allowed unless its target host
// matches a Blocked glob.
type WebConfig struct {
	// Blocked is a list of host glob patterns; a WebFetch whose URL host matches
	// any of them is denied (rule_id web_policy/fetch_blocked). Patterns match
	// case-insensitively and `*` spans dots (so "*tracking*" matches subdomains,
	// "*.internal" matches a suffix, "169.254.*" a prefix). Empty by default —
	// nothing is blocked. This is domain control, not exfil-proofing; to make
	// WebFetch prompt again, disable web_policy/fetch via disabled_rules.
	Blocked []string `yaml:"blocked"`
}

// AWSConfig configures per-account AWS posture (ADR 0017). The daemon
// resolves the AWS account targeted by an `aws --profile <name>` CLI command
// (from ~/.aws/config) and injects it as input.aws_account; aws_policy/*
// reads the posture here and maps it to a verdict
// (sandbox: CUD allow / delete ask; prod: CUD ask / delete deny;
// locked: CUD deny; custom: per-account flags).
//
// default_posture is the fail-safe: an account not listed under accounts is
// treated as default_posture (prod when unset). resources maps an ARN glob
// (e.g. "arn:aws:s3:::prod-*") to a posture that overrides the account
// posture for matching resources (most-specific / longest matching glob
// wins).
type AWSConfig struct {
	DefaultPosture string                 `yaml:"default_posture"`
	Accounts       map[string]AWSAccount  `yaml:"accounts"`
	Resources      map[string]AWSResource `yaml:"resources"`
}

// AWSAccount is the per-account posture entry. Posture is one of
// sandbox|prod|locked|custom. The boolean flags are consulted only when
// posture is custom.
type AWSAccount struct {
	Posture    string `yaml:"posture"`
	AllowCUD   bool   `yaml:"allow_cud"`
	DenyDelete bool   `yaml:"deny_delete"`
	ReadOnly   bool   `yaml:"read_only"`
}

// AWSResource is a resource-level posture override keyed by an ARN glob.
type AWSResource struct {
	Posture    string `yaml:"posture"`
	DenyDelete bool   `yaml:"deny_delete"`
}

// SecretsConfig controls env stripping at agent launch.  When StripOnLaunch
// is true (the default), agentjail-shield removes env vars matching
// EnvBlocklist from the agent's environment before exec'ing it.  This
// prevents ambient credentials (AWS_ACCESS_KEY_ID, PGPASSWORD, etc.) from
// leaking into the sandboxed agent process.
//
// If the agentjail-secrets broker is running, stripped vars are replaced
// with placeholders signalling that scoped creds are available via the
// broker (Kind-A from ADR 0004).
type SecretsConfig struct {
	EnvBlocklist []string `yaml:"env_blocklist"`

	StripOnLaunch *bool `yaml:"strip_on_launch"`

	// EnvPassthrough is a list of additional env var names that are allowed
	// through the clean-env allowlist. These are appended to the built-in
	// baseline allowlist (PATH, HOME, TERM, etc.) when constructing the
	// agent's environment. Use this for project-specific safe variables
	// that the agent needs but that are not in the baseline.
	EnvPassthrough []string `yaml:"env_passthrough"`

	Grants []SecretGrant `yaml:"grants"`
}

type SecretGrant struct {
	Name  string `yaml:"name"`
	Scope string `yaml:"scope"`
	TTL   string `yaml:"ttl"`
}

// CredentialConfig describes a credential that the phantom token registry
// manages. The proxy generates a phantom token for each credential, strips
// the real value from the agent's env, and injects it into upstream requests
// that pass host/method/path validation.
type CredentialConfig struct {
	ID             string                    `yaml:"id"`
	EnvVar         string                    `yaml:"env_var"`
	Source         string                    `yaml:"source"`
	AllowedHosts   []string                  `yaml:"allowed_hosts"`
	AllowedMethods []string                  `yaml:"allowed_methods"`
	AllowedPaths   []string                  `yaml:"allowed_paths"`
	Injection      CredentialInjectionConfig `yaml:"injection"`
	Violation      string                    `yaml:"violation"`
	TTL            string                    `yaml:"ttl"`
}

// CredentialInjectionConfig describes how a real credential is injected into
// the upstream HTTP request when the proxy swaps a phantom token.
type CredentialInjectionConfig struct {
	Type   string `yaml:"type"`
	Header string `yaml:"header"`
	Scheme string `yaml:"scheme"`
}

// Load reads a PolicyConfig from a YAML file at path.
//
// Unknown YAML fields cause an error (strict mode). An empty file or a file
// containing only YAML comments is valid and returns an empty (zero-value)
// PolicyConfig with a nil error — callers that need defaults should merge with
// Default() after loading.
//
// Returns a non-nil *PolicyConfig alongside any error so callers can still
// access partially-decoded data for diagnostics.
func Load(path string) (*PolicyConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy config %s: %w", path, err)
	}
	defer f.Close()
	return decode(f)
}

// validateDisabledRules checks that every entry in patterns is a syntactically
// valid glob pattern with "/" as the segment separator (matching OPA's
// glob.match(p, ["/"], id) semantics).
//
// path.Match is used because it treats "/" as a separator and rejects the same
// class of malformed patterns (unmatched "[", etc.) that OPA would reject.
// A compile-time rejection prevents a bad pattern from turning every eval into
// an error at runtime.
func validateDisabledRules(patterns []string) error {
	for _, p := range patterns {
		// path.Match will return ErrBadPattern for malformed globs.
		if _, err := path.Match(p, "probe"); err != nil {
			return fmt.Errorf("disabled_rules: invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

// validateMCPGlobs checks that every entry in mcp.allowed and mcp.blocked is
// a syntactically valid glob pattern, using the same path.Match probe as
// validateDisabledRules -- MCP server names never contain "/", so path.Match
// is equivalent to mcp_policy.rego's glob.match(pattern, [], name) here too.
// A malformed mcp.allowed/mcp.blocked pattern causes Load/decode to return an
// error, so it can never silently reach OPA evaluation (where mcp_policy.rego
// would deny-by-default anyway, but only after the bad pattern were already
// live in the enforced config) or MCPDerivedAllowedHosts.
func validateMCPGlobs(mcp MCPConfig) error {
	for _, p := range mcp.Allowed {
		if _, err := path.Match(p, "probe"); err != nil {
			return fmt.Errorf("mcp.allowed: invalid glob pattern %q: %w", p, err)
		}
	}
	for _, p := range mcp.Blocked {
		if _, err := path.Match(p, "probe"); err != nil {
			return fmt.Errorf("mcp.blocked: invalid glob pattern %q: %w", p, err)
		}
	}
	return nil
}

// decode is the inner parser shared by Load and tests.
func decode(r io.Reader) (*PolicyConfig, error) {
	cfg := &PolicyConfig{}
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		// io.EOF means the reader had no content (empty file) — that is valid.
		if strings.Contains(err.Error(), "EOF") {
			return cfg, nil
		}
		return cfg, fmt.Errorf("decode policy config: %w", err)
	}
	if err := validateDisabledRules(cfg.DisabledRules); err != nil {
		return cfg, err
	}
	if err := validateMCPGlobs(cfg.MCP); err != nil {
		return cfg, err
	}
	if err := validateDaemonUnreachable(cfg.DaemonUnreachable); err != nil {
		return cfg, err
	}
	if err := validateEnforcement(cfg.Enforcement); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Default returns a PolicyConfig with sensible out-of-box settings.
//
// MCP.Allowed is empty (deny all MCP calls by default) because the allowlist
// model requires explicit opt-in.  MCP.Blocked pre-populates common
// payment/comms server patterns that should never be auto-allowed.
//
// Network.AllowedHosts pre-populates the common dev package registries so
// a default install does not block go get / npm install / pip install out of
// the box.  Users can extend this list in policy.yaml.
func Default() *PolicyConfig {
	return &PolicyConfig{
		MCP: MCPConfig{
			Allowed: []string{},
			Blocked: []string{
				"*stripe*",
				"*payment*",
				"*billing*",
				"*twilio*",
				"*sendgrid*",
			},
			Servers: map[string]MCPServerConfig{},
		},
		File: FileConfig{
			ExtraDeny:  []string{},
			ExtraAllow: []string{},
		},
		Commands: CommandConfig{
			ExtraBlock: []string{},
		},
		DisabledRules: []string{},
		Network: NetworkConfig{
			// Extended/editable defaults only -- the essential provider hosts
			// (api.anthropic.com, claude.ai, ...) are always merged in via
			// EffectiveAllowedHosts and are intentionally NOT part of this
			// seed. See EssentialAllowedHosts / ExtendedDefaultAllowedHosts.
			AllowedHosts: ExtendedDefaultAllowedHosts(),
		},
		// Web read tools (WebSearch/WebFetch) are allowed by default; no hosts
		// are blocked out of the box. Add host globs here to deny specific
		// WebFetch targets.
		Web: WebConfig{
			Blocked: []string{},
		},
		// AWS per-account posture: fail-safe default is prod (unknown account
		// -> delete denied). No accounts blessed by default.
		AWS: AWSConfig{
			DefaultPosture: "prod",
			Accounts:       map[string]AWSAccount{},
			Resources:      map[string]AWSResource{},
		},
		Secrets: SecretsConfig{
			EnvBlocklist: []string{
				"AWS_ACCESS_KEY_ID",
				"AWS_SECRET_ACCESS_KEY",
				"AWS_SESSION_TOKEN",
				"AWS_SECURITY_TOKEN",
				"AWS_DELEGATION_TOKEN",
				"PGPASSWORD",
				"REDIS_PASSWORD",
				"GITHUB_TOKEN",
				"ANTHROPIC_API_KEY",
				"OPENAI_API_KEY",
			},
			StripOnLaunch: boolPtr(true),
		},
		// Skills: empty lists = allow all skills (backwards-compatible default).
		// Populate allowed/blocked/ask in policy.yaml for granular control.
		Skills: SkillsConfig{
			Allowed: []string{},
			Blocked: []string{},
			Ask:     []string{},
		},
		// DaemonUnreachable: degraded by default — the offline denials are a
		// subset of the permanently-locked online rules, so no working call is
		// newly refused (ADR 0074, superseding 0050's allow default).
		DaemonUnreachable: DaemonUnreachableDegraded,
		Enforcement:       EnforcementEnforce,
	}
}

// Merge returns a new PolicyConfig that starts from base and applies non-zero
// fields from overlay on top.  The merge semantics are:
//
//   - Slice fields: if overlay's slice is non-empty, it replaces the base
//     slice entirely.  An overlay of nil/empty means "keep the base value."
//     This lets a partial policy.yaml (e.g. only mcp.allowed) keep the
//     default mcp.blocked list intact.
//   - Map fields (MCP.Servers): overlay entries are unioned into the base
//     map; an overlay entry replaces a base entry with the same key.
//   - TempRoots is always derived at runtime by the daemon; Merge copies
//     the base value (which will be replaced at injection time anyway).
//
// MergeProjectOverlay applies an ADDITIVE-ONLY per-folder overlay on top of a
// fully-resolved base policy. It is deliberately DISTINCT from Merge (which
// replaces slices, letting an overlay shrink or clear a base list). A project
// overlay -- a `./.agentjail/policy.yaml` walked up from the agent's CWD -- is
// less trusted than the user's global policy, so it may only WIDEN allow-lists
// and ADD to block-lists; it can never remove or weaken a base restriction:
//
//   - network.allowed_hosts: UNION(base, overlay) -- a trusted project may add hosts
//   - mcp.allowed:           UNION(base, overlay) -- a trusted project may allow more MCPs
//   - mcp.blocked:           UNION(base, overlay) -- overlay may add blocks (more restrictive)
//
// Everything else is taken from base UNCHANGED: the non-removable essentials
// (via EffectiveAllowedHosts), disabled_rules, deny lists, per-server tool
// policy, secrets, etc. Because mcp.blocked is unioned (never shrunk) and
// blocked wins over allowed in mcp_policy.rego, widening mcp.allowed can never
// un-block a blocked server. An overlay must only reach this function for a
// TRUSTED project directory (see the trust gate); an untrusted overlay is
// ignored upstream and never merged.
//
// Neither base nor overlay is mutated; a freshly allocated *PolicyConfig is
// returned. A nil overlay returns a copy of base unchanged.
func MergeProjectOverlay(base, overlay *PolicyConfig) *PolicyConfig {
	if base == nil {
		base = Default()
	}
	result := *base // shallow copy; the three widened fields below are replaced with fresh slices
	if overlay == nil {
		return &result
	}
	result.Network.AllowedHosts = unionPreserveOrder(base.Network.AllowedHosts, overlay.Network.AllowedHosts)
	result.MCP.Allowed = unionPreserveOrder(base.MCP.Allowed, overlay.MCP.Allowed)
	result.MCP.Blocked = unionPreserveOrder(base.MCP.Blocked, overlay.MCP.Blocked)
	return &result
}

// unionPreserveOrder returns base's entries followed by overlay's new entries,
// de-duplicated, order-preserving (base first). It never drops a base entry.
func unionPreserveOrder(base, overlay []string) []string {
	seen := make(map[string]struct{}, len(base)+len(overlay))
	out := make([]string, 0, len(base)+len(overlay))
	for _, group := range [][]string{base, overlay} {
		for _, s := range group {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// Neither base nor overlay is mutated; Merge returns a freshly allocated
// *PolicyConfig.
func Merge(base, overlay *PolicyConfig) *PolicyConfig {
	if base == nil {
		base = Default()
	}
	if overlay == nil {
		overlay = &PolicyConfig{}
	}

	// Deep-copy base as our result.
	result := &PolicyConfig{}

	// MCP.Allowed
	if len(overlay.MCP.Allowed) > 0 {
		result.MCP.Allowed = append([]string(nil), overlay.MCP.Allowed...)
	} else {
		result.MCP.Allowed = append([]string(nil), base.MCP.Allowed...)
	}
	// MCP.Blocked
	if len(overlay.MCP.Blocked) > 0 {
		result.MCP.Blocked = append([]string(nil), overlay.MCP.Blocked...)
	} else {
		result.MCP.Blocked = append([]string(nil), base.MCP.Blocked...)
	}
	// MCP.Servers — union, overlay wins on conflict.
	result.MCP.Servers = make(map[string]MCPServerConfig, len(base.MCP.Servers)+len(overlay.MCP.Servers))
	for k, v := range base.MCP.Servers {
		result.MCP.Servers[k] = v
	}
	for k, v := range overlay.MCP.Servers {
		result.MCP.Servers[k] = v
	}

	// File.ExtraDeny
	if len(overlay.File.ExtraDeny) > 0 {
		result.File.ExtraDeny = append([]string(nil), overlay.File.ExtraDeny...)
	} else {
		result.File.ExtraDeny = append([]string(nil), base.File.ExtraDeny...)
	}
	// File.ExtraAllow
	if len(overlay.File.ExtraAllow) > 0 {
		result.File.ExtraAllow = append([]string(nil), overlay.File.ExtraAllow...)
	} else {
		result.File.ExtraAllow = append([]string(nil), base.File.ExtraAllow...)
	}
	// TempRoots — runtime-injected; copy from base (daemon will overwrite).
	result.File.TempRoots = append([]string(nil), base.File.TempRoots...)

	// Commands.ExtraBlock
	if len(overlay.Commands.ExtraBlock) > 0 {
		result.Commands.ExtraBlock = append([]string(nil), overlay.Commands.ExtraBlock...)
	} else {
		result.Commands.ExtraBlock = append([]string(nil), base.Commands.ExtraBlock...)
	}

	// Network.AllowedHosts -- nil-vs-empty matters here: yaml.v3 decodes an
	// omitted "allowed_hosts" key to nil, and an explicit "allowed_hosts: []"
	// to a non-nil empty slice. An omitted field means "keep the base
	// (extended defaults)"; an explicit empty list means "the user wants no
	// extended hosts" and replaces the base with an empty list. Either way,
	// EffectiveAllowedHosts still merges in the non-removable essentials, so
	// even an explicit empty list keeps the agent able to reach its provider.
	if overlay.Network.AllowedHosts != nil {
		result.Network.AllowedHosts = append([]string(nil), overlay.Network.AllowedHosts...)
	} else {
		result.Network.AllowedHosts = append([]string(nil), base.Network.AllowedHosts...)
	}

	// Network.TunnelMITM -- tri-state pointer, so nil means "not stated" and
	// keeps the base rather than clearing it. ADR 0077 (D3).
	if overlay.Network.TunnelMITM != nil {
		result.Network.TunnelMITM = overlay.Network.TunnelMITM
	} else {
		result.Network.TunnelMITM = base.Network.TunnelMITM
	}

	// Network.CaptureGateway -- tri-state pointer, same contract as
	// TunnelMITM. See ADR 0109-baseurl-capture-gateway.
	if overlay.Network.CaptureGateway != nil {
		result.Network.CaptureGateway = overlay.Network.CaptureGateway
	} else {
		result.Network.CaptureGateway = base.Network.CaptureGateway
	}

	// Network.TunnelIPv6 -- tri-state pointer, same contract as TunnelMITM.
	// See ADR 0110-network-flag-consolidation.
	if overlay.Network.TunnelIPv6 != nil {
		result.Network.TunnelIPv6 = overlay.Network.TunnelIPv6
	} else {
		result.Network.TunnelIPv6 = base.Network.TunnelIPv6
	}

	// Web.Blocked
	if len(overlay.Web.Blocked) > 0 {
		result.Web.Blocked = append([]string(nil), overlay.Web.Blocked...)
	} else {
		result.Web.Blocked = append([]string(nil), base.Web.Blocked...)
	}

	// AWS — fail-safe: default_posture falls back to "prod" if both empty.
	// (An empty overlay default_posture means "keep base", not "clear" — and
	// base is "prod" from Default(), so the fail-safe is preserved.)
	switch {
	case overlay.AWS.DefaultPosture != "":
		result.AWS.DefaultPosture = overlay.AWS.DefaultPosture
	case base.AWS.DefaultPosture != "":
		result.AWS.DefaultPosture = base.AWS.DefaultPosture
	default:
		result.AWS.DefaultPosture = "prod"
	}
	// Accounts/Resources maps: union, overlay wins on conflict.
	result.AWS.Accounts = make(map[string]AWSAccount, len(base.AWS.Accounts)+len(overlay.AWS.Accounts))
	for k, v := range base.AWS.Accounts {
		result.AWS.Accounts[k] = v
	}
	for k, v := range overlay.AWS.Accounts {
		result.AWS.Accounts[k] = v
	}
	result.AWS.Resources = make(map[string]AWSResource, len(base.AWS.Resources)+len(overlay.AWS.Resources))
	for k, v := range base.AWS.Resources {
		result.AWS.Resources[k] = v
	}
	for k, v := range overlay.AWS.Resources {
		result.AWS.Resources[k] = v
	}

	// Secrets.EnvBlocklist
	if len(overlay.Secrets.EnvBlocklist) > 0 {
		result.Secrets.EnvBlocklist = append([]string(nil), overlay.Secrets.EnvBlocklist...)
	} else {
		result.Secrets.EnvBlocklist = append([]string(nil), base.Secrets.EnvBlocklist...)
	}
	// Secrets.StripOnLaunch — pointer: nil means keep base, non-nil means override.
	if overlay.Secrets.StripOnLaunch != nil {
		result.Secrets.StripOnLaunch = boolPtr(*overlay.Secrets.StripOnLaunch)
	} else if base.Secrets.StripOnLaunch != nil {
		result.Secrets.StripOnLaunch = boolPtr(*base.Secrets.StripOnLaunch)
	} else {
		result.Secrets.StripOnLaunch = boolPtr(true)
	}
	// Secrets.Grants — overlay wins if non-empty, else keep base.
	if len(overlay.Secrets.Grants) > 0 {
		result.Secrets.Grants = append([]SecretGrant(nil), overlay.Secrets.Grants...)
	} else {
		result.Secrets.Grants = append([]SecretGrant(nil), base.Secrets.Grants...)
	}
	// Secrets.EnvPassthrough — overlay wins if non-empty, else keep base.
	if len(overlay.Secrets.EnvPassthrough) > 0 {
		result.Secrets.EnvPassthrough = append([]string(nil), overlay.Secrets.EnvPassthrough...)
	} else {
		result.Secrets.EnvPassthrough = append([]string(nil), base.Secrets.EnvPassthrough...)
	}

	// Credentials — overlay wins if non-empty, else keep base.
	if len(overlay.Credentials) > 0 {
		result.Credentials = append([]CredentialConfig(nil), overlay.Credentials...)
	} else {
		result.Credentials = append([]CredentialConfig(nil), base.Credentials...)
	}

	// DisabledRules — overlay wins if non-empty, else keep base.
	// An empty overlay means "don't change the base" (not "clear all disabled rules").
	if len(overlay.DisabledRules) > 0 {
		result.DisabledRules = append([]string(nil), overlay.DisabledRules...)
	} else {
		result.DisabledRules = append([]string(nil), base.DisabledRules...)
	}

	// Skills.Allowed
	if len(overlay.Skills.Allowed) > 0 {
		result.Skills.Allowed = append([]string(nil), overlay.Skills.Allowed...)
	} else {
		result.Skills.Allowed = append([]string(nil), base.Skills.Allowed...)
	}
	// Skills.Blocked
	if len(overlay.Skills.Blocked) > 0 {
		result.Skills.Blocked = append([]string(nil), overlay.Skills.Blocked...)
	} else {
		result.Skills.Blocked = append([]string(nil), base.Skills.Blocked...)
	}
	// Skills.Ask
	if len(overlay.Skills.Ask) > 0 {
		result.Skills.Ask = append([]string(nil), overlay.Skills.Ask...)
	} else {
		result.Skills.Ask = append([]string(nil), base.Skills.Ask...)
	}

	// DaemonUnreachable — overlay wins if set, else base, else the "degraded"
	// default (mirrors AWS.DefaultPosture's three-way fallback above).
	switch {
	case overlay.DaemonUnreachable != "":
		result.DaemonUnreachable = overlay.DaemonUnreachable
	case base.DaemonUnreachable != "":
		result.DaemonUnreachable = base.DaemonUnreachable
	default:
		result.DaemonUnreachable = DaemonUnreachableDegraded
	}

	// Enforcement — same three-way fallback. Deliberately NOT in
	// MergeProjectOverlay: that path is additive-only and a project's
	// .agentjail/policy.yaml lives in the repo the agent can write, so honouring
	// it here would let the agent turn off its own enforcement.
	// See ADR 0091-monitor-mode-tools.
	switch {
	case overlay.Enforcement != "":
		result.Enforcement = overlay.Enforcement
	case base.Enforcement != "":
		result.Enforcement = base.Enforcement
	default:
		result.Enforcement = EnforcementEnforce
	}

	return result
}

// LoadOrDefault loads and merges a PolicyConfig from path over Default().
//
// The absent-vs-malformed distinction is load-bearing (ADR 0040): a genuinely
// missing policy.yaml is the normal first-run state and silently falls back
// to Default() with no error. A PRESENT but unparseable/invalid file (e.g. a
// stray tab, or a bad mcp.allowed glob caught by validateMCPGlobs) is a
// different situation -- it means an operator or an attacker with file-write
// access changed the enforced policy and it no longer parses -- so that case
// returns the error instead of silently swapping in permissive defaults.
// Callers on the enforcement path (agentjail-shield, agentjail-netproxy) MUST
// treat a non-nil error here as fail-loud (refuse to launch / refuse to
// (re)apply), never as "fall back to Default()".
//
//   - File does not exist: Default() is returned with a nil error.
//   - File exists but Load fails (parse or validation error): the error is
//     returned; the *PolicyConfig return value is nil.
func LoadOrDefault(path string) (*PolicyConfig, error) {
	cfg, err := Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return nil, err
	}
	return Merge(Default(), cfg), nil
}

// LoadPolicyForEnforcement is the canonical load path for enforcement
// binaries (agentjail-shield, agentjail-netproxy) -- as opposed to
// LoadOrDefault, which is used throughout the CLI/UI for convenience reads.
// The two currently share fail-loud semantics, but LoadPolicyForEnforcement
// exists as its own named entry point so the "refuse to run with a broken
// enforced policy" contract is explicit at every enforcement call site,
// independent of how LoadOrDefault's internals evolve. See ADR 0041.
//
// Distinguishes the two cases explicitly via os.Stat rather than relying on
// Load's wrapped error:
//
//   - File does not exist: returns Merge(Default(), &PolicyConfig{}) (i.e.
//     built-in defaults) with a nil error -- the normal first-run state,
//     before `agentjail install` has written a policy.yaml.
//   - File exists but Stat/Load/validate fails: returns the error and a nil
//     *PolicyConfig. Callers on the enforcement path MUST treat this as
//     fail-loud (refuse to launch / refuse to (re)apply), never silently
//     substitute Default().
//   - File exists and loads cleanly: returns Merge(Default(), cfg).
func LoadPolicyForEnforcement(path string) (*PolicyConfig, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Merge(Default(), &PolicyConfig{}), nil
		}
		return nil, fmt.Errorf("stat policy config %s: %w", path, err)
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return Merge(Default(), cfg), nil
}

// Save marshals cfg to YAML and writes it atomically to path (temp file +
// rename) with 0600 permissions.  The directory must already exist.
func Save(cfg *PolicyConfig, path string) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal policy config: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for policy config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Best-effort cleanup if we fail before rename.
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp policy config: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp policy config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp policy config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp policy config to %s: %w", path, err)
	}
	return nil
}

// ToOPAData converts the PolicyConfig to the map[string]interface{} shape
// representing the `data.agentjail.config` subtree in the OPA data document.
// The caller is responsible for nesting this under {"config": ToOPAData()}
// when constructing the agentjail namespace to pass to NewHookOPAEngineWithData.
//
// The shape produced (maps to data.agentjail.config.*):
//
//	{
//	  "mcp": {
//	    "allowed": [...],
//	    "blocked": [...],
//	    "servers": { "<name>": {"allowed_tools": [...]} }
//	  },
//	  "file": {
//	    "extra_deny":  [...],
//	    "extra_allow": [...],
//	    "temp_roots":  [...]   // injected at runtime by the daemon
//	  },
//	  "commands": { "extra_block": [...] },
//	  "network":  { "allowed_hosts": [...] },
//	  "web":      { "blocked": [...] }
//	}
//
// Nil slices are serialised as empty JSON arrays so Rego sees [] not null.
func (c *PolicyConfig) ToOPAData() map[string]interface{} {
	if c == nil {
		c = Default()
	}

	sliceOrEmpty := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}

	servers := make(map[string]interface{}, len(c.MCP.Servers))
	for name, sc := range c.MCP.Servers {
		servers[name] = map[string]interface{}{
			"allowed_tools": sliceOrEmpty(sc.AllowedTools),
			"blocked_tools": sliceOrEmpty(sc.BlockedTools),
			"ask_tools":     sliceOrEmpty(sc.AskTools),
		}
	}

	accounts := make(map[string]interface{}, len(c.AWS.Accounts))
	for acct, a := range c.AWS.Accounts {
		accounts[acct] = map[string]interface{}{
			"posture":     postureOrEmpty(a.Posture),
			"allow_cud":   a.AllowCUD,
			"deny_delete": a.DenyDelete,
			"read_only":   a.ReadOnly,
		}
	}
	resources := make(map[string]interface{}, len(c.AWS.Resources))
	for glob, r := range c.AWS.Resources {
		resources[glob] = map[string]interface{}{
			"posture":     postureOrEmpty(r.Posture),
			"deny_delete": r.DenyDelete,
		}
	}
	defaultPosture := c.AWS.DefaultPosture
	if defaultPosture == "" {
		defaultPosture = "prod"
	}

	return map[string]interface{}{
		"mcp": map[string]interface{}{
			"allowed": sliceOrEmpty(c.MCP.Allowed),
			"blocked": sliceOrEmpty(c.MCP.Blocked),
			"servers": servers,
		},
		"file": map[string]interface{}{
			"extra_deny":  sliceOrEmpty(c.File.ExtraDeny),
			"extra_allow": sliceOrEmpty(c.File.ExtraAllow),
			"temp_roots":  sliceOrEmpty(c.File.TempRoots),
		},
		"commands": map[string]interface{}{
			"extra_block": sliceOrEmpty(c.Commands.ExtraBlock),
		},
		// network.allowed_hosts is the EFFECTIVE egress allowlist (non-removable
		// essentials + the editable Network.AllowedHosts), not the raw editable
		// YAML list -- so any future rego rule reading this key sees the real
		// enforced set. See PolicyConfig.EffectiveAllowedHosts.
		"network": map[string]interface{}{
			"allowed_hosts": sliceOrEmpty(c.EffectiveAllowedHosts()),
		},
		// web.blocked is read by web_policy.rego to deny WebFetch to matching hosts.
		"web": map[string]interface{}{
			"blocked": sliceOrEmpty(c.Web.Blocked),
		},
		// aws per-account posture is read by aws_policy.rego (ADR 0017).
		// default_posture is the fail-safe (prod); accounts/resources may be empty.
		"aws": map[string]interface{}{
			"default_posture": defaultPosture,
			"accounts":        accounts,
			"resources":       resources,
		},
		"secrets": map[string]interface{}{
			"env_blocklist":   sliceOrEmpty(c.Secrets.EnvBlocklist),
			"env_passthrough": sliceOrEmpty(c.Secrets.EnvPassthrough),
			"strip_on_launch": c.Secrets.StripOnLaunch != nil && *c.Secrets.StripOnLaunch,
			"grants":          grantsToOPA(c.Secrets.Grants),
		},
		// skills controls which Skill tool invocations are permitted.
		// Rego reads it as data.agentjail.config.skills.{allowed,blocked,ask}.
		"skills": map[string]interface{}{
			"allowed": sliceOrEmpty(c.Skills.Allowed),
			"blocked": sliceOrEmpty(c.Skills.Blocked),
			"ask":     sliceOrEmpty(c.Skills.Ask),
		},
		// credentials is read by policy to understand phantom token bindings.
		"credentials": credentialsToOPA(c.Credentials),
		// disabled_rules is read by resolver.rego to suppress non-locked candidates.
		// Rego reads it as data.agentjail.config.disabled_rules.
		"disabled_rules": sliceOrEmpty(c.DisabledRules),
	}
}

// postureOrEmpty returns p unchanged, or "" when empty. Used so an unset
// posture serialises as an empty string (Rego treats it as the fail-safe
// default_posture path).
func postureOrEmpty(p string) string {
	return p
}

func grantsToOPA(grants []SecretGrant) []interface{} {
	if len(grants) == 0 {
		return []interface{}{}
	}
	out := make([]interface{}, len(grants))
	for i, g := range grants {
		out[i] = map[string]interface{}{
			"name":  g.Name,
			"scope": g.Scope,
			"ttl":   g.TTL,
		}
	}
	return out
}

func credentialsToOPA(creds []CredentialConfig) []interface{} {
	nilSafe := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	if len(creds) == 0 {
		return []interface{}{}
	}
	out := make([]interface{}, len(creds))
	for i, c := range creds {
		out[i] = map[string]interface{}{
			"id":              c.ID,
			"env_var":         c.EnvVar,
			"source":          c.Source,
			"allowed_hosts":   nilSafe(c.AllowedHosts),
			"allowed_methods": nilSafe(c.AllowedMethods),
			"allowed_paths":   nilSafe(c.AllowedPaths),
			"injection": map[string]interface{}{
				"type":   c.Injection.Type,
				"header": c.Injection.Header,
				"scheme": c.Injection.Scheme,
			},
			"violation": c.Violation,
			"ttl":       c.TTL,
		}
	}
	return out
}

// Validate checks the config for obvious misconfigurations and returns a
// (possibly empty) slice of human-readable warning strings.  Warnings are
// advisory — they do not prevent the daemon from starting.
//
// Current checks:
//   - mcp.allowed empty: all MCP calls will be denied (intended safe default,
//     but operators who expect to use MCP should see this warning).
func Validate(cfg *PolicyConfig) []string {
	if cfg == nil {
		return []string{"config is nil — using built-in defaults"}
	}
	var warns []string
	if len(cfg.MCP.Allowed) == 0 {
		warns = append(warns, "mcp.allowed is empty — all MCP calls will be denied")
	}
	return warns
}

// boolPtr returns a pointer to b.  Used for SecretsConfig.StripOnLaunch
// which is a *bool so that "not specified in YAML" (nil) can be
// distinguished from "explicitly set to false".
func boolPtr(b bool) *bool {
	return &b
}
