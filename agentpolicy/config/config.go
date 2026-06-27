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
	MCP      MCPConfig     `yaml:"mcp"`
	File     FileConfig    `yaml:"file"`
	Commands CommandConfig `yaml:"commands"`
	Network  NetworkConfig `yaml:"network"`
	Web      WebConfig     `yaml:"web"`
	AWS      AWSConfig     `yaml:"aws"`
	Secrets  SecretsConfig `yaml:"secrets"`
	Skills   SkillsConfig  `yaml:"skills"`
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
// over TCP.  The shield resolves each hostname to IP addresses at startup and
// emits per-IP sbpl allow rules (macOS) or logs a not-implemented warning
// (Linux — Landlock has no network ABI).
//
// Filtering is IP-based, not hostname-based: if a CDN host rotates its IPs
// between sessions, the new IPs will not be in the allow set until the next
// shield launch.  This is a documented Tier 1.5 trade-off.
type NetworkConfig struct {
	// AllowedHosts is the list of hostnames whose resolved IPs are permitted
	// for outbound TCP connections.  The resolver runs at shield startup; DNS
	// (UDP 53) and loopback are always permitted regardless of this list.
	AllowedHosts []string `yaml:"allowed_hosts"`
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

	Grants []SecretGrant `yaml:"grants"`
}

type SecretGrant struct {
	Name  string `yaml:"name"`
	Scope string `yaml:"scope"`
	TTL   string `yaml:"ttl"`
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
			AllowedHosts: []string{
				"api.github.com",
				"raw.githubusercontent.com",
				"codeload.github.com",
				"registry.npmjs.org",
				"pypi.org",
				"files.pythonhosted.org",
				"crates.io",
				"proxy.golang.org",
				"sum.golang.org",
				"deno.land",
				// agentjail anonymous telemetry backend (see docs/TELEMETRY.md); users may remove this.
				"us.i.posthog.com",
			},
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

	// Network.AllowedHosts
	if len(overlay.Network.AllowedHosts) > 0 {
		result.Network.AllowedHosts = append([]string(nil), overlay.Network.AllowedHosts...)
	} else {
		result.Network.AllowedHosts = append([]string(nil), base.Network.AllowedHosts...)
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

	return result
}

// LoadOrDefault loads and merges a PolicyConfig from path over Default().
// If the file does not exist, Default() is returned with no error.
// If the file exists but cannot be parsed, the error is returned.
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
		"network": map[string]interface{}{
			"allowed_hosts": sliceOrEmpty(c.Network.AllowedHosts),
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
