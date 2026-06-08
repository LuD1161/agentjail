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
	MCP          MCPConfig     `yaml:"mcp"`
	File         FileConfig    `yaml:"file"`
	Commands     CommandConfig `yaml:"commands"`
	Network      NetworkConfig `yaml:"network"`
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

	// DisabledRules — overlay wins if non-empty, else keep base.
	// An empty overlay means "don't change the base" (not "clear all disabled rules").
	if len(overlay.DisabledRules) > 0 {
		result.DisabledRules = append([]string(nil), overlay.DisabledRules...)
	} else {
		result.DisabledRules = append([]string(nil), base.DisabledRules...)
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
//	  "network":  { "allowed_hosts": [...] }
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
		// disabled_rules is read by resolver.rego to suppress non-locked candidates.
		// Rego reads it as data.agentjail.config.disabled_rules.
		"disabled_rules": sliceOrEmpty(c.DisabledRules),
	}
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
