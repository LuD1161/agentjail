package config

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// ---------------------------------------------------------------------------
// Load / decode
// ---------------------------------------------------------------------------

func TestLoadValidConfig(t *testing.T) {
	src := `
mcp:
  allowed:
    - "filesystem"
    - "github*"
  blocked:
    - "*stripe*"
file:
  extra_deny:
    - "/tmp/sensitive"
  extra_allow:
    - "/home/user/project"
commands:
  extra_block:
    - "curl.*bash"
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.MCP.Allowed) != 2 {
		t.Errorf("expected 2 allowed MCP entries, got %d", len(cfg.MCP.Allowed))
	}
	if cfg.MCP.Allowed[0] != "filesystem" {
		t.Errorf("expected first allowed = filesystem, got %q", cfg.MCP.Allowed[0])
	}
	if len(cfg.MCP.Blocked) != 1 {
		t.Errorf("expected 1 blocked MCP entry, got %d", len(cfg.MCP.Blocked))
	}
	if len(cfg.File.ExtraDeny) != 1 {
		t.Errorf("expected 1 extra_deny entry, got %d", len(cfg.File.ExtraDeny))
	}
	if len(cfg.File.ExtraAllow) != 1 {
		t.Errorf("expected 1 extra_allow entry, got %d", len(cfg.File.ExtraAllow))
	}
	if len(cfg.Commands.ExtraBlock) != 1 {
		t.Errorf("expected 1 extra_block entry, got %d", len(cfg.Commands.ExtraBlock))
	}
}

func TestLoadMCPServersConfig(t *testing.T) {
	src := `
mcp:
  allowed:
    - "filesystem"
    - "fetch"
  blocked: []
  servers:
    filesystem:
      allowed_tools:
        - "read_file"
        - "list_directory"
    fetch:
      allowed_tools:
        - "fetch"
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.MCP.Servers) != 2 {
		t.Errorf("expected 2 server entries, got %d", len(cfg.MCP.Servers))
	}
	fsSrv, ok := cfg.MCP.Servers["filesystem"]
	if !ok {
		t.Fatal("expected 'filesystem' server config to be present")
	}
	if len(fsSrv.AllowedTools) != 2 {
		t.Errorf("expected 2 filesystem allowed_tools, got %d", len(fsSrv.AllowedTools))
	}
	if fsSrv.AllowedTools[0] != "read_file" {
		t.Errorf("expected first filesystem tool = read_file, got %q", fsSrv.AllowedTools[0])
	}
	fetchSrv, ok := cfg.MCP.Servers["fetch"]
	if !ok {
		t.Fatal("expected 'fetch' server config to be present")
	}
	if len(fetchSrv.AllowedTools) != 1 || fetchSrv.AllowedTools[0] != "fetch" {
		t.Errorf("unexpected fetch allowed_tools: %v", fetchSrv.AllowedTools)
	}
}

func TestLoadMCPServersAbsent(t *testing.T) {
	// When servers key is absent, Servers should be nil (or empty map) — back-compat.
	src := `
mcp:
  allowed:
    - "filesystem"
  blocked: []
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Servers absent in YAML: decoded as nil map, which is fine.
	if len(cfg.MCP.Servers) != 0 {
		t.Errorf("expected empty Servers map, got %v", cfg.MCP.Servers)
	}
}

func TestLoadMCPServersEmptyToolList(t *testing.T) {
	// A server with an empty allowed_tools list means all tools are permitted.
	src := `
mcp:
  allowed:
    - "filesystem"
  blocked: []
  servers:
    filesystem:
      allowed_tools: []
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fsSrv, ok := cfg.MCP.Servers["filesystem"]
	if !ok {
		t.Fatal("expected 'filesystem' server config")
	}
	if len(fsSrv.AllowedTools) != 0 {
		t.Errorf("expected empty allowed_tools, got %v", fsSrv.AllowedTools)
	}
}

func TestDefaultServersIsNonNilEmptyMap(t *testing.T) {
	cfg := Default()
	if cfg.MCP.Servers == nil {
		t.Error("Default().MCP.Servers should be a non-nil empty map, not nil")
	}
	if len(cfg.MCP.Servers) != 0 {
		t.Errorf("Default().MCP.Servers should be empty, got %v", cfg.MCP.Servers)
	}
}

func TestLoadEmptyConfig(t *testing.T) {
	// Empty file is valid; produces a zero-value PolicyConfig.
	cfg, err := decode(strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty file should not return error, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil cfg for empty input")
	}
}

func TestLoadCommentOnlyConfig(t *testing.T) {
	src := `# just a comment\n# another comment\n`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("comment-only file should not return error, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil cfg for comment-only input")
	}
}

func TestLoadUnknownFieldRejected(t *testing.T) {
	src := `
mcp:
  allowed: []
unknown_top_level_key: true
`
	_, err := decode(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected an error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown") && !strings.Contains(err.Error(), "field") {
		t.Errorf("error message should mention unknown field, got: %v", err)
	}
}

func TestLoadUnknownNestedFieldRejected(t *testing.T) {
	src := `
mcp:
  allowed: []
  unknown_nested: "oops"
`
	_, err := decode(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected an error for unknown nested field, got nil")
	}
}

// ---------------------------------------------------------------------------
// Default()
// ---------------------------------------------------------------------------

func TestDefaultValues(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.MCP.Allowed == nil {
		t.Error("MCP.Allowed should be non-nil empty slice, not nil")
	}
	if len(cfg.MCP.Allowed) != 0 {
		t.Errorf("expected MCP.Allowed empty, got %v", cfg.MCP.Allowed)
	}
	expectedBlocked := []string{"*stripe*", "*payment*", "*billing*", "*twilio*", "*sendgrid*"}
	if !reflect.DeepEqual(cfg.MCP.Blocked, expectedBlocked) {
		t.Errorf("MCP.Blocked mismatch: got %v, want %v", cfg.MCP.Blocked, expectedBlocked)
	}
	if cfg.File.ExtraDeny == nil || len(cfg.File.ExtraDeny) != 0 {
		t.Errorf("expected File.ExtraDeny = [], got %v", cfg.File.ExtraDeny)
	}
	if cfg.File.ExtraAllow == nil || len(cfg.File.ExtraAllow) != 0 {
		t.Errorf("expected File.ExtraAllow = [], got %v", cfg.File.ExtraAllow)
	}
	if cfg.Commands.ExtraBlock == nil || len(cfg.Commands.ExtraBlock) != 0 {
		t.Errorf("expected Commands.ExtraBlock = [], got %v", cfg.Commands.ExtraBlock)
	}
}

func TestDefaultNetworkAllowedHostsIncludesTelemetry(t *testing.T) {
	cfg := Default()
	const telemetryHost = "us.i.posthog.com"
	for _, h := range cfg.Network.AllowedHosts {
		if h == telemetryHost {
			return
		}
	}
	t.Errorf("Default().Network.AllowedHosts does not contain %q (agentjail anonymous telemetry backend); got %v",
		telemetryHost, cfg.Network.AllowedHosts)
}

// TestDefaultWebBlockedIsEmpty verifies WebFetch is unrestricted out of the box
// (no hosts blocked) and the slice is non-nil so Rego sees [] not null.
func TestDefaultWebBlockedIsEmpty(t *testing.T) {
	cfg := Default()
	if cfg.Web.Blocked == nil || len(cfg.Web.Blocked) != 0 {
		t.Errorf("expected Web.Blocked = [] (non-nil empty), got %#v", cfg.Web.Blocked)
	}
}

// TestMergeWebBlockedOverlay verifies a policy.yaml web.blocked overlay replaces
// the (empty) default, and that ToOPAData projects it under web.blocked.
func TestMergeWebBlockedOverlay(t *testing.T) {
	overlay := &PolicyConfig{Web: WebConfig{Blocked: []string{"*tracking*", "169.254.*"}}}
	merged := Merge(Default(), overlay)
	if !reflect.DeepEqual(merged.Web.Blocked, []string{"*tracking*", "169.254.*"}) {
		t.Fatalf("merged Web.Blocked = %v", merged.Web.Blocked)
	}

	data := merged.ToOPAData()
	web, ok := data["web"].(map[string]interface{})
	if !ok {
		t.Fatalf("ToOPAData missing web object: %#v", data["web"])
	}
	if !reflect.DeepEqual(web["blocked"], []string{"*tracking*", "169.254.*"}) {
		t.Fatalf("ToOPAData web.blocked = %#v", web["blocked"])
	}

	// An empty overlay keeps the default (empty) — and never projects nil.
	keep := Merge(Default(), &PolicyConfig{})
	kdata := keep.ToOPAData()["web"].(map[string]interface{})
	if kdata["blocked"] == nil {
		t.Fatal("ToOPAData web.blocked must be [] not nil")
	}
}

// ---------------------------------------------------------------------------
// Validate()
// ---------------------------------------------------------------------------

func TestValidateEmptyAllowedWarns(t *testing.T) {
	cfg := &PolicyConfig{
		MCP: MCPConfig{
			Allowed: []string{},
			Blocked: []string{},
		},
	}
	warns := Validate(cfg)
	if len(warns) == 0 {
		t.Fatal("expected at least one warning for empty mcp.allowed, got none")
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "mcp.allowed is empty") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about empty mcp.allowed, got: %v", warns)
	}
}

func TestValidateNonEmptyAllowedNoWarn(t *testing.T) {
	cfg := &PolicyConfig{
		MCP: MCPConfig{
			Allowed: []string{"filesystem"},
			Blocked: []string{},
		},
	}
	warns := Validate(cfg)
	for _, w := range warns {
		if strings.Contains(w, "mcp.allowed is empty") {
			t.Errorf("unexpected warning about empty mcp.allowed: %v", warns)
		}
	}
}

func TestValidateNilConfig(t *testing.T) {
	warns := Validate(nil)
	if len(warns) == 0 {
		t.Fatal("expected a warning for nil config")
	}
}

// ---------------------------------------------------------------------------
// Round-trip: marshal Default() → unmarshal → deep-equal
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	orig := Default()

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(orig); err != nil {
		t.Fatalf("marshal Default() failed: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close encoder failed: %v", err)
	}

	decoded, err := decode(&buf)
	if err != nil {
		t.Fatalf("unmarshal round-trip failed: %v", err)
	}

	if !reflect.DeepEqual(orig, decoded) {
		t.Errorf("round-trip mismatch:\n  orig:    %+v\n  decoded: %+v", orig, decoded)
	}
}

// ---------------------------------------------------------------------------
// Merge()
// ---------------------------------------------------------------------------

// TestMergePartialYAML verifies that a partial overlay (only mcp.allowed)
// keeps the default blocked patterns (AC5.6).
func TestMergePartialYAML(t *testing.T) {
	// Only mcp.allowed provided — mcp.blocked should come from Default().
	overlay := &PolicyConfig{
		MCP: MCPConfig{
			Allowed: []string{"foo"},
		},
	}
	result := Merge(Default(), overlay)

	// overlay.allowed wins
	if len(result.MCP.Allowed) != 1 || result.MCP.Allowed[0] != "foo" {
		t.Errorf("expected MCP.Allowed=[foo], got %v", result.MCP.Allowed)
	}
	// default blocked must be preserved (AC5.6)
	defaultBlocked := Default().MCP.Blocked
	if !reflect.DeepEqual(result.MCP.Blocked, defaultBlocked) {
		t.Errorf("expected default blocked=%v, got %v", defaultBlocked, result.MCP.Blocked)
	}
}

// TestMergeNilOverlay verifies that Merge(base, nil) returns a deep copy of base.
func TestMergeNilOverlay(t *testing.T) {
	base := Default()
	result := Merge(base, nil)
	if !reflect.DeepEqual(base.MCP.Blocked, result.MCP.Blocked) {
		t.Errorf("Merge with nil overlay changed blocked: %v vs %v", base.MCP.Blocked, result.MCP.Blocked)
	}
}

// TestMergeDoesNotMutateBase verifies that Merge never mutates its inputs.
func TestMergeDoesNotMutateBase(t *testing.T) {
	base := Default()
	origBlocked := append([]string(nil), base.MCP.Blocked...)
	overlay := &PolicyConfig{
		MCP: MCPConfig{
			Blocked: []string{"*evil*"},
		},
	}
	_ = Merge(base, overlay)
	if !reflect.DeepEqual(base.MCP.Blocked, origBlocked) {
		t.Errorf("Merge mutated base.MCP.Blocked: expected %v, got %v", origBlocked, base.MCP.Blocked)
	}
}

// TestMergeServersUnion verifies that Merge unions server configs.
func TestMergeServersUnion(t *testing.T) {
	base := &PolicyConfig{
		MCP: MCPConfig{
			Allowed:  []string{"fs"},
			Blocked:  []string{},
			Servers: map[string]MCPServerConfig{
				"fs": {AllowedTools: []string{"read_file"}},
			},
		},
	}
	overlay := &PolicyConfig{
		MCP: MCPConfig{
			Servers: map[string]MCPServerConfig{
				"fetch": {AllowedTools: []string{"fetch"}},
			},
		},
	}
	result := Merge(base, overlay)
	if _, ok := result.MCP.Servers["fs"]; !ok {
		t.Error("expected 'fs' server from base to be present in merged result")
	}
	if _, ok := result.MCP.Servers["fetch"]; !ok {
		t.Error("expected 'fetch' server from overlay to be present in merged result")
	}
}

// ---------------------------------------------------------------------------
// Save() and LoadOrDefault()
// ---------------------------------------------------------------------------

// TestSaveRoundTrip verifies that Save writes a valid YAML file and
// LoadOrDefault reads it back to an equivalent config.
func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"

	orig := Default()
	orig.MCP.Allowed = []string{"filesystem", "github"}

	if err := Save(orig, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadOrDefault(path)
	if err != nil {
		t.Fatalf("LoadOrDefault: %v", err)
	}

	if !reflect.DeepEqual(orig.MCP.Allowed, loaded.MCP.Allowed) {
		t.Errorf("MCP.Allowed mismatch after Save/Load: got %v want %v", loaded.MCP.Allowed, orig.MCP.Allowed)
	}
	if !reflect.DeepEqual(orig.MCP.Blocked, loaded.MCP.Blocked) {
		t.Errorf("MCP.Blocked mismatch after Save/Load: got %v want %v", loaded.MCP.Blocked, orig.MCP.Blocked)
	}
}

// TestSavePermissions verifies that Save creates the file with 0600.
func TestSavePermissions(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	if err := Save(Default(), path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("expected 0600, got %o", mode)
	}
}

// TestLoadOrDefaultMissingFile verifies that LoadOrDefault returns Default()
// when the file does not exist (no error).
func TestLoadOrDefaultMissingFile(t *testing.T) {
	cfg, err := LoadOrDefault("/nonexistent/path/policy.yaml")
	if err != nil {
		t.Fatalf("LoadOrDefault with missing file should not error, got: %v", err)
	}
	def := Default()
	if !reflect.DeepEqual(cfg.MCP.Blocked, def.MCP.Blocked) {
		t.Errorf("expected default blocked, got %v", cfg.MCP.Blocked)
	}
}

// ---------------------------------------------------------------------------
// ToOPAData()
// ---------------------------------------------------------------------------

// TestToOPADataShape verifies that ToOPAData produces the expected nested map.
func TestToOPADataShape(t *testing.T) {
	cfg := Default()
	cfg.MCP.Allowed = []string{"filesystem"}
	cfg.File.TempRoots = []string{"/tmp", "/private/tmp"}

	data := cfg.ToOPAData()

	mcp, ok := data["mcp"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data[mcp] to be map, got %T", data["mcp"])
	}
	allowed, ok := mcp["allowed"].([]string)
	if !ok {
		t.Fatalf("expected data.mcp.allowed to be []string, got %T", mcp["allowed"])
	}
	if len(allowed) != 1 || allowed[0] != "filesystem" {
		t.Errorf("expected allowed=[filesystem], got %v", allowed)
	}

	file, ok := data["file"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data[file] to be map, got %T", data["file"])
	}
	roots, ok := file["temp_roots"].([]string)
	if !ok {
		t.Fatalf("expected data.file.temp_roots to be []string, got %T", file["temp_roots"])
	}
	if len(roots) < 1 {
		t.Error("expected at least one temp_root")
	}
}

// TestTempRootsNotInYAML verifies that TempRoots is not serialised to YAML
// (yaml:"-" tag), so it does not appear in policy.yaml.
func TestTempRootsNotInYAML(t *testing.T) {
	cfg := Default()
	cfg.File.TempRoots = []string{"/tmp"}

	var buf bytes.Buffer
	if err := yaml.NewEncoder(&buf).Encode(cfg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	content := buf.String()
	if strings.Contains(content, "temp_roots") {
		t.Errorf("TempRoots should not appear in YAML, but got: %s", content)
	}
}

// ---------------------------------------------------------------------------
// DisabledRules validation
// ---------------------------------------------------------------------------

// TestDisabledRulesValidGlobs verifies that valid glob patterns are accepted.
func TestDisabledRulesValidGlobs(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{"exact_id", "file_policy/sensitive_credential"},
		{"single_star", "file_policy/*"},
		{"multi_glob", "command_policy/*"},
		{"library_star", "library/*"},
		{"exact_agentjail_self", "file_policy/agentjail_self"},
		{"resolver_star", "resolver/*"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			src := "disabled_rules:\n  - \"" + tc.pattern + "\"\n"
			cfg, err := decode(strings.NewReader(src))
			if err != nil {
				t.Errorf("pattern %q should be valid, got error: %v", tc.pattern, err)
			}
			if cfg == nil {
				t.Fatalf("expected non-nil cfg")
			}
			if len(cfg.DisabledRules) != 1 || cfg.DisabledRules[0] != tc.pattern {
				t.Errorf("expected DisabledRules=[%q], got %v", tc.pattern, cfg.DisabledRules)
			}
		})
	}
}

// TestDisabledRulesInvalidGlobRejected verifies that syntactically malformed
// glob patterns are rejected at load time (so a bad pattern can't silently
// cause a runtime error during evaluation).
//
// Note: path.Match validates syntax — an unclosed bracket like "[invalid" is
// rejected. Patterns like "[z-a]" (inverted range) are syntactically valid
// but match nothing; those pass validation because they don't cause OPA
// runtime errors.
func TestDisabledRulesInvalidGlobRejected(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{"unclosed_bracket", "file_policy/[invalid"},
		{"unclosed_bracket_eof", "[unclosed"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			src := "disabled_rules:\n  - \"" + tc.pattern + "\"\n"
			_, err := decode(strings.NewReader(src))
			if err == nil {
				t.Errorf("pattern %q should be rejected, but no error returned", tc.pattern)
			}
		})
	}
}

// TestDisabledRulesInToOPAData verifies that disabled_rules is included
// in ToOPAData() output under the correct key.
func TestDisabledRulesInToOPAData(t *testing.T) {
	cfg := Default()
	cfg.DisabledRules = []string{"file_policy/sensitive_credential", "command_policy/*"}

	data := cfg.ToOPAData()

	raw, ok := data["disabled_rules"]
	if !ok {
		t.Fatal("expected disabled_rules key in ToOPAData() output")
	}
	rules, ok := raw.([]string)
	if !ok {
		t.Fatalf("expected disabled_rules to be []string, got %T", raw)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 disabled_rules, got %d: %v", len(rules), rules)
	}
	if rules[0] != "file_policy/sensitive_credential" || rules[1] != "command_policy/*" {
		t.Errorf("disabled_rules mismatch: got %v", rules)
	}
}

// TestDisabledRulesEmptyInToOPAData verifies that nil DisabledRules is
// serialised as an empty slice (not null) in ToOPAData().
func TestDisabledRulesEmptyInToOPAData(t *testing.T) {
	cfg := Default()
	// DisabledRules is nil by default.
	data := cfg.ToOPAData()
	raw, ok := data["disabled_rules"]
	if !ok {
		t.Fatal("expected disabled_rules key in ToOPAData() output")
	}
	rules, ok := raw.([]string)
	if !ok {
		t.Fatalf("expected disabled_rules to be []string, got %T", raw)
	}
	if len(rules) != 0 {
		t.Errorf("expected empty disabled_rules, got %v", rules)
	}
}

// TestDisabledRulesMergeOverlayWins verifies that a non-empty overlay
// disabled_rules replaces the base value.
func TestDisabledRulesMergeOverlayWins(t *testing.T) {
	base := Default()
	base.DisabledRules = []string{"file_policy/sensitive_credential"}

	overlay := &PolicyConfig{
		DisabledRules: []string{"command_policy/no-sudo", "library/*"},
	}
	result := Merge(base, overlay)
	if len(result.DisabledRules) != 2 {
		t.Errorf("expected 2 disabled_rules from overlay, got %v", result.DisabledRules)
	}
	if result.DisabledRules[0] != "command_policy/no-sudo" {
		t.Errorf("expected overlay to win, got %v", result.DisabledRules)
	}
}

// TestDisabledRulesMergeEmptyOverlayKeepsBase verifies that an empty overlay
// disabled_rules keeps the base value (not "clear everything").
func TestDisabledRulesMergeEmptyOverlayKeepsBase(t *testing.T) {
	base := Default()
	base.DisabledRules = []string{"file_policy/sensitive_credential"}

	overlay := &PolicyConfig{} // empty DisabledRules
	result := Merge(base, overlay)
	if len(result.DisabledRules) != 1 || result.DisabledRules[0] != "file_policy/sensitive_credential" {
		t.Errorf("expected base disabled_rules preserved, got %v", result.DisabledRules)
	}
}

// TestDisabledRulesPartialYAMLKeepsDefaultBlocked verifies that a partial
// policy.yaml that sets disabled_rules keeps the default MCP.Blocked list.
func TestDisabledRulesPartialYAMLKeepsDefaultBlocked(t *testing.T) {
	src := `
disabled_rules:
  - "file_policy/sensitive_credential"
`
	overlay, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	result := Merge(Default(), overlay)
	if len(result.DisabledRules) != 1 {
		t.Errorf("expected 1 disabled_rule, got %v", result.DisabledRules)
	}
	// Default blocked patterns must be preserved (partial overlay semantics).
	defaultBlocked := Default().MCP.Blocked
	if !reflect.DeepEqual(result.MCP.Blocked, defaultBlocked) {
		t.Errorf("expected default MCP.Blocked=%v, got %v", defaultBlocked, result.MCP.Blocked)
	}
}
