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

// TestDefaultNetworkAllowedHostsIncludesClaudeCode verifies that the
// essential Claude Code provider hosts reach the agent via
// EffectiveAllowedHosts(), even though they are no longer part of the raw
// (editable) Default().Network.AllowedHosts seed -- they now live in
// EssentialAllowedHosts and are merged in unconditionally.
func TestDefaultNetworkAllowedHostsIncludesClaudeCode(t *testing.T) {
	cfg := Default()
	required := []string{"api.anthropic.com", "platform.claude.com"}
	hosts := make(map[string]bool, len(cfg.Network.AllowedHosts))
	for _, h := range cfg.EffectiveAllowedHosts() {
		hosts[h] = true
	}
	for _, r := range required {
		if !hosts[r] {
			t.Errorf("Default().EffectiveAllowedHosts() missing %q (required for Claude Code connectivity)", r)
		}
	}
}

// TestDefaultAllowedHostsIsExtendedOnly verifies that Default().Network.AllowedHosts
// equals ExtendedDefaultAllowedHosts() exactly, and contains none of the
// essential hosts (which are merged separately via EffectiveAllowedHosts).
func TestDefaultAllowedHostsIsExtendedOnly(t *testing.T) {
	cfg := Default()
	extended := ExtendedDefaultAllowedHosts()
	if !reflect.DeepEqual(cfg.Network.AllowedHosts, extended) {
		t.Fatalf("Default().Network.AllowedHosts != ExtendedDefaultAllowedHosts()\ngot:  %v\nwant: %v", cfg.Network.AllowedHosts, extended)
	}
	essentials := EssentialAllowedHosts()
	extendedSet := make(map[string]bool, len(extended))
	for _, h := range extended {
		extendedSet[h] = true
	}
	for _, e := range essentials {
		if extendedSet[e] {
			t.Errorf("Default().Network.AllowedHosts (extended) must not contain essential host %q", e)
		}
	}
}

// TestEssentialAllowedHostsExactOnly verifies no essential host contains a
// wildcard -- the non-removable surface must be exact hostnames only.
func TestEssentialAllowedHostsExactOnly(t *testing.T) {
	for _, h := range EssentialAllowedHosts() {
		if strings.Contains(h, "*") {
			t.Errorf("EssentialAllowedHosts() contains a wildcard entry %q; essentials must be exact hosts only", h)
		}
	}
}

// TestAllowedHostsExcludeMetaProxyAndPayment verifies neither the essential
// nor extended default host lists contain meta-proxy MCP hosts (Composio,
// Zapier) or the Stripe payment MCP host -- these are deliberately excluded.
func TestAllowedHostsExcludeMetaProxyAndPayment(t *testing.T) {
	excluded := []string{"mcp.composio.dev", "mcp.zapier.com", "mcp.stripe.com"}
	all := append(append([]string{}, EssentialAllowedHosts()...), ExtendedDefaultAllowedHosts()...)
	for _, e := range excluded {
		for _, h := range all {
			if h == e {
				t.Errorf("essential/extended default hosts must not contain %q", e)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// EffectiveAllowedHosts()
// ---------------------------------------------------------------------------

// TestEffectiveAllowedHostsAlwaysIncludesEssentials verifies that
// EffectiveAllowedHosts() contains every essential host regardless of
// whether Network.AllowedHosts is nil, an explicit empty slice, or a custom
// user list -- and that a custom user host is additive, not a replacement.
func TestEffectiveAllowedHostsAlwaysIncludesEssentials(t *testing.T) {
	essentials := EssentialAllowedHosts()

	cases := []struct {
		name  string
		hosts []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"custom", []string{"my.corp.internal"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: tc.hosts}}
			effective := cfg.EffectiveAllowedHosts()
			effectiveSet := make(map[string]bool, len(effective))
			for _, h := range effective {
				effectiveSet[h] = true
			}
			for _, e := range essentials {
				if !effectiveSet[e] {
					t.Errorf("EffectiveAllowedHosts() (case %s) missing essential host %q; got %v", tc.name, e, effective)
				}
			}
			if tc.name == "custom" && !effectiveSet["my.corp.internal"] {
				t.Errorf("EffectiveAllowedHosts() (case custom) missing user host my.corp.internal; got %v", effective)
			}
		})
	}
}

// TestEffectiveAllowedHostsDedupedEssentialsFirst verifies dedupe and
// essentials-first ordering when the user list happens to overlap with an
// essential host.
func TestEffectiveAllowedHostsDedupedEssentialsFirst(t *testing.T) {
	cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"api.anthropic.com", "extra.example.com"}}}
	effective := cfg.EffectiveAllowedHosts()

	count := 0
	for _, h := range effective {
		if h == "api.anthropic.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected api.anthropic.com exactly once, got %d occurrences in %v", count, effective)
	}
	if effective[0] != EssentialAllowedHosts()[0] {
		t.Errorf("expected essentials first, got %v", effective)
	}
	found := false
	for _, h := range effective {
		if h == "extra.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected extra.example.com present, got %v", effective)
	}
}

// TestEffectiveAllowedHostsReturnsCopy verifies EffectiveAllowedHosts (and
// EssentialAllowedHosts / ExtendedDefaultAllowedHosts) return defensive
// copies: mutating a returned slice must not affect a subsequent call.
func TestEffectiveAllowedHostsReturnsCopy(t *testing.T) {
	cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"foo.example.com"}}}

	first := cfg.EffectiveAllowedHosts()
	first[0] = "tampered"
	second := cfg.EffectiveAllowedHosts()
	if second[0] == "tampered" {
		t.Fatalf("EffectiveAllowedHosts() shares backing storage across calls: %v", second)
	}

	e1 := EssentialAllowedHosts()
	e1[0] = "tampered"
	e2 := EssentialAllowedHosts()
	if e2[0] == "tampered" {
		t.Fatalf("EssentialAllowedHosts() shares backing storage across calls: %v", e2)
	}

	x1 := ExtendedDefaultAllowedHosts()
	x1[0] = "tampered"
	x2 := ExtendedDefaultAllowedHosts()
	if x2[0] == "tampered" {
		t.Fatalf("ExtendedDefaultAllowedHosts() shares backing storage across calls: %v", x2)
	}
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

	// Compare via YAML re-encode since reflect.DeepEqual fails on *bool
	// (two pointers to true with different addresses aren't DeepEqual).
	var origBuf, decodedBuf bytes.Buffer
	enc2 := yaml.NewEncoder(&origBuf)
	enc2.SetIndent(2)
	_ = enc2.Encode(orig)
	_ = enc2.Close()
	enc3 := yaml.NewEncoder(&decodedBuf)
	enc3.SetIndent(2)
	_ = enc3.Encode(decoded)
	_ = enc3.Close()
	if origBuf.String() != decodedBuf.String() {
		t.Errorf("round-trip mismatch:\n  orig YAML:\n%s\n  decoded YAML:\n%s", origBuf.String(), decodedBuf.String())
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

// TestMergeNetworkAllowedHostsNilVsEmpty verifies the nil-vs-empty merge
// semantics specific to Network.AllowedHosts: an omitted "network" section or
// omitted "allowed_hosts" key (decodes to nil) keeps the base extended
// defaults; an explicit "allowed_hosts: []" (a non-nil empty slice) replaces
// the base with an empty extended list; an explicit non-empty list replaces
// the base entirely. In every case EffectiveAllowedHosts() still contains the
// essentials, since Merge never touches those.
func TestMergeNetworkAllowedHostsNilVsEmpty(t *testing.T) {
	base := Default()

	// Omitted network section entirely -> overlay.Network.AllowedHosts is nil.
	omitted := Merge(base, &PolicyConfig{})
	if !reflect.DeepEqual(omitted.Network.AllowedHosts, base.Network.AllowedHosts) {
		t.Errorf("omitted network section: expected base extended hosts, got %v", omitted.Network.AllowedHosts)
	}

	// Explicit empty list -> overlay.Network.AllowedHosts is non-nil empty.
	explicitEmpty := Merge(base, &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{}}})
	if len(explicitEmpty.Network.AllowedHosts) != 0 {
		t.Errorf("explicit empty allowed_hosts: expected raw list to be empty, got %v", explicitEmpty.Network.AllowedHosts)
	}
	if effective := explicitEmpty.EffectiveAllowedHosts(); len(effective) != len(EssentialAllowedHosts()) {
		t.Errorf("explicit empty allowed_hosts: expected effective == essentials only, got %v", effective)
	}

	// Explicit non-empty list -> replaces base entirely.
	replaced := Merge(base, &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"my.corp.internal"}}})
	if !reflect.DeepEqual(replaced.Network.AllowedHosts, []string{"my.corp.internal"}) {
		t.Errorf("explicit non-empty allowed_hosts: expected [my.corp.internal], got %v", replaced.Network.AllowedHosts)
	}
	effective := replaced.EffectiveAllowedHosts()
	foundEssential, foundCustom := false, false
	for _, h := range effective {
		if h == "api.anthropic.com" {
			foundEssential = true
		}
		if h == "my.corp.internal" {
			foundCustom = true
		}
	}
	if !foundEssential || !foundCustom {
		t.Errorf("replaced allowed_hosts: expected effective to contain both essential and custom host, got %v", effective)
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
			Allowed: []string{"fs"},
			Blocked: []string{},
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

// TestToOPADataNetworkAllowedHostsIsEffective verifies that ToOPAData
// serializes the EFFECTIVE allowlist under network.allowed_hosts -- i.e. it
// includes the essential hosts even when the raw Network.AllowedHosts list
// omits them.
func TestToOPADataNetworkAllowedHostsIsEffective(t *testing.T) {
	cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"my.corp.internal"}}}
	data := cfg.ToOPAData()
	network, ok := data["network"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data[network] to be map, got %T", data["network"])
	}
	hosts, ok := network["allowed_hosts"].([]string)
	if !ok {
		t.Fatalf("expected data.network.allowed_hosts to be []string, got %T", network["allowed_hosts"])
	}
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	if !hostSet["api.anthropic.com"] {
		t.Errorf("ToOPAData network.allowed_hosts missing essential host api.anthropic.com; got %v", hosts)
	}
	if !hostSet["my.corp.internal"] {
		t.Errorf("ToOPAData network.allowed_hosts missing user host my.corp.internal; got %v", hosts)
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

// ---------------------------------------------------------------------------
// AWS per-account posture (ADR 0017 / P1.2)
// ---------------------------------------------------------------------------

// TestDefaultAWSPosture verifies the fail-safe default is prod with empty maps.
func TestDefaultAWSPosture(t *testing.T) {
	cfg := Default()
	if cfg.AWS.DefaultPosture != "prod" {
		t.Fatalf("Default AWS.DefaultPosture = %q, want %q", cfg.AWS.DefaultPosture, "prod")
	}
	if cfg.AWS.Accounts == nil {
		t.Fatal("Default AWS.Accounts must be a non-nil map")
	}
	if cfg.AWS.Resources == nil {
		t.Fatal("Default AWS.Resources must be a non-nil map")
	}
}

// TestLoadAWSPosture parses an aws section with account + resource postures.
func TestLoadAWSPosture(t *testing.T) {
	src := `
aws:
  default_posture: prod
  accounts:
    "123456789012":
      posture: sandbox
      allow_cud: true
    "987654321098":
      posture: locked
      read_only: true
  resources:
    "arn:aws:s3:::prod-*":
      posture: locked
      deny_delete: true
`
	overlay, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if overlay.AWS.DefaultPosture != "prod" {
		t.Errorf("default_posture = %q", overlay.AWS.DefaultPosture)
	}
	sandbox, ok := overlay.AWS.Accounts["123456789012"]
	if !ok {
		t.Fatal("missing account 123456789012")
	}
	if sandbox.Posture != "sandbox" || !sandbox.AllowCUD {
		t.Errorf("sandbox account = %+v", sandbox)
	}
	locked, ok := overlay.AWS.Accounts["987654321098"]
	if !ok {
		t.Fatal("missing account 987654321098")
	}
	if locked.Posture != "locked" || !locked.ReadOnly {
		t.Errorf("locked account = %+v", locked)
	}
	res, ok := overlay.AWS.Resources["arn:aws:s3:::prod-*"]
	if !ok {
		t.Fatal("missing resource override")
	}
	if res.Posture != "locked" || !res.DenyDelete {
		t.Errorf("resource override = %+v", res)
	}
}

// TestMergeAWSPosture verifies overlay default_posture wins and maps union.
func TestMergeAWSPosture(t *testing.T) {
	base := Default()
	overlay := &PolicyConfig{
		AWS: AWSConfig{
			DefaultPosture: "sandbox",
			Accounts: map[string]AWSAccount{
				"111": {Posture: "sandbox"},
			},
			Resources: map[string]AWSResource{
				"arn:aws:s3:::a-*": {Posture: "sandbox"},
			},
		},
	}
	merged := Merge(base, overlay)
	if merged.AWS.DefaultPosture != "sandbox" {
		t.Fatalf("merged default_posture = %q, want sandbox", merged.AWS.DefaultPosture)
	}
	if _, ok := merged.AWS.Accounts["111"]; !ok {
		t.Error("overlay account missing after merge")
	}
}

// TestMergeAWSPostureFailSafe verifies an empty overlay keeps prod.
func TestMergeAWSPostureFailSafe(t *testing.T) {
	merged := Merge(Default(), &PolicyConfig{})
	if merged.AWS.DefaultPosture != "prod" {
		t.Fatalf("merged default_posture = %q, want prod (fail-safe)", merged.AWS.DefaultPosture)
	}
}

// TestToOPADataAWS verifies the aws section is projected for Rego.
func TestToOPADataAWS(t *testing.T) {
	cfg := &PolicyConfig{
		AWS: AWSConfig{
			DefaultPosture: "prod",
			Accounts: map[string]AWSAccount{
				"123": {Posture: "sandbox", AllowCUD: true, DenyDelete: false, ReadOnly: false},
			},
			Resources: map[string]AWSResource{
				"arn:aws:s3:::prod-*": {Posture: "locked", DenyDelete: true},
			},
		},
	}
	data := cfg.ToOPAData()
	aws, ok := data["aws"].(map[string]interface{})
	if !ok {
		t.Fatalf("ToOPAData missing aws object: %#v", data["aws"])
	}
	if aws["default_posture"] != "prod" {
		t.Errorf("aws.default_posture = %#v", aws["default_posture"])
	}
	accounts, ok := aws["accounts"].(map[string]interface{})
	if !ok {
		t.Fatalf("aws.accounts not a map: %#v", aws["accounts"])
	}
	acct, ok := accounts["123"].(map[string]interface{})
	if !ok {
		t.Fatal("missing account 123 in ToOPAData")
	}
	if acct["posture"] != "sandbox" || acct["allow_cud"] != true {
		t.Errorf("account 123 = %#v", acct)
	}
	resources, ok := aws["resources"].(map[string]interface{})
	if !ok {
		t.Fatalf("aws.resources not a map: %#v", aws["resources"])
	}
	if _, ok := resources["arn:aws:s3:::prod-*"]; !ok {
		t.Error("missing resource override in ToOPAData")
	}
}

// TestToOPADataAWSEmpty verifies an empty AWS config still projects a valid
// aws object (no nil maps) so Rego sees {} not null.
func TestToOPADataAWSEmpty(t *testing.T) {
	data := Default().ToOPAData()
	aws, ok := data["aws"].(map[string]interface{})
	if !ok {
		t.Fatalf("ToOPAData missing aws object: %#v", data["aws"])
	}
	if aws["default_posture"] != "prod" {
		t.Errorf("default_posture = %#v, want prod", aws["default_posture"])
	}
	if accounts, ok := aws["accounts"].(map[string]interface{}); !ok || accounts == nil {
		t.Errorf("aws.accounts must be a non-nil map: %#v", aws["accounts"])
	}
	if resources, ok := aws["resources"].(map[string]interface{}); !ok || resources == nil {
		t.Errorf("aws.resources must be a non-nil map: %#v", aws["resources"])
	}
}

// ---------------------------------------------------------------------------
// MCPServerConfig.BlockedTools / AskTools
// ---------------------------------------------------------------------------

// TestLoadMCPServerBlockedAndAskTools verifies that blocked_tools and ask_tools
// round-trip through YAML decode correctly.
func TestLoadMCPServerBlockedAndAskTools(t *testing.T) {
	src := `
mcp:
  allowed:
    - "filesystem"
  blocked: []
  servers:
    filesystem:
      allowed_tools: ["read_file", "list_directory"]
      blocked_tools: ["delete_file"]
      ask_tools: ["write_file", "create_directory"]
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fs, ok := cfg.MCP.Servers["filesystem"]
	if !ok {
		t.Fatal("expected 'filesystem' server config to be present")
	}
	if len(fs.AllowedTools) != 2 {
		t.Errorf("expected 2 allowed_tools, got %d", len(fs.AllowedTools))
	}
	if len(fs.BlockedTools) != 1 || fs.BlockedTools[0] != "delete_file" {
		t.Errorf("expected blocked_tools=[delete_file], got %v", fs.BlockedTools)
	}
	if len(fs.AskTools) != 2 || fs.AskTools[0] != "write_file" || fs.AskTools[1] != "create_directory" {
		t.Errorf("expected ask_tools=[write_file, create_directory], got %v", fs.AskTools)
	}
}

// TestMCPServerBlockedAskToolsAbsent verifies that absent blocked_tools/ask_tools
// decode as nil slices (backwards compatible).
func TestMCPServerBlockedAskToolsAbsent(t *testing.T) {
	src := `
mcp:
  allowed:
    - "filesystem"
  blocked: []
  servers:
    filesystem:
      allowed_tools: ["read_file"]
`
	cfg, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fs := cfg.MCP.Servers["filesystem"]
	if len(fs.BlockedTools) != 0 {
		t.Errorf("expected empty BlockedTools, got %v", fs.BlockedTools)
	}
	if len(fs.AskTools) != 0 {
		t.Errorf("expected empty AskTools, got %v", fs.AskTools)
	}
}

// TestToOPADataMCPServerBlockedAskTools verifies that blocked_tools and ask_tools
// are projected into the OPA data document.
func TestToOPADataMCPServerBlockedAskTools(t *testing.T) {
	cfg := Default()
	cfg.MCP.Servers = map[string]MCPServerConfig{
		"filesystem": {
			AllowedTools: []string{"read_file"},
			BlockedTools: []string{"delete_file"},
			AskTools:     []string{"write_file"},
		},
	}

	data := cfg.ToOPAData()
	mcp, ok := data["mcp"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data[mcp] to be map, got %T", data["mcp"])
	}
	servers, ok := mcp["servers"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data.mcp.servers to be map, got %T", mcp["servers"])
	}
	fs, ok := servers["filesystem"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filesystem server config map, got %T", servers["filesystem"])
	}

	blocked, ok := fs["blocked_tools"].([]string)
	if !ok {
		t.Fatalf("expected blocked_tools to be []string, got %T", fs["blocked_tools"])
	}
	if len(blocked) != 1 || blocked[0] != "delete_file" {
		t.Errorf("expected blocked_tools=[delete_file], got %v", blocked)
	}

	ask, ok := fs["ask_tools"].([]string)
	if !ok {
		t.Fatalf("expected ask_tools to be []string, got %T", fs["ask_tools"])
	}
	if len(ask) != 1 || ask[0] != "write_file" {
		t.Errorf("expected ask_tools=[write_file], got %v", ask)
	}
}

// TestToOPADataMCPServerEmptyBlockedAskTools verifies that nil blocked_tools and
// ask_tools are serialised as empty slices (not null) in OPA data.
func TestToOPADataMCPServerEmptyBlockedAskTools(t *testing.T) {
	cfg := Default()
	cfg.MCP.Servers = map[string]MCPServerConfig{
		"filesystem": {
			AllowedTools: []string{"read_file"},
			// BlockedTools and AskTools are nil
		},
	}

	data := cfg.ToOPAData()
	mcp := data["mcp"].(map[string]interface{})
	servers := mcp["servers"].(map[string]interface{})
	fs := servers["filesystem"].(map[string]interface{})

	blocked, ok := fs["blocked_tools"].([]string)
	if !ok {
		t.Fatalf("expected blocked_tools to be []string, got %T", fs["blocked_tools"])
	}
	if len(blocked) != 0 {
		t.Errorf("expected empty blocked_tools, got %v", blocked)
	}

	ask, ok := fs["ask_tools"].([]string)
	if !ok {
		t.Fatalf("expected ask_tools to be []string, got %T", fs["ask_tools"])
	}
	if len(ask) != 0 {
		t.Errorf("expected empty ask_tools, got %v", ask)
	}
}

// TestMergeServersBlockedAskTools verifies that Merge unions server configs
// including the new BlockedTools and AskTools fields.
func TestMergeServersBlockedAskTools(t *testing.T) {
	base := &PolicyConfig{
		MCP: MCPConfig{
			Allowed: []string{"filesystem"},
			Blocked: []string{},
			Servers: map[string]MCPServerConfig{
				"filesystem": {
					AllowedTools: []string{"read_file"},
					BlockedTools: []string{"delete_file"},
					AskTools:     []string{"write_file"},
				},
			},
		},
	}
	overlay := &PolicyConfig{
		MCP: MCPConfig{
			Servers: map[string]MCPServerConfig{
				"filesystem": {
					AllowedTools: []string{"read_file", "write_file"},
					BlockedTools: []string{"rm_rf"},
					AskTools:     []string{"create_directory"},
				},
			},
		},
	}
	result := Merge(base, overlay)
	fs, ok := result.MCP.Servers["filesystem"]
	if !ok {
		t.Fatal("expected 'filesystem' in merged result")
	}
	// Overlay replaces the whole MCPServerConfig for a key.
	if len(fs.BlockedTools) != 1 || fs.BlockedTools[0] != "rm_rf" {
		t.Errorf("expected overlay blocked_tools=[rm_rf], got %v", fs.BlockedTools)
	}
	if len(fs.AskTools) != 1 || fs.AskTools[0] != "create_directory" {
		t.Errorf("expected overlay ask_tools=[create_directory], got %v", fs.AskTools)
	}
}

// TestMCPServerBlockedAskToolsYAMLRoundTrip verifies full YAML encode/decode
// round-trip with the new fields.
func TestMCPServerBlockedAskToolsYAMLRoundTrip(t *testing.T) {
	orig := Default()
	orig.MCP.Servers = map[string]MCPServerConfig{
		"filesystem": {
			AllowedTools: []string{"read_file"},
			BlockedTools: []string{"delete_file"},
			AskTools:     []string{"write_file"},
		},
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(orig); err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close encoder failed: %v", err)
	}

	decoded, err := decode(&buf)
	if err != nil {
		t.Fatalf("unmarshal round-trip failed: %v", err)
	}

	fs := decoded.MCP.Servers["filesystem"]
	if !reflect.DeepEqual(fs.AllowedTools, []string{"read_file"}) {
		t.Errorf("round-trip allowed_tools mismatch: %v", fs.AllowedTools)
	}
	if !reflect.DeepEqual(fs.BlockedTools, []string{"delete_file"}) {
		t.Errorf("round-trip blocked_tools mismatch: %v", fs.BlockedTools)
	}
	if !reflect.DeepEqual(fs.AskTools, []string{"write_file"}) {
		t.Errorf("round-trip ask_tools mismatch: %v", fs.AskTools)
	}
}

// ---------------------------------------------------------------------------
// HostedMCP registry / MCPDerivedAllowedHosts (ADR 0040)
// ---------------------------------------------------------------------------

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}

func TestMCPDerivedAllowedHostsTableDriven(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		blocked []string
		want    []string // hosts that MUST be present
		notWant []string // hosts that MUST NOT be present
	}{
		{
			name:    "linear-server allowed",
			allowed: []string{"linear-server"},
			want:    []string{"mcp.linear.app", "api.linear.app"},
		},
		{
			name:    "wildcard allowed, posthog blocked",
			allowed: []string{"*"},
			blocked: []string{"*posthog*"},
			want:    []string{"mcp.linear.app", "api.linear.app"},
			notWant: []string{"*.posthog.com"},
		},
		{
			name:    "plugin_* alias prefix",
			allowed: []string{"plugin_*"},
			want:    []string{"*.posthog.com", "mcp.context7.com"},
		},
		{
			name:    "linear* prefix matches linear",
			allowed: []string{"linear*"},
			want:    []string{"mcp.linear.app", "api.linear.app"},
		},
		{
			name:    "custom block excludes context7",
			allowed: []string{"*"},
			blocked: []string{"*context7*"},
			want:    []string{"mcp.linear.app"},
			notWant: []string{"mcp.context7.com"},
		},
		{
			name:    "wildcard allow, no blocked -> all registry hosts",
			allowed: []string{"*"},
			want:    HostedMCPAllowedHosts(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mcp := MCPConfig{Allowed: tc.allowed, Blocked: tc.blocked}
			got := MCPDerivedAllowedHosts(mcp)
			for _, w := range tc.want {
				if !containsHost(got, w) {
					t.Errorf("expected host %q present, got %v", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if containsHost(got, nw) {
					t.Errorf("expected host %q absent, got %v", nw, got)
				}
			}
		})
	}
}

// TestMCPDerivedAllowedHostsEmptyAllowed verifies an empty mcp.allowed
// derives no hosts (safe default -- deny all MCP, imply no hosts).
func TestMCPDerivedAllowedHostsEmptyAllowed(t *testing.T) {
	got := MCPDerivedAllowedHosts(MCPConfig{})
	if len(got) != 0 {
		t.Errorf("expected no derived hosts for empty mcp.allowed, got %v", got)
	}
}

// TestMCPDerivedAllowedHostsDedupStableOrder verifies dedup and registry-order
// stability when overlapping patterns match the same entry multiple times.
func TestMCPDerivedAllowedHostsDedupStableOrder(t *testing.T) {
	mcp := MCPConfig{Allowed: []string{"linear", "linear-server", "linear*"}}
	got := MCPDerivedAllowedHosts(mcp)
	if !reflect.DeepEqual(got, []string{"mcp.linear.app", "api.linear.app"}) {
		t.Errorf("expected deduped [mcp.linear.app api.linear.app], got %v", got)
	}
}

// TestMCPDerivedAllowedHostsBadPatternNoPanic verifies a malformed glob is
// treated defensively as "no match" rather than panicking (defense-in-depth;
// Load already rejects malformed mcp.allowed/mcp.blocked patterns).
func TestMCPDerivedAllowedHostsBadPatternNoPanic(t *testing.T) {
	mcp := MCPConfig{Allowed: []string{"[bad"}}
	got := MCPDerivedAllowedHosts(mcp)
	if len(got) != 0 {
		t.Errorf("expected no derived hosts for malformed pattern, got %v", got)
	}
}

// TestHostedMCPRegistryDefensiveCopy verifies HostedMCPRegistry and
// HostedMCPAllowedHosts return copies safe to mutate.
func TestHostedMCPRegistryDefensiveCopy(t *testing.T) {
	r1 := HostedMCPRegistry()
	r1[0].Name = "tampered"
	r1[0].Hosts[0] = "tampered"
	r2 := HostedMCPRegistry()
	if r2[0].Name == "tampered" || r2[0].Hosts[0] == "tampered" {
		t.Fatalf("HostedMCPRegistry() shares backing storage across calls: %+v", r2[0])
	}

	h1 := HostedMCPAllowedHosts()
	h1[0] = "tampered"
	h2 := HostedMCPAllowedHosts()
	if h2[0] == "tampered" {
		t.Fatalf("HostedMCPAllowedHosts() shares backing storage across calls: %v", h2)
	}
}

// TestExtendedDefaultHostedMCPSectionMatchesRegistry is the drift test: the
// "Hosted MCP servers" subset of ExtendedDefaultAllowedHosts() must equal
// HostedMCPAllowedHosts() exactly -- the hosts must live only in the
// registry, never duplicated as literals in ExtendedDefaultAllowedHosts.
func TestExtendedDefaultHostedMCPSectionMatchesRegistry(t *testing.T) {
	extended := ExtendedDefaultAllowedHosts()
	registryHosts := HostedMCPAllowedHosts()
	registrySet := make(map[string]bool, len(registryHosts))
	for _, h := range registryHosts {
		registrySet[h] = true
	}
	extendedSet := make(map[string]bool, len(extended))
	for _, h := range extended {
		extendedSet[h] = true
	}
	for _, h := range registryHosts {
		if !extendedSet[h] {
			t.Errorf("ExtendedDefaultAllowedHosts() missing registry host %q", h)
		}
	}
	// Every host that any registry entry's canonical name suggests it owns
	// (matched against registry Hosts values exactly, not by substring
	// heuristic) must come from the registry -- i.e. removing the registry
	// hosts from Extended and re-adding them must reproduce Extended
	// exactly, proving there is no second, stray copy of a registry host
	// literal sitting elsewhere in ExtendedDefaultAllowedHosts.
	rebuilt := make([]string, 0, len(extended))
	seenRebuilt := make(map[string]bool)
	for _, h := range extended {
		if registrySet[h] {
			continue // dropped; re-added exactly once below in registry order
		}
		if !seenRebuilt[h] {
			seenRebuilt[h] = true
			rebuilt = append(rebuilt, h)
		}
	}
	if len(rebuilt)+len(registryHosts) != len(extendedSet) {
		t.Errorf("ExtendedDefaultAllowedHosts() has %d unique hosts but only %d non-registry + %d registry hosts account for; suggests a duplicated hosted-MCP literal outside the registry",
			len(extendedSet), len(rebuilt), len(registryHosts))
	}
}

// ---------------------------------------------------------------------------
// EssentialAllowedHosts / EffectiveAllowedHosts: mcp-proxy.anthropic.com
// ---------------------------------------------------------------------------

// TestEssentialsIncludeMCPProxyAnthropic verifies mcp-proxy.anthropic.com is
// present in EffectiveAllowedHosts() even with a custom allowed_hosts list
// that omits it entirely.
func TestEssentialsIncludeMCPProxyAnthropic(t *testing.T) {
	found := false
	for _, h := range EssentialAllowedHosts() {
		if h == "mcp-proxy.anthropic.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("EssentialAllowedHosts() missing mcp-proxy.anthropic.com")
	}

	cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"github.com", "registry.npmjs.org"}}}
	effective := cfg.EffectiveAllowedHosts()
	if !containsHost(effective, "mcp-proxy.anthropic.com") {
		t.Errorf("EffectiveAllowedHosts() with a curated allowed_hosts omitting mcp-proxy.anthropic.com must still include it; got %v", effective)
	}
}

// TestEssentialsIncludeChatOpenAI verifies chat.openai.com (legacy
// OpenAI/Codex backend URL) is present in EssentialAllowedHosts() and
// therefore in EffectiveAllowedHosts() even with a custom allowed_hosts list
// that omits it entirely.
func TestEssentialsIncludeChatOpenAI(t *testing.T) {
	found := false
	for _, h := range EssentialAllowedHosts() {
		if h == "chat.openai.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("EssentialAllowedHosts() missing chat.openai.com")
	}

	cfg := &PolicyConfig{Network: NetworkConfig{AllowedHosts: []string{"github.com", "registry.npmjs.org"}}}
	effective := cfg.EffectiveAllowedHosts()
	if !containsHost(effective, "chat.openai.com") {
		t.Errorf("EffectiveAllowedHosts() with a curated allowed_hosts omitting chat.openai.com must still include it; got %v", effective)
	}
}

// TestEffectiveAllowedHostsEndToEndCuratedPlusMCP verifies the full three-tier
// merge: a curated (narrow) editable allowed_hosts list, combined with
// mcp.allowed for several hosted MCP servers, produces an effective set that
// includes the MCP-derived hosts even though they are absent from the raw
// editable list -- essentials first, then MCP-derived, then editable,
// deduped and order-stable.
func TestEffectiveAllowedHostsEndToEndCuratedPlusMCP(t *testing.T) {
	cfg := &PolicyConfig{
		Network: NetworkConfig{AllowedHosts: []string{"github.com", "registry.npmjs.org"}},
		MCP: MCPConfig{
			Allowed: []string{"linear-server", "plugin_context7_context7", "plugin_posthog_posthog"},
		},
	}
	effective := cfg.EffectiveAllowedHosts()

	for _, want := range []string{
		"mcp.linear.app", "mcp.context7.com", "*.posthog.com",
		"mcp-proxy.anthropic.com", "github.com", "registry.npmjs.org",
	} {
		if !containsHost(effective, want) {
			t.Errorf("expected %q in EffectiveAllowedHosts(), got %v", want, effective)
		}
	}

	// Order: essentials first.
	essentials := EssentialAllowedHosts()
	for i, e := range essentials {
		if effective[i] != e {
			t.Fatalf("expected essentials-first ordering at index %d: want %q got %q (full: %v)", i, e, effective[i], effective)
		}
	}

	// Dedup: no repeats.
	seen := make(map[string]int)
	for _, h := range effective {
		seen[h]++
	}
	for h, n := range seen {
		if n > 1 {
			t.Errorf("host %q appears %d times in EffectiveAllowedHosts(), want deduped", h, n)
		}
	}
}

// ---------------------------------------------------------------------------
// mcp.allowed / mcp.blocked glob validation at Load (ADR 0040 item 3)
// ---------------------------------------------------------------------------

func TestLoadRejectsMalformedMCPAllowedGlob(t *testing.T) {
	src := `
mcp:
  allowed:
    - "[bad"
`
	_, err := decode(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected error for malformed mcp.allowed glob, got nil")
	}
}

func TestLoadRejectsMalformedMCPBlockedGlob(t *testing.T) {
	src := `
mcp:
  blocked:
    - "[bad"
`
	_, err := decode(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected error for malformed mcp.blocked glob, got nil")
	}
}

func TestLoadAcceptsWellFormedMCPGlobs(t *testing.T) {
	src := `
mcp:
  allowed:
    - "linear*"
    - "plugin_*"
  blocked:
    - "*stripe*"
`
	_, err := decode(strings.NewReader(src))
	if err != nil {
		t.Fatalf("unexpected error for well-formed mcp globs: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fail-loud: absent vs. malformed policy file (ADR 0040 item 4)
// ---------------------------------------------------------------------------

// TestLoadOrDefaultAbsentFileYieldsDefaults verifies a genuinely missing file
// still yields Default() with a nil error (first-run behavior unchanged).
func TestLoadOrDefaultAbsentFileYieldsDefaults(t *testing.T) {
	dir := t.TempDir()
	missing := dir + "/does-not-exist.yaml"

	cfg, err := LoadOrDefault(missing)
	if err != nil {
		t.Fatalf("expected nil error for absent file, got %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("expected Default() for absent file, got %+v", cfg)
	}
}

// TestLoadOrDefaultMalformedPresentFileErrors verifies a PRESENT but
// unparseable file returns an error rather than silently falling back to
// Default() -- the fail-loud distinction the shield/netproxy launch paths
// depend on.
func TestLoadOrDefaultMalformedPresentFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	// A stray tab makes this invalid YAML.
	if err := os.WriteFile(path, []byte("mcp:\n\tallowed: [\"x\"]\n"), 0o600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}

	_, err := LoadOrDefault(path)
	if err == nil {
		t.Fatal("expected error for present-but-malformed policy file, got nil")
	}
}

// TestLoadOrDefaultPresentFileWithInvalidMCPGlobErrors verifies the same
// fail-loud behavior for a structurally valid YAML file that fails the new
// mcp.allowed glob validation.
func TestLoadOrDefaultPresentFileWithInvalidMCPGlobErrors(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	if err := os.WriteFile(path, []byte("mcp:\n  allowed:\n    - \"[bad\"\n"), 0o600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}

	_, err := LoadOrDefault(path)
	if err == nil {
		t.Fatal("expected error for present policy file with invalid mcp.allowed glob, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadPolicyForEnforcement (ADR 0041)
// ---------------------------------------------------------------------------

// TestLoadPolicyForEnforcementAbsentFile verifies an absent path yields
// Merge(Default(), &PolicyConfig{}) with a nil error.
func TestLoadPolicyForEnforcementAbsentFile(t *testing.T) {
	dir := t.TempDir()
	missing := dir + "/does-not-exist.yaml"

	cfg, err := LoadPolicyForEnforcement(missing)
	if err != nil {
		t.Fatalf("expected nil error for absent file, got %v", err)
	}
	want := Merge(Default(), &PolicyConfig{})
	if !reflect.DeepEqual(cfg.MCP.Blocked, want.MCP.Blocked) || !reflect.DeepEqual(cfg.Network.AllowedHosts, want.Network.AllowedHosts) {
		t.Fatalf("expected merged defaults for absent file, got %+v", cfg)
	}
}

// TestLoadPolicyForEnforcementMalformedFileErrors verifies a PRESENT but
// invalid-YAML file (a literal TAB-indented list) returns an error --
// fail-loud, never a silent fallback to defaults.
func TestLoadPolicyForEnforcementMalformedFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	if err := os.WriteFile(path, []byte("mcp:\n\tallowed: [\"x\"]\n"), 0o600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}

	cfg, err := LoadPolicyForEnforcement(path)
	if err == nil {
		t.Fatal("expected error for present-but-malformed policy file, got nil")
	}
	if cfg != nil {
		t.Errorf("expected nil *PolicyConfig on error, got %+v", cfg)
	}
}

// TestLoadPolicyForEnforcementValidFile verifies a present, valid file is
// merged over Default().
func TestLoadPolicyForEnforcementValidFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	src := "mcp:\n  allowed:\n    - \"linear-server\"\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}

	cfg, err := LoadPolicyForEnforcement(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.MCP.Allowed) != 1 || cfg.MCP.Allowed[0] != "linear-server" {
		t.Errorf("expected MCP.Allowed=[linear-server], got %v", cfg.MCP.Allowed)
	}
	// Merged over Default(): default blocked patterns preserved.
	if !reflect.DeepEqual(cfg.MCP.Blocked, Default().MCP.Blocked) {
		t.Errorf("expected default blocked preserved, got %v", cfg.MCP.Blocked)
	}
}

// ---------------------------------------------------------------------------
// HostPattern / ClassifyHost (ADR 0041)
// ---------------------------------------------------------------------------

func TestClassifyHost(t *testing.T) {
	cases := []struct {
		host         string
		wantWildcard bool
	}{
		{"*.claude.ai", true},
		{"*.posthog.com", true},
		{"*.huggingface.co", true},
		{"api.linear.app", false},
		{"api.anthropic.com", false},
		{"mcp.linear.app", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			hp := ClassifyHost(tc.host)
			if hp.Pattern != tc.host {
				t.Errorf("ClassifyHost(%q).Pattern = %q, want %q", tc.host, hp.Pattern, tc.host)
			}
			if hp.Wildcard != tc.wantWildcard {
				t.Errorf("ClassifyHost(%q).Wildcard = %v, want %v", tc.host, hp.Wildcard, tc.wantWildcard)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cursor CLI hosts (ADR 0041)
// ---------------------------------------------------------------------------

// TestExtendedDefaultIncludesCursorLoginHosts verifies cursor.com and
// www.cursor.com (Cursor CLI login/update flows) are present in the Cursor
// block of ExtendedDefaultAllowedHosts, alongside the existing exact
// *.cursor.sh API subdomains.
func TestExtendedDefaultIncludesCursorLoginHosts(t *testing.T) {
	extended := ExtendedDefaultAllowedHosts()
	for _, want := range []string{"cursor.com", "www.cursor.com", "api2.cursor.sh", "authenticate.cursor.sh"} {
		if !containsHost(extended, want) {
			t.Errorf("ExtendedDefaultAllowedHosts() missing Cursor host %q; got %v", want, extended)
		}
	}
	// Deliberately no broad *.cursor.sh wildcard.
	for _, h := range extended {
		if h == "*.cursor.sh" {
			t.Errorf("ExtendedDefaultAllowedHosts() must not contain a broad *.cursor.sh wildcard")
		}
	}
}

// ---------------------------------------------------------------------------
// DaemonUnreachable (ADR 0050) tests
// ---------------------------------------------------------------------------

// TestDefaultDaemonUnreachableIsDegraded pins the ADR 0074 default. It is safe
// precisely because degraded's offline denials are a subset of the locked rules
// OPA already enforces online, so nothing that works against a live daemon is
// newly refused when it dies.
func TestDefaultDaemonUnreachableIsDegraded(t *testing.T) {
	cfg := Default()
	if cfg.DaemonUnreachable != DaemonUnreachableDegraded {
		t.Errorf("Default().DaemonUnreachable = %q, want %q", cfg.DaemonUnreachable, DaemonUnreachableDegraded)
	}
}

// TestMergeDaemonUnreachableUnsetIsDegraded covers the second of the three
// places an unset level resolves (the third is the daemon's sidecar writer):
// two configs that both omit the key must not silently fall back to fail-open.
func TestMergeDaemonUnreachableUnsetIsDegraded(t *testing.T) {
	got := Merge(&PolicyConfig{}, &PolicyConfig{}).DaemonUnreachable
	if got != DaemonUnreachableDegraded {
		t.Errorf("Merge with neither side set = %q, want %q", got, DaemonUnreachableDegraded)
	}
}

// TestMergeDaemonUnreachableExplicitAllowSurvives: opting back into fail-open
// must stay possible — the default moved, the choice did not disappear.
func TestMergeDaemonUnreachableExplicitAllowSurvives(t *testing.T) {
	got := Merge(&PolicyConfig{DaemonUnreachable: DaemonUnreachableAllow}, &PolicyConfig{}).DaemonUnreachable
	if got != DaemonUnreachableAllow {
		t.Errorf("explicit allow in base = %q, want %q", got, DaemonUnreachableAllow)
	}
}

func TestLoadDaemonUnreachableEmptyIsValid(t *testing.T) {
	cfg, err := decode(strings.NewReader(`mcp:
  allowed: ["*"]
`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.DaemonUnreachable != "" {
		t.Errorf("expected empty DaemonUnreachable when unset, got %q", cfg.DaemonUnreachable)
	}
}

func TestLoadDaemonUnreachableValidValues(t *testing.T) {
	for _, level := range []DaemonUnreachableLevel{DaemonUnreachableAllow, DaemonUnreachableDegraded, DaemonUnreachableDeny} {
		yamlSrc := "daemon_unreachable: " + string(level) + "\n"
		cfg, err := decode(strings.NewReader(yamlSrc))
		if err != nil {
			t.Fatalf("decode(%q): unexpected error: %v", level, err)
		}
		if cfg.DaemonUnreachable != level {
			t.Errorf("decode(%q): got %q", level, cfg.DaemonUnreachable)
		}
	}
}

func TestLoadDaemonUnreachableInvalidValueRejected(t *testing.T) {
	_, err := decode(strings.NewReader("daemon_unreachable: bogus\n"))
	if err == nil {
		t.Fatal("expected error for invalid daemon_unreachable value, got nil")
	}
	if !strings.Contains(err.Error(), "daemon_unreachable") {
		t.Errorf("error should mention daemon_unreachable, got: %v", err)
	}
}

func TestMergeDaemonUnreachableOverlayWinsWhenSet(t *testing.T) {
	base := Default()
	base.DaemonUnreachable = DaemonUnreachableDegraded
	overlay := &PolicyConfig{DaemonUnreachable: DaemonUnreachableDeny}
	merged := Merge(base, overlay)
	if merged.DaemonUnreachable != DaemonUnreachableDeny {
		t.Errorf("expected overlay to win, got %q", merged.DaemonUnreachable)
	}
}

func TestMergeDaemonUnreachableKeepsBaseWhenOverlayEmpty(t *testing.T) {
	base := Default()
	base.DaemonUnreachable = DaemonUnreachableDegraded
	merged := Merge(base, &PolicyConfig{})
	if merged.DaemonUnreachable != DaemonUnreachableDegraded {
		t.Errorf("expected base to be kept, got %q", merged.DaemonUnreachable)
	}
}
