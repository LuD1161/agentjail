// mcp_discovery_test.go — unit tests for MCP server discovery, filtering, and
// the discoverMCPSeedList helper.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- claudeGlobalMCPServers ------------------------------------------------

func TestClaudeGlobalMCPServers_ReadsKeys(t *testing.T) {
	home := t.TempDir()
	content := `{"mcpServers":{"claude-mem":{},"context7":{"command":"npx"}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write .claude.json: %v", err)
	}
	got := claudeGlobalMCPServers(home)
	want := map[string]bool{"claude-mem": true, "context7": true}
	if len(got) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(got), got)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected name %q", name)
		}
	}
}

func TestClaudeGlobalMCPServers_MissingFile(t *testing.T) {
	home := t.TempDir()
	got := claudeGlobalMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil/empty for missing file, got %v", got)
	}
}

func TestClaudeGlobalMCPServers_MalformedJSON(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := claudeGlobalMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil/empty for malformed JSON, got %v", got)
	}
}

func TestClaudeGlobalMCPServers_NoMCPServersKey(t *testing.T) {
	home := t.TempDir()
	content := `{"otherKey":"value"}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := claudeGlobalMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil/empty when mcpServers absent, got %v", got)
	}
}

// ---- cursorMCPServers ------------------------------------------------------

func TestCursorMCPServers_ReadsKeys(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `{"mcpServers":{"my-server":{},"another":{"type":"http"}}}`
	if err := os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := cursorMCPServers(home)
	want := map[string]bool{"my-server": true, "another": true}
	if len(got) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(got), got)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected name %q", name)
		}
	}
}

func TestCursorMCPServers_MissingFile(t *testing.T) {
	home := t.TempDir()
	got := cursorMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil/empty for missing file, got %v", got)
	}
}

// ---- codexMCPServers + parseCodexMCPSections --------------------------------

func TestParseCodexMCPSections_Basic(t *testing.T) {
	toml := `
[features]
hooks = true

[mcp_servers.foo]
command = "npx"
args = ["-y", "foo-mcp"]

[mcp_servers.bar-server]
command = "some-binary"
`
	got := parseCodexMCPSections([]byte(toml))
	want := map[string]bool{"foo": true, "bar-server": true}
	if len(got) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(got), got)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected name %q", name)
		}
	}
}

func TestParseCodexMCPSections_Empty(t *testing.T) {
	got := parseCodexMCPSections([]byte(""))
	if len(got) != 0 {
		t.Errorf("expected empty for blank toml, got %v", got)
	}
}

func TestParseCodexMCPSections_NoMCPSection(t *testing.T) {
	toml := `[features]\nhooks = true\n`
	got := parseCodexMCPSections([]byte(toml))
	if len(got) != 0 {
		t.Errorf("expected empty when no mcp_servers section, got %v", got)
	}
}

func TestParseCodexMCPSections_SubKeyIgnored(t *testing.T) {
	// [mcp_servers.foo.bar] should NOT be included (has a dot in the name part).
	toml := `
[mcp_servers.foo]
key = "val"

[mcp_servers.foo.bar]
key = "val"
`
	got := parseCodexMCPSections([]byte(toml))
	if len(got) != 1 || got[0] != "foo" {
		t.Errorf("expected only [foo], got %v", got)
	}
}

func TestCodexMCPServers_MissingFile(t *testing.T) {
	home := t.TempDir()
	got := codexMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil/empty for missing file, got %v", got)
	}
}

// ---- discoverInstalledMCPServers (AC2.1) ------------------------------------

// TestDiscoverInstalledMCPServers_MultiSource verifies AC2.1: given fixtures for
// Claude Code (claude-mem, context7) and Codex (foo), the result is
// [claude-mem, context7, foo] sorted and de-duplicated.
func TestDiscoverInstalledMCPServers_MultiSource(t *testing.T) {
	home := t.TempDir()

	// Claude Code: ~/.claude.json
	claudeJSON := `{"mcpServers":{"claude-mem":{},"context7":{}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(claudeJSON), 0o600); err != nil {
		t.Fatalf("write .claude.json: %v", err)
	}

	// Codex: ~/.codex/config.toml
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	codexTOML := "[mcp_servers.foo]\ncommand = \"npx\"\n"
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexTOML), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	got := discoverInstalledMCPServers(home)
	want := []string{"claude-mem", "context7", "foo"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, name := range got {
		if name != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, name, want[i])
		}
	}
}

func TestDiscoverInstalledMCPServers_Deduplication(t *testing.T) {
	home := t.TempDir()

	// Same name in Claude and Cursor.
	claudeJSON := `{"mcpServers":{"shared-server":{}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(claudeJSON), 0o600); err != nil {
		t.Fatalf("write .claude.json: %v", err)
	}

	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o700); err != nil {
		t.Fatalf("mkdir .cursor: %v", err)
	}
	cursorJSON := `{"mcpServers":{"shared-server":{}}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(cursorJSON), 0o600); err != nil {
		t.Fatalf("write mcp.json: %v", err)
	}

	got := discoverInstalledMCPServers(home)
	if len(got) != 1 || got[0] != "shared-server" {
		t.Errorf("expected de-dup to [shared-server], got %v", got)
	}
}

// ---- filterAndWarnMCPNames (AC2.2, AC2.7) -----------------------------------

// TestFilterAndWarnMCPNames_BlocklistExclusion verifies AC2.2: my-payment-bot
// is excluded by the *payment* pattern and a warning is printed.
func TestFilterAndWarnMCPNames_BlocklistExclusion(t *testing.T) {
	var warn bytes.Buffer
	blocked := []string{"*stripe*", "*payment*", "*billing*"}
	names := []string{"claude-mem", "my-payment-bot", "context7"}

	got := filterAndWarnMCPNames(names, blocked, &warn)

	// my-payment-bot should be excluded.
	for _, name := range got {
		if name == "my-payment-bot" {
			t.Errorf("my-payment-bot should have been filtered out")
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 safe names, got %d: %v", len(got), got)
	}
	if !strings.Contains(warn.String(), "my-payment-bot") {
		t.Errorf("expected warning mentioning my-payment-bot, got: %q", warn.String())
	}
}

// TestFilterAndWarnMCPNames_GlobMetaRejection verifies AC2.7: a name like
// foo*bar containing glob metacharacters is rejected with a warning.
func TestFilterAndWarnMCPNames_GlobMetaRejection(t *testing.T) {
	var warn bytes.Buffer
	names := []string{"safe-name", "foo*bar", "another[one]"}

	got := filterAndWarnMCPNames(names, nil, &warn)

	for _, name := range got {
		if name == "foo*bar" || name == "another[one]" {
			t.Errorf("glob-meta name %q should have been rejected", name)
		}
	}
	if len(got) != 1 || got[0] != "safe-name" {
		t.Errorf("expected only [safe-name], got %v", got)
	}
	if !strings.Contains(warn.String(), "foo*bar") {
		t.Errorf("expected warning about foo*bar, got: %q", warn.String())
	}
}

// ---- discoverMCPSeedList (integration) --------------------------------------

func TestDiscoverMCPSeedList_Empty(t *testing.T) {
	home := t.TempDir()
	var w bytes.Buffer
	got := discoverMCPSeedList(home, &w)
	if len(got) != 0 {
		t.Errorf("expected nil/empty when no MCP configs present, got %v", got)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output when no servers found, got: %q", w.String())
	}
}

func TestDiscoverMCPSeedList_PrintsSummary(t *testing.T) {
	home := t.TempDir()

	claudeJSON := `{"mcpServers":{"claude-mem":{},"context7":{}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(claudeJSON), 0o600); err != nil {
		t.Fatalf("write .claude.json: %v", err)
	}

	var w bytes.Buffer
	got := discoverMCPSeedList(home, &w)

	if len(got) != 2 {
		t.Fatalf("expected 2 seeded names, got %v", got)
	}
	// Q-B: summary must be printed.
	summary := w.String()
	if !strings.Contains(summary, "trusted") || !strings.Contains(summary, "2") {
		t.Errorf("expected summary with count, got: %q", summary)
	}
}

func TestDiscoverMCPSeedList_FilteredByBlocklist(t *testing.T) {
	home := t.TempDir()

	// Only my-payment-bot → should be filtered out.
	claudeJSON := `{"mcpServers":{"my-payment-bot":{}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(claudeJSON), 0o600); err != nil {
		t.Fatalf("write .claude.json: %v", err)
	}

	var w bytes.Buffer
	got := discoverMCPSeedList(home, &w)

	if len(got) != 0 {
		t.Errorf("expected empty after blocklist filter, got %v", got)
	}
	if !strings.Contains(w.String(), "my-payment-bot") {
		t.Errorf("expected warning about my-payment-bot, got: %q", w.String())
	}
}

// ---- glob safety helpers ---------------------------------------------------

func TestContainsGlobMeta(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"safe-name", false},
		{"claude-mem", false},
		{"foo*bar", true},
		{"foo?bar", true},
		{"foo[bar]", true},
		{"foo{bar}", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := containsGlobMeta(tc.s); got != tc.want {
			t.Errorf("containsGlobMeta(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	patterns := []string{"*stripe*", "*payment*", "*billing*"}
	cases := []struct {
		name string
		want bool
	}{
		{"my-stripe-server", true},
		{"payment-gateway", true},
		{"claude-mem", false},
		{"filesystem", false},
		{"my-billing-api", true},
	}
	for _, tc := range cases {
		if got := matchesAnyGlob(tc.name, patterns); got != tc.want {
			t.Errorf("matchesAnyGlob(%q, patterns) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---- pluginMCPServerKeys ----------------------------------------------------

func TestPluginMCPServerKeys_Wrapped(t *testing.T) {
	r := strings.NewReader(`{"mcpServers": {"posthog": {"type": "http", "url": "https://mcp.posthog.com"}}}`)
	got := pluginMCPServerKeys(r)
	if len(got) != 1 || got[0] != "posthog" {
		t.Errorf("expected [posthog], got %v", got)
	}
}

func TestPluginMCPServerKeys_Flat(t *testing.T) {
	r := strings.NewReader(`{"context7": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}}`)
	got := pluginMCPServerKeys(r)
	if len(got) != 1 || got[0] != "context7" {
		t.Errorf("expected [context7], got %v", got)
	}
}

func TestPluginMCPServerKeys_FlatFiltersMetadata(t *testing.T) {
	r := strings.NewReader(`{"version": "1.0", "$schema": "http://...", "my-server": {"command": "node", "args": ["server.js"]}}`)
	got := pluginMCPServerKeys(r)
	if len(got) != 1 || got[0] != "my-server" {
		t.Errorf("expected [my-server], got %v", got)
	}
}

func TestPluginMCPServerKeys_Empty(t *testing.T) {
	got := pluginMCPServerKeys(strings.NewReader(""))
	if len(got) != 0 {
		t.Errorf("expected nil for empty reader, got %v", got)
	}
}

func TestPluginMCPServerKeys_MalformedJSON(t *testing.T) {
	got := pluginMCPServerKeys(strings.NewReader("{bad"))
	if len(got) != 0 {
		t.Errorf("expected nil for malformed JSON, got %v", got)
	}
}

// ---- claudePluginMCPServers -------------------------------------------------

func TestClaudePluginMCPServers_HappyPath(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	posthogInstall := filepath.Join(home, "posthog-install")
	if err := os.MkdirAll(posthogInstall, 0o700); err != nil {
		t.Fatalf("mkdir posthog install: %v", err)
	}
	context7Install := filepath.Join(home, "context7-install")
	if err := os.MkdirAll(context7Install, 0o700); err != nil {
		t.Fatalf("mkdir context7 install: %v", err)
	}

	posthogMCP := `{"mcpServers": {"posthog": {"type": "http", "url": "https://mcp.posthog.com"}}}`
	if err := os.WriteFile(filepath.Join(posthogInstall, ".mcp.json"), []byte(posthogMCP), 0o600); err != nil {
		t.Fatalf("write posthog .mcp.json: %v", err)
	}
	context7MCP := `{"context7": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}}`
	if err := os.WriteFile(filepath.Join(context7Install, ".mcp.json"), []byte(context7MCP), 0o600); err != nil {
		t.Fatalf("write context7 .mcp.json: %v", err)
	}

	registry := `{"version": 1, "plugins": {"posthog@claude-plugins-official": [{"installPath": "` + posthogInstall + `"}], "context7@claude-plugins-official": [{"installPath": "` + context7Install + `"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	got := claudePluginMCPServers(home)
	want := []string{"plugin_context7_context7", "plugin_posthog_posthog"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, name := range got {
		if name != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, name, want[i])
		}
	}
}

func TestClaudePluginMCPServers_MultiEntry(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	// First entry has no .mcp.json
	firstInstall := filepath.Join(home, "first-install")
	if err := os.MkdirAll(firstInstall, 0o700); err != nil {
		t.Fatalf("mkdir first install: %v", err)
	}

	// Second entry has .mcp.json
	secondInstall := filepath.Join(home, "second-install")
	if err := os.MkdirAll(secondInstall, 0o700); err != nil {
		t.Fatalf("mkdir second install: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secondInstall, ".mcp.json"), []byte(`{"mcpServers": {"my-tool": {}}}`), 0o600); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	registry := `{"version": 1, "plugins": {"myplugin@org": [{"installPath": "` + firstInstall + `"}, {"installPath": "` + secondInstall + `"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	got := claudePluginMCPServers(home)
	if len(got) != 1 || got[0] != "plugin_myplugin_my-tool" {
		t.Errorf("expected [plugin_myplugin_my-tool], got %v", got)
	}
}

func TestClaudePluginMCPServers_MalformedKey(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	install := filepath.Join(home, "install")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatalf("mkdir install: %v", err)
	}
	if err := os.WriteFile(filepath.Join(install, ".mcp.json"), []byte(`{"mcpServers": {"tool": {}}}`), 0o600); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	// Registry key without @
	registry := `{"version": 1, "plugins": {"no-at-sign": [{"installPath": "` + install + `"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	got := claudePluginMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil for malformed key, got %v", got)
	}
}

func TestClaudePluginMCPServers_MissingFile(t *testing.T) {
	home := t.TempDir()
	got := claudePluginMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil for missing registry, got %v", got)
	}
}

func TestClaudePluginMCPServers_RelativePath(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	// Entry with a relative installPath — should be skipped for security
	registry := `{"version": 1, "plugins": {"myplugin@org": [{"installPath": "relative/path"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	got := claudePluginMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected nil for relative path, got %v", got)
	}
}

func TestClaudePluginMCPServers_MissingMCPJSON(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	install := filepath.Join(home, "install")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatalf("mkdir install: %v", err)
	}
	// No .mcp.json written

	registry := `{"version": 1, "plugins": {"myplugin@org": [{"installPath": "` + install + `"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	got := claudePluginMCPServers(home)
	if len(got) != 0 {
		t.Errorf("expected empty when no .mcp.json in installPath, got %v", got)
	}
}

func TestDiscoverMCPSeedList_PluginBlocklisted(t *testing.T) {
	home := t.TempDir()
	pluginsDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatalf("mkdir plugins: %v", err)
	}

	install := filepath.Join(home, "stripe-install")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatalf("mkdir install: %v", err)
	}
	if err := os.WriteFile(filepath.Join(install, ".mcp.json"), []byte(`{"mcpServers": {"stripe": {}}}`), 0o600); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	registry := `{"version": 1, "plugins": {"stripe-tools@some-org": [{"installPath": "` + install + `"}]}}`
	if err := os.WriteFile(filepath.Join(pluginsDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatalf("write installed_plugins.json: %v", err)
	}

	var w bytes.Buffer
	got := discoverMCPSeedList(home, &w)

	for _, name := range got {
		if strings.Contains(name, "stripe") {
			t.Errorf("stripe server %q should have been filtered by blocklist", name)
		}
	}
	if !strings.Contains(w.String(), "stripe") {
		t.Errorf("expected warning mentioning stripe, got: %q", w.String())
	}
}
