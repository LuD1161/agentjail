package mcpclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverServersWithConfig(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{
  "mcpServers": {"fixture-stdio": {"command": "fixture-command"}}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cursor 2026.07.23 remote-server shape, verified 2026-08-13.
	// https://docs.cursor.com/context/model-context-protocol
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{
  "mcpServers": {"fixture-http": {"url": "https://example.invalid/mcp"}}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(`
[mcp_servers.fixture-codex]
command = "uvx"
args = ["context7"]
env = { SAFE_MODE = "1" }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := DiscoverServersWithConfig(home)
	if len(entries) != 3 {
		t.Fatalf("entries=%d, want 3", len(entries))
	}

	byName := make(map[string]MCPServerEntry, len(entries))
	for _, entry := range entries {
		byName[entry.Name] = entry
	}
	stdio := byName["fixture-stdio"]
	if stdio.Source != "claude" || stdio.Config.Type != "stdio" || stdio.Config.Command != "fixture-command" {
		t.Fatalf("stdio entry = %#v", stdio)
	}
	http := byName["fixture-http"]
	if http.Source != "cursor" || http.Config.Type != "http" || http.Config.URL != "https://example.invalid/mcp" {
		t.Fatalf("http entry = %#v", http)
	}
	codex := byName["fixture-codex"]
	if codex.Source != "codex" || codex.Config.Type != "stdio" || codex.Config.Command != "uvx" || len(codex.Config.Args) != 1 {
		t.Fatalf("codex entry = %#v", codex)
	}
}

func TestCodexServersResolveDeclaredHTTPEnvironmentOnly(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_DISCOVERY_BEARER", "bearer-secret")
	t.Setenv("MCP_DISCOVERY_HEADER", "header-secret")
	config := `
[mcp_servers.remote]
url = "https://example.invalid/mcp"
bearer_token_env_var = "MCP_DISCOVERY_BEARER"
env_http_headers = { "X-Workspace" = "MCP_DISCOVERY_HEADER" }

[mcp_servers.disabled]
command = "should-not-run"
enabled = false
`
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := codexServers(home)
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if got := entries[0].Config.Headers["Authorization"]; got != "Bearer bearer-secret" {
		t.Fatalf("authorization header = %q", got)
	}
	if got := entries[0].Config.Headers["X-Workspace"]; got != "header-secret" {
		t.Fatalf("environment header = %q", got)
	}
}

func TestCodexServersRejectMalformedConfigWithoutPartialDiscovery(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(`[mcp_servers.linear
command = "secret-bearing-command"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if entries := codexServers(home); len(entries) != 0 {
		t.Fatalf("malformed config returned entries: %#v", entries)
	}
}
