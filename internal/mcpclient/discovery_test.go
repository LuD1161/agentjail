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

	entries := DiscoverServersWithConfig(home)
	if len(entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(entries))
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
}
