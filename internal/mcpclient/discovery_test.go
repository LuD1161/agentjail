package mcpclient

import (
	"os"
	"testing"
)

func TestDiscoverServersWithConfig(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	entries := DiscoverServersWithConfig(home)
	if len(entries) == 0 {
		t.Skip("no MCP servers configured on this machine")
	}

	for _, e := range entries {
		t.Logf("server=%q source=%q type=%q command=%q url=%q",
			e.Name, e.Source, e.Config.Type, e.Config.Command, e.Config.URL)
	}

	// Check that fff is discovered (known to be in ~/.claude.json).
	found := false
	for _, e := range entries {
		if e.Name == "fff" {
			found = true
			if e.Source != "claude" {
				t.Errorf("fff source = %q, want 'claude'", e.Source)
			}
			if e.Config.Type != "stdio" {
				t.Errorf("fff type = %q, want 'stdio'", e.Config.Type)
			}
			if e.Config.Command == "" {
				t.Error("fff command is empty")
			}
		}
	}
	if !found {
		t.Error("expected to find 'fff' server in discovery results")
	}
}
