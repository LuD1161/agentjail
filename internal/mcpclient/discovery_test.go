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

	// The exact set of servers is environment-dependent, so assert the shape
	// of each discovered entry rather than requiring a specific server.
	for _, e := range entries {
		if e.Name == "" {
			t.Error("discovered server has empty Name")
		}
		if e.Source == "" {
			t.Errorf("server %q has empty Source", e.Name)
		}
		if e.Config.Type == "" {
			t.Errorf("server %q has empty Type", e.Name)
		}
		// A stdio server must carry a command; an http/sse server a URL.
		switch e.Config.Type {
		case "stdio":
			if e.Config.Command == "" {
				t.Errorf("stdio server %q has empty Command", e.Name)
			}
		case "http", "sse":
			if e.Config.URL == "" {
				t.Errorf("%s server %q has empty URL", e.Config.Type, e.Name)
			}
		}
	}
}
