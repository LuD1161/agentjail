package mcpclient

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestListToolsStdioFFF is an integration test that connects to the local
// fff-mcp server. Skipped if the binary is not installed.
func TestListToolsStdioFFF(t *testing.T) {
	const fffBin = "/home/openclaw/.local/bin/fff-mcp"
	if _, err := os.Stat(fffBin); err != nil {
		t.Skipf("fff-mcp not installed at %s", fffBin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := MCPServerConfig{
		Name:    "fff",
		Type:    "stdio",
		Command: fffBin,
		Args:    []string{},
	}

	tools, err := ListTools(ctx, cfg)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(tools) == 0 {
		t.Fatal("expected at least one tool from fff-mcp, got 0")
	}

	// Check that known tools are present.
	found := make(map[string]bool)
	for _, tool := range tools {
		found[tool.Name] = true
		t.Logf("tool: %s - %s", tool.Name, tool.Description)
	}

	for _, want := range []string{"grep", "find_files", "multi_grep"} {
		if !found[want] {
			t.Errorf("expected tool %q not found", want)
		}
	}
}

// TestListAllToolsConcurrent tests the concurrent ListAllTools function.
func TestListAllToolsConcurrent(t *testing.T) {
	const fffBin = "/home/openclaw/.local/bin/fff-mcp"
	if _, err := os.Stat(fffBin); err != nil {
		t.Skipf("fff-mcp not installed at %s", fffBin)
	}

	// Reset cache for this test.
	cacheMu.Lock()
	cacheData = nil
	cacheStamp = time.Time{}
	cacheMu.Unlock()

	ctx := context.Background()
	servers := []MCPServerConfig{
		{
			Name:    "fff",
			Type:    "stdio",
			Command: fffBin,
		},
		{
			Name:    "nonexistent",
			Type:    "stdio",
			Command: "/usr/bin/this-does-not-exist-mcptest",
		},
	}

	results := ListAllTools(ctx, servers)

	if r, ok := results["fff"]; !ok {
		t.Fatal("expected fff in results")
	} else {
		if r.Status != "connected" {
			t.Errorf("fff status = %q, want 'connected'", r.Status)
		}
		if len(r.Tools) == 0 {
			t.Error("fff has 0 tools, expected some")
		}
	}

	if r, ok := results["nonexistent"]; !ok {
		t.Fatal("expected nonexistent in results")
	} else {
		if r.Status != "unreachable" {
			t.Errorf("nonexistent status = %q, want 'unreachable'", r.Status)
		}
	}
}
