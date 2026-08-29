package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/internal/agentguidance"
	"github.com/LuD1161/agentjail/internal/agents"
)

func TestReconcileInstalledAgentGuidanceOnlyTouchesInstalledAgents(t *testing.T) {
	home := t.TempDir()
	env := buildAgentsEnv(home)
	if err := (agents.ClaudeCode{}).Install(env); err != nil {
		t.Fatal(err)
	}
	claudePath := filepath.Join(home, ".claude", "CLAUDE.md")
	stale := agentguidance.MarkerStart + "\nstale\n" + agentguidance.MarkerEnd + "\n"
	if err := os.WriteFile(claudePath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := reconcileInstalledAgentGuidance(home); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), agentguidance.Guidance) || strings.Contains(string(got), "stale") {
		t.Fatalf("Claude guidance did not refresh: %s", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("uninstalled Codex guidance was created: %v", err)
	}
}
