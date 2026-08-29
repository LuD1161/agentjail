package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeUninstallRestoresGlobalGuidanceFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "CLAUDE.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("# User guidance\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	env := Env{Home: home}
	if err := (ClaudeCode{}).ReconcileGuidance(env); err != nil {
		t.Fatal(err)
	}
	if err := (ClaudeCode{}).Uninstall(env); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("CLAUDE.md after uninstall = %q, want %q", got, original)
	}
}

func TestUninstallReportsGuidanceCleanupFailure(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "CLAUDE.md")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := (ClaudeCode{}).Uninstall(Env{Home: home})
	if err == nil {
		t.Fatal("Uninstall() error = nil, want guidance cleanup failure")
	}
	for _, want := range []string{"remove AgentJail guidance", path, "not a regular file"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Uninstall() error = %q, want %q", err, want)
		}
	}
}

func TestCodexUninstallRestoresGlobalGuidanceFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "AGENTS.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("# User guidance\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	env := Env{Home: home}
	if err := (Codex{}).ReconcileGuidance(env); err != nil {
		t.Fatal(err)
	}
	if err := (Codex{}).Uninstall(env); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("AGENTS.md after uninstall = %q, want %q", got, original)
	}
}
