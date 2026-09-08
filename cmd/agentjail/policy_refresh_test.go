package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefreshInstalledCoreRulesRetiresStalePolicy(t *testing.T) {
	home := t.TempDir()
	origHome := roleUserHomeDir
	roleUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { roleUserHomeDir = origHome })
	dir := filepath.Join(home, ".agentjail", "rules")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := []byte("# old command_policy/no-bash-touch-sensitive-path\n")
	for _, name := range []string{"command_policy.rego", "custom.rego", "no_shell_eval.rego"} {
		if err := os.WriteFile(filepath.Join(dir, name), stale, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := refreshInstalledCoreRules(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "command_policy.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(coreRuleContent("command_policy")) || strings.Contains(string(got), "no-bash-touch-sensitive-path") {
		t.Fatal("installed command policy did not replace the retired rule with the shipped bundle")
	}
	for _, name := range []string{"custom.rego", "no_shell_eval.rego"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(stale) {
			t.Fatalf("non-core policy %s changed: %v", name, err)
		}
	}
}

func TestRefreshInstalledCoreRulesPreservesExplicitBundle(t *testing.T) {
	home := t.TempDir()
	origHome := roleUserHomeDir
	roleUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { roleUserHomeDir = origHome })
	dir := filepath.Join(home, "development-rules")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := refreshInstalledCoreRules(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("explicit bundle was modified: entries=%d err=%v", len(entries), err)
	}
}
