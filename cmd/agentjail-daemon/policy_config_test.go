package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountCustomRuleFiles(t *testing.T) {
	dir := t.TempDir()
	// built-in (core/library) stems → not custom
	for _, n := range []string{"command_policy.rego", "no_shell_eval.rego"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("package x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// custom stems → counted
	for _, n := range []string{"custom_a.rego", "custom_b.rego"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("package x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// non-rego + test file → ignored
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "custom_a_test.rego"), []byte("x"), 0o600)

	if n := countCustomRuleFiles(dir); n != 2 {
		t.Fatalf("countCustomRuleFiles=%d want 2", n)
	}
	if n := countCustomRuleFiles(""); n != 0 {
		t.Fatalf("empty dir should be 0, got %d", n)
	}
}
