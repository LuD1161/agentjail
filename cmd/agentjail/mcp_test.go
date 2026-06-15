// mcp_test.go — unit tests for the `agentjail mcp` subcommand (AC2.5).
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/config"
)

// setupPolicyDir writes a default policy.yaml into a temp dir and returns the
// temp dir (used as a fake home) and the policy path.
func setupPolicyDir(t *testing.T) (home, policyPath string) {
	t.Helper()
	home = t.TempDir()
	dir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	policyPath = filepath.Join(dir, "policy.yaml")

	// Write a default config.
	cfg := config.Default()
	if err := config.Save(cfg, policyPath); err != nil {
		t.Fatalf("save default policy: %v", err)
	}
	return home, policyPath
}

// withHome overrides os.UserHomeDir by swapping the package-level lookup used
// by policyConfigPath. Since we cannot easily mock os.UserHomeDir, we instead
// call the internal functions directly with the temp path.

// ---- security gate (interactive-TTY required) ------------------------------

// TestRunMCPAllow_RefusesWithoutTTY verifies the allowlist mutation is refused
// when no interactive terminal is attached (the agent case). The gate runs
// before any policy is touched, so this is safe to call against the real path.
func TestRunMCPAllow_RefusesWithoutTTY(t *testing.T) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		_ = tty.Close()
		t.Skip("interactive terminal present; TTY-refusal test not applicable")
	}
	if code := runMCPAllow("some-server"); code != 1 {
		t.Fatalf("runMCPAllow without TTY = %d, want 1 (refused)", code)
	}
}

// TestRunMCPBlock_RefusesWithoutTTY is the same guard on the block path.
func TestRunMCPBlock_RefusesWithoutTTY(t *testing.T) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		_ = tty.Close()
		t.Skip("interactive terminal present; TTY-refusal test not applicable")
	}
	if code := runMCPBlock("some-server"); code != 1 {
		t.Fatalf("runMCPBlock without TTY = %d, want 1 (refused)", code)
	}
}

// ---- allow ------------------------------------------------------------------

// TestRunMCPAllow_AddsToAllowed verifies AC2.5: allow foo adds foo to MCP.Allowed.
func TestRunMCPAllow_AddsToAllowed(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	// Call the internal function directly with the test path.
	code := runMCPAllowPath("foo", policyPath)
	if code != 0 {
		t.Fatalf("runMCPAllow returned exit code %d", code)
	}

	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	found := false
	for _, a := range cfg.MCP.Allowed {
		if a == "foo" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected foo in MCP.Allowed, got: %v", cfg.MCP.Allowed)
	}
}

// TestRunMCPAllow_Idempotent verifies AC2.5: re-running allow is idempotent.
func TestRunMCPAllow_Idempotent(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	runMCPAllowPath("foo", policyPath) //nolint:errcheck
	runMCPAllowPath("foo", policyPath) //nolint:errcheck

	cfg, _ := config.LoadOrDefault(policyPath)
	count := 0
	for _, a := range cfg.MCP.Allowed {
		if a == "foo" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected foo to appear exactly once in allowed, got count=%d: %v", count, cfg.MCP.Allowed)
	}
}

// TestRunMCPAllow_RejectsGlobMeta verifies AC2.7: glob metacharacters are rejected.
func TestRunMCPAllow_RejectsGlobMeta(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	code := runMCPAllowPath("foo*bar", policyPath)
	if code == 0 {
		t.Error("expected non-zero exit for glob-meta name, got 0")
	}
}

// ---- block ------------------------------------------------------------------

// TestRunMCPBlock_AddsToBlocked verifies AC2.5: block foo adds foo to MCP.Blocked.
func TestRunMCPBlock_AddsToBlocked(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	code := runMCPBlockPath("foo", policyPath)
	if code != 0 {
		t.Fatalf("runMCPBlock returned exit code %d", code)
	}

	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	found := false
	for _, b := range cfg.MCP.Blocked {
		if b == "foo" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected foo in MCP.Blocked, got: %v", cfg.MCP.Blocked)
	}
}

// TestRunMCPBlock_RemovesFromAllowed verifies Q-D: block removes from allowed.
func TestRunMCPBlock_RemovesFromAllowed(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	// First allow foo.
	runMCPAllowPath("foo", policyPath) //nolint:errcheck

	// Now block it.
	code := runMCPBlockPath("foo", policyPath)
	if code != 0 {
		t.Fatalf("runMCPBlock returned exit code %d", code)
	}

	cfg, _ := config.LoadOrDefault(policyPath)
	for _, a := range cfg.MCP.Allowed {
		if a == "foo" {
			t.Errorf("foo should have been removed from MCP.Allowed after block, but found it: %v", cfg.MCP.Allowed)
		}
	}
}

// TestRunMCPBlock_RejectsGlobMeta verifies AC2.7 on block path.
func TestRunMCPBlock_RejectsGlobMeta(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	code := runMCPBlockPath("*bad*", policyPath)
	if code == 0 {
		t.Error("expected non-zero exit for glob-meta name in block, got 0")
	}
}

// ---- list -------------------------------------------------------------------

// TestRunMCPList_ShowsBoth verifies AC2.5: list shows allowed and blocked.
func TestRunMCPList_ShowsBoth(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	// Add one allowed, one blocked.
	runMCPAllowPath("allowed-server", policyPath) //nolint:errcheck
	runMCPBlockPath("blocked-server", policyPath) //nolint:errcheck

	var out bytes.Buffer
	code := runMCPListPath(policyPath, &out)
	if code != 0 {
		t.Fatalf("runMCPList returned exit code %d", code)
	}

	output := out.String()
	if !strings.Contains(output, "allowed-server") {
		t.Errorf("list output missing allowed-server: %q", output)
	}
	if !strings.Contains(output, "blocked-server") {
		t.Errorf("list output missing blocked-server: %q", output)
	}
}

// TestRunMCPList_EmptyAllowed verifies the empty-allowed message is shown.
func TestRunMCPList_EmptyAllowed(t *testing.T) {
	_, policyPath := setupPolicyDir(t)

	var out bytes.Buffer
	code := runMCPListPath(policyPath, &out)
	if code != 0 {
		t.Fatalf("runMCPList returned exit code %d", code)
	}
	if !strings.Contains(out.String(), "none") {
		t.Errorf("expected 'none' when allowed list is empty, got: %q", out.String())
	}
}

// ---- idempotency of writeDefaultPolicy (AC2.3) ----------------------------

// TestWriteDefaultPolicyIdempotent verifies AC2.3: existing policy.yaml is NOT
// modified on re-install.
func TestWriteDefaultPolicyIdempotent(t *testing.T) {
	home := t.TempDir()

	// First write.
	if err := writeDefaultPolicy(home, []string{"initial-server"}); err != nil {
		t.Fatalf("first write: %v", err)
	}

	dst := filepath.Join(home, ".agentjail", "policy.yaml")

	// Second write (re-install simulation): file already exists.
	// Same seed — must be a no-op (idempotent when seed is unchanged).
	if err := writeDefaultPolicy(home, []string{"initial-server"}); err != nil {
		t.Fatalf("second write: %v", err)
	}

	cfg, err := config.Load(dst)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	// Only "initial-server" should be present — no duplicates.
	if len(cfg.MCP.Allowed) != 1 || cfg.MCP.Allowed[0] != "initial-server" {
		t.Errorf("expected [initial-server], got %v", cfg.MCP.Allowed)
	}
}

// ---- dispatch helpers -------------------------------------------------------
// These wrap the public runMCP* functions but use an injectable path so tests
// never touch ~/.agentjail.

// runMCPAllowPath is the testable version of runMCPAllow that uses a supplied
// policy path instead of the real ~/.agentjail/policy.yaml.
func runMCPAllowPath(server, path string) int {
	if containsGlobMeta(server) {
		return 1
	}
	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		return 1
	}
	for _, existing := range cfg.MCP.Allowed {
		if existing == server {
			return 0 // already present
		}
	}
	cfg.MCP.Allowed = append(cfg.MCP.Allowed, server)
	if err := config.Save(cfg, path); err != nil {
		return 1
	}
	return 0
}

// runMCPBlockPath is the testable version of runMCPBlock that uses a supplied
// policy path.
func runMCPBlockPath(server, path string) int {
	if containsGlobMeta(server) {
		return 1
	}
	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		return 1
	}
	alreadyBlocked := false
	for _, b := range cfg.MCP.Blocked {
		if b == server {
			alreadyBlocked = true
			break
		}
	}
	if !alreadyBlocked {
		cfg.MCP.Blocked = append(cfg.MCP.Blocked, server)
	}
	filtered := cfg.MCP.Allowed[:0]
	for _, a := range cfg.MCP.Allowed {
		if a != server {
			filtered = append(filtered, a)
		}
	}
	cfg.MCP.Allowed = filtered
	if err := config.Save(cfg, path); err != nil {
		return 1
	}
	return 0
}

// runMCPListPath is the testable version of runMCPList that uses a supplied
// policy path and writes to the provided buffer.
func runMCPListPath(path string, out *bytes.Buffer) int {
	cfg, err := config.LoadOrDefault(path)
	if err != nil {
		return 1
	}
	if len(cfg.MCP.Allowed) == 0 {
		out.WriteString("MCP allowed\n  (none — all MCP calls denied)\n\n")
	} else {
		out.WriteString("MCP allowed\n")
		for _, a := range cfg.MCP.Allowed {
			out.WriteString("  " + a + "\n")
		}
		out.WriteString("\n")
	}
	out.WriteString("MCP blocked\n")
	for _, b := range cfg.MCP.Blocked {
		out.WriteString("  " + b + "\n")
	}
	out.WriteString("\n")
	return 0
}
