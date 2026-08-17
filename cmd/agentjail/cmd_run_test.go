package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRunOptionsCredentialMappings(t *testing.T) {
	t.Parallel()
	options, rest, err := parseRunOptions([]string{
		"--credential", "aws-read-only-cred-prod",
		"--credential=cluster-dev",
		"--",
		"codex",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.credentials) != 2 || options.credentials[0] != "aws-read-only-cred-prod" || options.credentials[1] != "cluster-dev" {
		t.Fatalf("credentials = %#v", options.credentials)
	}
	if len(rest) != 2 || rest[0] != "--" || rest[1] != "codex" {
		t.Fatalf("rest = %#v", rest)
	}
}

func TestParseRunOptionsRequireTunnel(t *testing.T) {
	t.Parallel()
	options, rest, err := parseRunOptions([]string{"--require-tunnel", "--", "codex", "exec"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.requireTunnel {
		t.Fatalf("options = %#v, want requireTunnel", options)
	}
	if len(rest) != 3 || rest[0] != "--" || rest[1] != "codex" || rest[2] != "exec" {
		t.Fatalf("rest = %#v", rest)
	}
}

func TestParseRunOptionsRejectsMissingCredentialID(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--credential"}, {"--credential", "--", "codex"}, {"--credential="}} {
		if _, _, err := parseRunOptions(args); err == nil {
			t.Fatalf("parseRunOptions(%q) succeeded, want error", args)
		}
	}
}

// TestResolveRealAgent_SkipsShimDir verifies that resolveRealAgent finds the
// real binary even when the agentjail shim dir (~/.agentjail/bin) is FIRST on
// PATH -- the ordering transparent interception needs. A naive exec.LookPath
// would return the shim and loop.
func TestResolveRealAgent_SkipsShimDir(t *testing.T) {
	home := t.TempDir()
	shimDir := filepath.Join(home, ".agentjail", "bin")
	realDir := filepath.Join(home, ".local", "bin")
	for _, d := range []string{shimDir, realDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A "claude" in BOTH the shim dir and the real dir.
	shimClaude := filepath.Join(shimDir, "claude")
	realClaude := filepath.Join(realDir, "claude")
	if err := os.WriteFile(shimClaude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realClaude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Shim dir FIRST on PATH (the auto-shield ordering).
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	got, err := resolveRealAgent("claude", home)
	if err != nil {
		t.Fatalf("resolveRealAgent: %v", err)
	}
	if got != realClaude {
		t.Errorf("resolveRealAgent = %q, want the real binary %q (must skip the shim dir %q)", got, realClaude, shimDir)
	}
}

// TestResolveRealAgent_OnlyShimIsError verifies that when the ONLY match is the
// shim dir, resolution fails cleanly (no loop, no false positive) rather than
// returning the shim.
func TestResolveRealAgent_OnlyShimIsError(t *testing.T) {
	home := t.TempDir()
	shimDir := filepath.Join(home, ".agentjail", "bin")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shimDir, "claude"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)

	if got, err := resolveRealAgent("claude", home); err == nil {
		t.Errorf("resolveRealAgent = %q, want error when only the shim dir has the binary", got)
	}
}
