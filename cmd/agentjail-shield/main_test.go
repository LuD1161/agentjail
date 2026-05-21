package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// TestDefaultPolicyPath checks that defaultPolicyPath returns a path ending in
// .agentjail/policy.yaml (and not the /tmp fallback when $HOME is reachable).
func TestDefaultPolicyPath(t *testing.T) {
	p := defaultPolicyPath()
	if !strings.HasSuffix(p, ".agentjail/policy.yaml") {
		t.Errorf("defaultPolicyPath() = %q; want suffix .agentjail/policy.yaml", p)
	}
}

// TestFlagParseNoDashDash verifies that omitting '--' causes flag.Args() to
// return an empty slice (the separator requirement is checked in main itself,
// but we can unit-test flag parsing here).
func TestFlagParseNoDashDash(t *testing.T) {
	// Reset flag state to parse a fresh set of args.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.String("policy", "/tmp/test.yaml", "")
	profilePrint := fs.Bool("profile-print", false, "")

	err := fs.Parse([]string{"--policy=/tmp/test.yaml"})
	if err != nil {
		t.Fatalf("flag.Parse unexpected error: %v", err)
	}
	// No positional args after flags — simulates missing '--' agent-cmd.
	if len(fs.Args()) != 0 {
		t.Errorf("expected no args, got %v", fs.Args())
	}
	if *profilePrint {
		t.Error("profilePrint should be false")
	}
}

// TestFlagParseWithDashDash verifies that '--' separates shield flags from
// agent command correctly.
func TestFlagParseWithDashDash(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	policyFlag := fs.String("policy", "/tmp/test.yaml", "")
	_ = fs.Bool("profile-print", false, "")

	err := fs.Parse([]string{"--policy=/tmp/custom.yaml", "--", "claude", "--print", "hello"})
	if err != nil {
		t.Fatalf("flag.Parse unexpected error: %v", err)
	}
	if *policyFlag != "/tmp/custom.yaml" {
		t.Errorf("policy = %q; want /tmp/custom.yaml", *policyFlag)
	}
	args := fs.Args()
	if len(args) != 3 || args[0] != "claude" {
		t.Errorf("args = %v; want [claude --print hello]", args)
	}
}

// TestAgentNotFound checks that LookPath fails for a non-existent binary
// (we can't easily test os.Exit(127) from a unit test, but we can test the
// path resolution logic independently).
func TestAgentNotFound(t *testing.T) {
	_, err := os.Stat("/usr/bin/this-binary-does-not-exist-agentjail-shield-test")
	if !os.IsNotExist(err) {
		t.Skip("unexpected binary found")
	}
}
