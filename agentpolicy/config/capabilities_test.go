package config

import (
	"strings"
	"testing"
)

func TestDefaultEnablesGitSSHCapability(t *testing.T) {
	if !Default().GitSSHEnabled() {
		t.Fatal("standard profile must enable Git over SSH")
	}
}

func TestNilPolicyDoesNotEnableGitSSHCapability(t *testing.T) {
	var cfg *PolicyConfig
	if cfg.GitSSHEnabled() {
		t.Fatal("nil policy must not enable a host capability")
	}
}

func TestMergePreservesExplicitGitSSHFalse(t *testing.T) {
	cfg, err := decode(strings.NewReader("capabilities:\n  git_ssh: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(Default(), cfg)
	if merged.GitSSHEnabled() {
		t.Fatal("explicit capabilities.git_ssh false was lost during merge")
	}
}

func TestMergeUsesStandardGitSSHWhenOmitted(t *testing.T) {
	cfg, err := decode(strings.NewReader("commands:\n  extra_block: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !Merge(Default(), cfg).GitSSHEnabled() {
		t.Fatal("omitted capabilities.git_ssh must retain the standard default")
	}
}
