// library_embed.go — embedded policy rule files for `agentjail policy` subcommand.
//
// The library/ subdirectory is a copy of agentpolicy/policies/library/ (non-test .rego
// files only). The policies/ subdirectory is a BYTE-IDENTICAL mirror of the hook-path
// core files from agentpolicy/policies/: command_policy, file_policy, mcp_policy,
// no_daemon_kill, no_hook_self_disable, and resolver. All six are baked into the binary
// at compile time via go:embed so the CLI works without a checkout of the agentpolicy tree.
//
// NOTE: default.rego is intentionally excluded — it belongs to package agentjail.default
// (a legacy/credential-broker path) and is not part of the hook-wire decision path.
//
// no_daemon_kill and no_hook_self_disable were promoted from library to always-on locked
// core (ADR 0014 follow-up #10). Their rule_ids retain the "library/" prefix for
// historical reasons.
//
// Whenever agentpolicy/policies/library/ or agentpolicy/policies/*.rego changes, run:
//   cp agentpolicy/policies/{command_policy,file_policy,mcp_policy,no_daemon_kill,no_hook_self_disable,resolver}.rego \
//      cmd/agentjail/policies/
// The embed_parity_test.go guard will catch any drift.
package main

import (
	"embed"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed library/*.rego
var libraryFS embed.FS

//go:embed policies/*.rego
var policiesFS embed.FS

// libraryRuleNames returns sorted rule names (filename stem, no .rego suffix)
// for all embedded library rules.
func libraryRuleNames() []string {
	entries, _ := libraryFS.ReadDir("library")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".rego") && !strings.HasSuffix(n, "_test.rego") {
			names = append(names, strings.TrimSuffix(n, ".rego"))
		}
	}
	sort.Strings(names)
	return names
}

// coreRuleNames returns sorted rule names (filename stem, no .rego suffix)
// for all embedded core policies.
func coreRuleNames() []string {
	entries, _ := policiesFS.ReadDir("policies")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".rego") && !strings.HasSuffix(n, "_test.rego") {
			names = append(names, strings.TrimSuffix(n, ".rego"))
		}
	}
	sort.Strings(names)
	return names
}

// libraryRuleContent returns the embedded bytes for the named library rule.
// name must be the stem (no .rego suffix). Returns nil if not found.
func libraryRuleContent(name string) []byte {
	b, err := libraryFS.ReadFile(filepath.Join("library", name+".rego"))
	if err != nil {
		return nil
	}
	return b
}

// coreRuleContent returns the embedded bytes for the named core rule.
func coreRuleContent(name string) []byte {
	b, err := policiesFS.ReadFile(filepath.Join("policies", name+".rego"))
	if err != nil {
		return nil
	}
	return b
}

// allCoreRuleBytes returns a map of core rule name -> bytes for all embedded core rules.
func allCoreRuleBytes() map[string][]byte {
	result := map[string][]byte{}
	_ = fs.WalkDir(policiesFS, "policies", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := d.Name()
		if !strings.HasSuffix(n, ".rego") || strings.HasSuffix(n, "_test.rego") {
			return nil
		}
		stem := strings.TrimSuffix(n, ".rego")
		b, _ := policiesFS.ReadFile(path)
		result[stem] = b
		return nil
	})
	return result
}
