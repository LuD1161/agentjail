// embed_parity_test.go — parity guard between the source policy tree
// (agentpolicy/policies/) and the embedded mirror (cmd/agentjail/policies/,
// cmd/agentjail/library/).
//
// These tests fail immediately when a developer updates a source file and
// forgets to copy the mirror — preventing the fail-open regression that
// motivated the R1-R5 fix batch.
//
// Scope:
//   - Hook-path core files: {command_policy, file_policy, mcp_policy, resolver}.rego
//   - Library rules: all non-test .rego files under agentpolicy/policies/library/
//
// Exclusions:
//   - default.rego: belongs to package agentjail.default (a legacy
//     credential-broker path), not the hook-wire decision path.  It is not
//     shipped in cmd/agentjail/policies/ and must not be included here.
//   - *_test.rego: OPA unit tests; not compiled into the binary.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sourceRoot returns the absolute path to agentpolicy/policies/ relative to
// this test file's location (cmd/agentjail/).
func sourceRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = .../cmd/agentjail/embed_parity_test.go
	// repo root = ../..
	dir := filepath.Dir(file)
	return filepath.Join(dir, "..", "..", "agentpolicy", "policies")
}

// TestCoreFileParity asserts that each of the six hook-path core files is
// byte-identical between agentpolicy/policies/ (source of truth) and the
// embedded mirror (allCoreRuleBytes()).
//
// no_daemon_kill and no_hook_self_disable were promoted from the library to
// always-on locked core (ADR 0014 follow-up #10). They are now included in
// this set.
func TestCoreFileParity(t *testing.T) {
	t.Parallel()

	srcDir := sourceRoot(t)

	// The hook-path files that must be mirrored.
	hookPathFiles := []string{
		"aws_posture",
		"command_policy",
		"file_policy",
		"mcp_policy",
		"internal_tools",
		"web_policy",
		"no_daemon_kill",
		"no_hook_self_disable",
		"resolver",
	}

	mirrorBytes := allCoreRuleBytes()

	for _, name := range hookPathFiles {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srcPath := filepath.Join(srcDir, name+".rego")
			srcBytes, err := os.ReadFile(srcPath)
			if err != nil {
				t.Fatalf("read source %s.rego: %v", name, err)
			}

			mirrorContent, ok := mirrorBytes[name]
			if !ok {
				t.Fatalf("embedded mirror missing %s.rego — run: cp agentpolicy/policies/%s.rego cmd/agentjail/policies/", name, name)
			}

			if string(srcBytes) != string(mirrorContent) {
				t.Errorf("%s.rego differs between source and mirror embed.\n"+
					"Fix: cp agentpolicy/policies/%s.rego cmd/agentjail/policies/%s.rego",
					name, name, name)
			}
		})
	}

	// Ensure default.rego is NOT in the mirror embed.
	// (It belongs to package agentjail.default — a legacy path, out of scope.)
	if _, ok := mirrorBytes["default"]; ok {
		t.Error("embed mirror must NOT include default.rego (package agentjail.default — legacy credential-broker path)")
	}
}

// TestLibraryFileParity asserts that every non-test library rule in
// agentpolicy/policies/library/ is byte-identical to its counterpart in
// cmd/agentjail/library/ (via libraryRuleContent).
func TestLibraryFileParity(t *testing.T) {
	t.Parallel()

	srcLibDir := filepath.Join(sourceRoot(t), "library")

	entries, err := os.ReadDir(srcLibDir)
	if err != nil {
		t.Fatalf("read source library dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".rego") || strings.HasSuffix(n, "_test.rego") {
			continue
		}
		name := strings.TrimSuffix(n, ".rego")
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srcBytes, err := os.ReadFile(filepath.Join(srcLibDir, n))
			if err != nil {
				t.Fatalf("read source library/%s: %v", n, err)
			}

			mirrorBytes := libraryRuleContent(name)
			if mirrorBytes == nil {
				t.Fatalf("embedded mirror missing library/%s — run: cp agentpolicy/policies/library/%s cmd/agentjail/library/%s", n, n, n)
			}

			if string(srcBytes) != string(mirrorBytes) {
				t.Errorf("library/%s differs between source and mirror embed.\n"+
					"Fix: cp agentpolicy/policies/library/%s cmd/agentjail/library/%s",
					n, n, n)
			}
		})
	}
}
