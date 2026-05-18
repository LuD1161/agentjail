// quarantine_test.go — tests for the staged quarantine in loadModules (ADR 0014 §5).
//
// These are unit tests around the loadModules function. They write temp .rego
// files directly into a temp directory and verify that:
//   1. With only valid custom files, all modules are returned.
//   2. With one valid + one bundle-breaking custom file, the good file is kept
//      and the bad one is silently skipped (WARN logged).
//   3. Core/library files are never quarantined — they are always included in
//      the baseline (a bad core file would be a bug, not a custom-rule issue).
//
// NOTE: loadModules is also tested indirectly by the full daemon integration
// tests in main_test.go.
package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coreRegoForTest is a minimal but valid core bundle that the daemon would
// normally load from ~/.agentjail/rules/.  We use a simplified resolver +
// command_policy pair so the test doesn't depend on the embedded policies tree.
const coreRegoForTest = `
package agentjail

import future.keywords.if
import future.keywords.in
import future.keywords.contains

locked_rules := {}

disabled := object.get(data.agentjail.config, "disabled_rules", [])

rule_disabled(id) if {
    not id in locked_rules
    some p in disabled
    glob.match(p, ["/"], id)
}

effective_candidate contains c if {
    some c in candidate
    not rule_disabled(c.rule_id)
}

default decision = {
    "action":  "ask",
    "reason":  "no policy candidate fired — defaulting to ask",
    "rule_id": "resolver/default",
}

decision = d if {
    deny_ids := {c.rule_id | some c in effective_candidate; c.action == "deny"}
    count(deny_ids) > 0
    min_id := min(deny_ids)
    some d in effective_candidate
    d.action == "deny"
    d.rule_id == min_id
}
`

// validCustomRego is a syntactically and semantically valid custom rule file
// that adds a candidate entry — compatible with the coreRegoForTest bundle.
const validCustomRegoForDaemon = `
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "NeverMatchTool_12345_daemon_test"
    r := {
        "action":  "deny",
        "rule_id": "custom/testdaemon/valid",
        "reason":  "test",
        "impact":  "test",
    }
}
`

// bundleBreakingRego is a file that causes an OPA compile-time error when
// combined with coreRegoForTest.  It references an undefined built-in function
// `no_such_builtin_function_xyz` — OPA catches this at compile (PrepareForEval)
// time rather than evaluation time, making it suitable for quarantine testing.
const bundleBreakingRego = `
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    # Reference an undefined function — OPA compile error, not runtime error.
    no_such_builtin_function_xyz("test")
    r := {
        "action":  "deny",
        "rule_id": "custom/testdaemon/break",
        "reason":  "break",
        "impact":  "break",
    }
}
`

// writeRulesDir creates a temp directory with a minimal core file plus the
// given custom files, and returns the directory path.
func writeRulesDir(t *testing.T, customFiles map[string]string) string {
	t.Helper()
	dir := t.TempDir()

	// Write a minimal "core" resolver file so the baseline compiles.
	if err := os.WriteFile(filepath.Join(dir, "resolver.rego"), []byte(coreRegoForTest), 0o640); err != nil {
		t.Fatalf("write resolver.rego: %v", err)
	}

	// Write custom files.
	for name, content := range customFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// TestLoadModules_HappyPath_NoCaustomFiles verifies that when there are no
// custom files, loadModules returns the baseline unchanged.
func TestLoadModules_HappyPath_NoCustomFiles(t *testing.T) {
	dir := writeRulesDir(t, nil)

	modules, err := loadModules(dir)
	if err != nil {
		t.Fatalf("loadModules: %v", err)
	}
	// Should have exactly one module: resolver.rego (the core file).
	if len(modules) != 1 {
		t.Errorf("expected 1 module (resolver.rego), got %d: %v", len(modules), moduleNames(modules))
	}
}

// TestLoadModules_ValidCustomFile verifies that a valid custom rule is included.
func TestLoadModules_ValidCustomFile(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{
		"a_valid_custom.rego": validCustomRegoForDaemon,
	})

	modules, err := loadModules(dir)
	if err != nil {
		t.Fatalf("loadModules: %v", err)
	}
	// Should have resolver.rego + a_valid_custom.rego = 2.
	if len(modules) != 2 {
		t.Errorf("expected 2 modules, got %d: %v", len(modules), moduleNames(modules))
	}
	if !modulesContain(modules, "a_valid_custom.rego") {
		t.Errorf("expected a_valid_custom.rego in modules, got: %v", moduleNames(modules))
	}
}

// TestLoadModules_QuarantinesBadCustomFile verifies that:
//   - A valid custom file is included.
//   - A bundle-breaking custom file is skipped (quarantined) with a WARN log.
//   - loadModules does NOT return an error.
func TestLoadModules_QuarantinesBadCustomFile(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{
		// 'a_' prefix so valid loads before 'z_' bad (sorted order matters).
		"a_valid_custom.rego": validCustomRegoForDaemon,
		"z_bad_custom.rego":   bundleBreakingRego,
	})

	// Capture slog output to verify the WARN is emitted.
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(slog.Default()) })

	modules, err := loadModules(dir)
	if err != nil {
		t.Fatalf("loadModules should not return an error even with a bad custom file, got: %v", err)
	}

	// Should have resolver.rego + valid custom = 2.  Bad one is skipped.
	if len(modules) != 2 {
		t.Errorf("expected 2 modules (baseline + valid custom), got %d: %v", len(modules), moduleNames(modules))
	}
	if !modulesContain(modules, "a_valid_custom.rego") {
		t.Errorf("expected a_valid_custom.rego in modules, got: %v", moduleNames(modules))
	}
	if modulesContain(modules, "z_bad_custom.rego") {
		t.Errorf("z_bad_custom.rego should have been quarantined but appears in modules")
	}

	// The WARN log must mention the bad file.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "skipping custom rule") {
		t.Errorf("expected 'skipping custom rule' WARN in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "z_bad_custom.rego") {
		t.Errorf("expected bad file name in log output, got:\n%s", logOutput)
	}
}

// TestLoadModules_BaselineLoadsWithAllBadCustomFiles verifies that even if ALL
// custom files are broken, the baseline still loads successfully.
func TestLoadModules_BaselineLoadsWithAllBadCustomFiles(t *testing.T) {
	dir := writeRulesDir(t, map[string]string{
		"b_bad1.rego": bundleBreakingRego,
		"c_bad2.rego": bundleBreakingRego,
	})

	modules, err := loadModules(dir)
	if err != nil {
		t.Fatalf("loadModules should not fail even with all bad custom files, got: %v", err)
	}

	// Only the baseline should be present (resolver.rego = 1 module).
	if len(modules) != 1 {
		t.Errorf("expected 1 module (baseline only), got %d: %v", len(modules), moduleNames(modules))
	}
	if !modulesContain(modules, "resolver.rego") {
		t.Errorf("baseline resolver.rego missing from modules: %v", moduleNames(modules))
	}
}

// ---- helpers ----------------------------------------------------------------

func moduleNames(modules [][2]string) []string {
	names := make([]string, len(modules))
	for i, m := range modules {
		names[i] = filepath.Base(m[0])
	}
	return names
}

func modulesContain(modules [][2]string, name string) bool {
	for _, m := range modules {
		if filepath.Base(m[0]) == name {
			return true
		}
	}
	return false
}
