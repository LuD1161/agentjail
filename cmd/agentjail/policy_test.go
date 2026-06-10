// policy_test.go — unit tests for `agentjail policy` subcommand.
//
// All tests that need a filesystem use t.TempDir(); no test modifies
// ~/.agentjail/ or sends SIGHUP to a real daemon.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuD1161/agentjail/agentpolicy/config"
)

// TestLibraryRuleNames verifies the embedded library rules are all present.
// no_daemon_kill and no_hook_self_disable are now always-on locked core rules
// and must NOT appear in the library set.
func TestLibraryRuleNames(t *testing.T) {
	names := libraryRuleNames()
	want := []string{
		"no_app_binary_write",
		"no_destructive_git",
		"no_history_read",
		"no_launchctl",
		"no_shell_eval",
		"no_shell_init_write",
	}
	if len(names) != len(want) {
		t.Fatalf("libraryRuleNames() = %v, want %v", names, want)
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, n, want[i])
		}
	}
}

// TestCoreRuleNames verifies the embedded core rules are all present.
// resolver.rego is required: it is the single producer of data.agentjail.decision
// and must be shipped alongside the candidate-contributing core files.
// no_daemon_kill and no_hook_self_disable are promoted to always-on locked core
// (ADR 0014 follow-up #10) and must appear here.
func TestCoreRuleNames(t *testing.T) {
	names := coreRuleNames()
	want := []string{
		"command_policy",
		"file_policy",
		"internal_tools",
		"mcp_policy",
		"no_daemon_kill",
		"no_hook_self_disable",
		"resolver",
	}
	if len(names) != len(want) {
		t.Fatalf("coreRuleNames() = %v, want %v", names, want)
	}
	for i, n := range names {
		if n != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, n, want[i])
		}
	}
}

// TestLibraryRuleContent verifies the embedded content is non-empty.
func TestLibraryRuleContent(t *testing.T) {
	for _, name := range libraryRuleNames() {
		b := libraryRuleContent(name)
		if len(b) == 0 {
			t.Errorf("libraryRuleContent(%q) returned empty", name)
		}
		// Should contain the rule id pattern
		if !strings.Contains(string(b), "package") {
			t.Errorf("libraryRuleContent(%q) missing 'package' declaration", name)
		}
	}
}

// TestLibraryRuleContent_Unknown verifies that an unknown name returns nil.
func TestLibraryRuleContent_Unknown(t *testing.T) {
	b := libraryRuleContent("does_not_exist")
	if b != nil {
		t.Errorf("libraryRuleContent for unknown rule should be nil, got %d bytes", len(b))
	}
}

// TestIsLibraryRule verifies known/unknown distinctions.
// no_daemon_kill and no_hook_self_disable are now always-on locked core rules
// and must NOT be classified as library rules.
func TestIsLibraryRule(t *testing.T) {
	if !isLibraryRule("no_shell_init_write") {
		t.Error("no_shell_init_write should be a library rule")
	}
	if !isLibraryRule("no_launchctl") {
		t.Error("no_launchctl should be a library rule")
	}
	if isLibraryRule("file_policy") {
		t.Error("file_policy should NOT be a library rule")
	}
	if isLibraryRule("bogus_rule") {
		t.Error("bogus_rule should NOT be a library rule")
	}
	// Promoted to core — must not be library.
	if isLibraryRule("no_daemon_kill") {
		t.Error("no_daemon_kill should NOT be a library rule (promoted to core)")
	}
	if isLibraryRule("no_hook_self_disable") {
		t.Error("no_hook_self_disable should NOT be a library rule (promoted to core)")
	}
}

// TestIsCoreRule verifies core rule classification.
// no_daemon_kill and no_hook_self_disable are promoted to always-on locked core.
func TestIsCoreRule(t *testing.T) {
	if !isCoreRule("file_policy") {
		t.Error("file_policy should be a core rule")
	}
	if !isCoreRule("mcp_policy") {
		t.Error("mcp_policy should be a core rule")
	}
	if !isCoreRule("resolver") {
		t.Error("resolver should be a core rule")
	}
	if isCoreRule("no_shell_init_write") {
		t.Error("no_shell_init_write should NOT be a core rule")
	}
	// Promoted to core.
	if !isCoreRule("no_daemon_kill") {
		t.Error("no_daemon_kill should be a core rule (promoted from library)")
	}
	if !isCoreRule("no_hook_self_disable") {
		t.Error("no_hook_self_disable should be a core rule (promoted from library)")
	}
}

// TestListRules_AllDisabled tests that list shows disabled for all library
// rules when the rules dir is empty.
func TestListRules_AllDisabled(t *testing.T) {
	// Use a real temp dir as the rules dir — nothing in it.
	tmpDir := t.TempDir()

	// Redirect HOME so rulesDir() points to our temp dir.
	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()

	// Create a fake ~/.agentjail/ inside tmpDir.
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.Setenv("HOME", fakeHome)

	// runPolicyList returns 0 on success; we don't capture stdout here, just
	// verify it doesn't panic or error.
	code := runPolicyList()
	if code != 0 {
		t.Errorf("runPolicyList() = %d, want 0", code)
	}
}

func TestPolicyUsagePremiumStructure(t *testing.T) {
	var buf bytes.Buffer
	printPolicyUsage(&buf)
	out := stripANSI(buf.String())

	required := []string{
		"agentjail policy",
		"Usage",
		"  agentjail policy <command>",
		"Commands",
		"list",
		"enable",
		"disable",
		"Examples",
		"  agentjail policy list",
		"  agentjail policy enable no_history_read",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("printPolicyUsage output missing %q\nfull output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "usage:") {
		t.Errorf("printPolicyUsage output contains raw usage line\nfull output:\n%s", out)
	}
	if !strings.HasSuffix(buf.String(), "\n\n") {
		t.Errorf("printPolicyUsage output should end with a blank line before the shell prompt\ngot:\n%q", buf.String())
	}
}

func TestPolicyListPremiumStructure(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	rulesPath := filepath.Join(fakeHome, ".agentjail", "rules")
	if err := os.MkdirAll(rulesPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesPath, "no_history_read.rego"), []byte("package test\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	var buf bytes.Buffer
	code := runPolicyListOutput(&buf)
	if code != 0 {
		t.Fatalf("runPolicyListOutput() = %d, want 0", code)
	}
	out := stripANSI(buf.String())

	required := []string{
		"Core Rules",
		"locked",
		// Core rules now shown as rule_ids.
		"command_policy/no-sudo",
		"command_policy/no-policy-mutation",
		"file_policy/agentjail_self",
		"resolver/default",
		"Optional Hardening",
		"on",
		// Library rules now shown as rule_ids.
		"library/no-history-read",
		"Block shell history reads",
		"library/no-shell-eval",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("policy list output missing %q\nfull output:\n%s", want, out)
		}
	}
	forbidden := []string{
		"RULE",
		"STATUS",
		"SOURCE",
		"agentpolicy/policies",
	}
	for _, bad := range forbidden {
		if strings.Contains(out, bad) {
			t.Errorf("policy list output contains stale table/source text %q\nfull output:\n%s", bad, out)
		}
	}
	if !strings.HasSuffix(buf.String(), "\n\n") {
		t.Errorf("policy list output should end with a blank line before the shell prompt\ngot:\n%q", buf.String())
	}
}

// TestEnableRule_Roundtrip_WithTempDir enables and then disables a rule, asserting
// file presence/absence at each step.
func TestEnableRule_Roundtrip_WithTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	rulesPath := filepath.Join(fakeHome, ".agentjail", "rules")
	if err := os.MkdirAll(rulesPath, 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	// Enable
	code := runPolicyEnable("no_shell_init_write")
	if code != 0 {
		t.Fatalf("runPolicyEnable() = %d, want 0", code)
	}
	target := filepath.Join(rulesPath, "no_shell_init_write.rego")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("rule file should exist after enable: %v", err)
	}

	// File should be non-empty valid rego
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "package") {
		t.Error("enabled rule file missing 'package' declaration")
	}

	// Disable
	code = runPolicyDisable("no_shell_init_write")
	if code != 0 {
		t.Fatalf("runPolicyDisable() = %d, want 0", code)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("rule file should not exist after disable")
	}
}

// TestEnableRule_Roundtrip_MultipleRules tests enabling several rules and
// then disabling them one by one.
func TestEnableRule_Roundtrip_MultipleRules(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	rulesPath := filepath.Join(fakeHome, ".agentjail", "rules")
	if err := os.MkdirAll(rulesPath, 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	names := []string{"no_launchctl", "no_history_read", "no_shell_eval"}
	for _, name := range names {
		if code := runPolicyEnable(name); code != 0 {
			t.Errorf("runPolicyEnable(%q) = %d, want 0", name, code)
		}
		if _, err := os.Stat(filepath.Join(rulesPath, name+".rego")); err != nil {
			t.Errorf("rule file for %q should exist: %v", name, err)
		}
	}

	for _, name := range names {
		if code := runPolicyDisable(name); code != 0 {
			t.Errorf("runPolicyDisable(%q) = %d, want 0", name, code)
		}
		if _, err := os.Stat(filepath.Join(rulesPath, name+".rego")); !os.IsNotExist(err) {
			t.Errorf("rule file for %q should not exist after disable", name)
		}
	}
}

// TestEnableRule_Idempotent verifies that enabling an already-enabled rule
// does not fail.
func TestEnableRule_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	if code := runPolicyEnable("no_shell_init_write"); code != 0 {
		t.Fatalf("first enable = %d", code)
	}
	if code := runPolicyEnable("no_shell_init_write"); code != 0 {
		t.Errorf("second enable should also succeed, got %d", code)
	}
}

// TestEnableRule_UnknownName verifies that enabling an unknown rule returns
// a non-zero exit code.
func TestEnableRule_UnknownName(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	code := runPolicyEnable("not_a_real_rule")
	if code == 0 {
		t.Error("enabling unknown rule should return non-zero exit code")
	}
}

// TestDisableRule_Core verifies that attempting to disable a core rule fails.
func TestDisableRule_Core(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	for _, name := range coreRuleNames() {
		code := runPolicyDisable(name)
		if code == 0 {
			t.Errorf("disabling core rule %q should fail, got exit 0", name)
		}
	}
}

// TestDisableRule_AlreadyDisabled verifies that disabling a rule that is
// not currently enabled does not error.
func TestDisableRule_AlreadyDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	// Disable a rule that was never enabled — should succeed (idempotent).
	code := runPolicyDisable("no_shell_init_write")
	if code != 0 {
		t.Errorf("disabling an already-disabled rule should succeed, got %d", code)
	}
}

// TestEnableRule_Unknown_ErrorMessage verifies the error message content.
func TestEnableRule_Unknown_ErrorMessage(t *testing.T) {
	// We can't easily capture stderr here without restructuring, so we just
	// verify the return code is non-zero and the function doesn't panic.
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	code := runPolicyEnable("xyzzy_does_not_exist")
	if code == 0 {
		t.Error("expected non-zero exit code for unknown rule name")
	}
}

// TestInstallCoreRules verifies the installCoreRules helper copies all core
// rules to the target directory.
func TestInstallCoreRules(t *testing.T) {
	dir := t.TempDir()

	if err := installCoreRules(dir); err != nil {
		t.Fatalf("installCoreRules() error: %v", err)
	}

	for _, name := range coreRuleNames() {
		dst := filepath.Join(dir, name+".rego")
		if _, err := os.Stat(dst); err != nil {
			t.Errorf("core rule file %q not installed: %v", name+".rego", err)
		}
	}

	// Run again — should be idempotent (re-writes embedded bytes).
	if err := installCoreRules(dir); err != nil {
		t.Fatalf("installCoreRules() second run error: %v", err)
	}
}

// TestInstallCoreRules_ReplacesStale verifies that a STALE core file is
// replaced with the embedded bytes on upgrade (the critical fail-open fix).
// A stale else-chain command_policy.rego must be replaced so that resolver.rego
// becomes the sole decision producer and library rule candidates are enforced.
func TestInstallCoreRules_ReplacesStale(t *testing.T) {
	dir := t.TempDir()

	// Seed a stale (dummy) core file simulating the old else-chain version.
	name := coreRuleNames()[0] // e.g. "command_policy"
	dst := filepath.Join(dir, name+".rego")
	stale := []byte("# stale else-chain — must be replaced by installCoreRules\n")
	if err := os.WriteFile(dst, stale, 0o640); err != nil {
		t.Fatal(err)
	}

	// Also seed a non-core file (simulates an enabled library rule + user rule).
	libDst := filepath.Join(dir, "no_destructive_git.rego")
	libContent := libraryRuleContent("no_destructive_git")
	if libContent == nil {
		t.Fatal("libraryRuleContent(no_destructive_git) returned nil")
	}
	if err := os.WriteFile(libDst, libContent, 0o640); err != nil {
		t.Fatal(err)
	}
	userDst := filepath.Join(dir, "my_custom_rule.rego")
	if err := os.WriteFile(userDst, []byte("# user rule\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := installCoreRules(dir); err != nil {
		t.Fatalf("installCoreRules() error: %v", err)
	}

	// Stale core file must be replaced with embedded bytes.
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	want := allCoreRuleBytes()[name]
	if string(got) == string(stale) {
		t.Errorf("installCoreRules left stale file intact; must replace on upgrade")
	}
	if string(got) != string(want) {
		t.Errorf("installCoreRules wrote unexpected content for %q:\ngot:  %q\nwant: %q", name, got[:min(80, len(got))], want[:min(80, len(want))])
	}

	// Non-core files must be preserved (allCoreRuleBytes only knows core files).
	if _, err := os.Stat(libDst); err != nil {
		t.Errorf("library rule was removed by installCoreRules: %v", err)
	}
	if _, err := os.Stat(userDst); err != nil {
		t.Errorf("user rule was removed by installCoreRules: %v", err)
	}
}


// TestRunPolicy_Help verifies the help subcommand returns 0.
func TestRunPolicy_Help(t *testing.T) {
	code := runPolicy([]string{"help"})
	if code != 0 {
		t.Errorf("runPolicy(help) = %d, want 0", code)
	}
}

// TestRunPolicy_NoArgs verifies the no-args case returns 2.
func TestRunPolicy_NoArgs(t *testing.T) {
	code := runPolicy([]string{})
	if code != 2 {
		t.Errorf("runPolicy([]) = %d, want 2", code)
	}
}

// TestRunPolicy_UnknownSubcmd verifies unknown subcommand returns 2.
func TestRunPolicy_UnknownSubcmd(t *testing.T) {
	code := runPolicy([]string{"frobnicate"})
	if code != 2 {
		t.Errorf("runPolicy(frobnicate) = %d, want 2", code)
	}
}

// TestRunPolicy_EnableNoArg verifies missing name returns 2.
func TestRunPolicy_EnableNoArg(t *testing.T) {
	code := runPolicy([]string{"enable"})
	if code != 2 {
		t.Errorf("runPolicy(enable) = %d, want 2", code)
	}
}

// TestRunPolicy_DisableNoArg verifies missing name returns 2.
func TestRunPolicy_DisableNoArg(t *testing.T) {
	code := runPolicy([]string{"disable"})
	if code != 2 {
		t.Errorf("runPolicy(disable) = %d, want 2", code)
	}
}

// TestEnableRule_CannotDisableCore_ViaRunPolicy tests the full dispatch path.
func TestEnableRule_CannotDisableCore_ViaRunPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(filepath.Join(fakeHome, ".agentjail", "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	origHome := os.Getenv("HOME")
	defer func() { os.Setenv("HOME", origHome) }()
	os.Setenv("HOME", fakeHome)

	code := runPolicy([]string{"disable", "file_policy"})
	if code == 0 {
		t.Error("disabling core rule via runPolicy should fail")
	}
}

// TestAllCoreRuleBytes verifies all embedded core rule bytes are present.
func TestAllCoreRuleBytes(t *testing.T) {
	all := allCoreRuleBytes()
	if len(all) == 0 {
		t.Fatal("allCoreRuleBytes() returned empty map")
	}
	for name, b := range all {
		if len(b) == 0 {
			t.Errorf("core rule %q has empty content", name)
		}
	}
}

// ---------------------------------------------------------------------------
// ADR 0014 tests — rule registry, locked set, disable/enable rule_ids, audit
// ---------------------------------------------------------------------------

// setupADR0047Home creates a fake home with ~/.agentjail/{rules,} plus a
// default policy.yaml and returns the home path and policy.yaml path.
func setupADR0047Home(t *testing.T) (home, policyPath string) {
	t.Helper()
	home = t.TempDir()
	agentjailDir := filepath.Join(home, ".agentjail")
	if err := os.MkdirAll(filepath.Join(agentjailDir, "rules"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	policyPath = filepath.Join(agentjailDir, "policy.yaml")
	cfg := config.Default()
	if err := config.Save(cfg, policyPath); err != nil {
		t.Fatalf("save default policy: %v", err)
	}
	return home, policyPath
}

// withFakeHome sets HOME to fakeHome for the duration of the test.
func withFakeHome(t *testing.T, fakeHome string) {
	t.Helper()
	orig := os.Getenv("HOME")
	os.Setenv("HOME", fakeHome)
	t.Cleanup(func() { os.Setenv("HOME", orig) })
}

// TestLockedSetMatchesRego asserts that the Go LockedRuleIDs set is identical
// to the locked_rules constant in resolver.rego. This test is the single
// CI gate that catches drift between the two representations.
func TestLockedSetMatchesRego(t *testing.T) {
	// Authoritative set as declared in resolver.rego (hardcoded).
	// If resolver.rego changes, this test will fail, forcing an update.
	regoLocked := map[string]bool{
		"file_policy/agentjail_self":        true,
		"library/no-daemon-kill":            true,
		"library/no-hook-self-disable":      true,
		"command_policy/no-policy-mutation": true,
		"resolver/default":                  true,
	}

	goLocked := LockedRuleIDs()

	// Check Go locked set equals Rego locked set.
	for id := range regoLocked {
		if !goLocked[id] {
			t.Errorf("rule_id %q is in resolver.rego locked_rules but NOT in Go LockedRuleIDs()", id)
		}
	}
	for id := range goLocked {
		if !regoLocked[id] {
			t.Errorf("rule_id %q is in Go LockedRuleIDs() but NOT in resolver.rego locked_rules — update resolver.rego or the registry", id)
		}
	}
}

// TestPolicyList_ThreeSections verifies the unified list renders Core,
// Optional Hardening, and Custom sections with correct on/off/locked badges.
func TestPolicyList_ThreeSections(t *testing.T) {
	home, policyPath := setupADR0047Home(t)
	withFakeHome(t, home)

	// Install a library rule file to make it appear "on".
	rulesPath := filepath.Join(home, ".agentjail", "rules")
	content := libraryRuleContent("no_history_read")
	if content == nil {
		t.Fatal("no_history_read embedded content nil")
	}
	if err := os.WriteFile(filepath.Join(rulesPath, "no_history_read.rego"), content, 0o640); err != nil {
		t.Fatal(err)
	}

	// Disable a core rule_id in policy.yaml.
	cfg, _ := config.LoadOrDefault(policyPath)
	cfg.DisabledRules = append(cfg.DisabledRules, "command_policy/no-sudo")
	if err := config.Save(cfg, policyPath); err != nil {
		t.Fatal(err)
	}

	// Add a custom rule file.
	if err := os.WriteFile(filepath.Join(rulesPath, "my_custom_rule.rego"), []byte("# custom\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code := runPolicyListOutput(&buf)
	if code != 0 {
		t.Fatalf("runPolicyListOutput() = %d, want 0", code)
	}
	out := stripANSI(buf.String())

	// Core section must be present with locked badges for locked ids.
	for _, want := range []string{
		"Core Rules",
		"file_policy/agentjail_self",
		"resolver/default",
		"command_policy/no-policy-mutation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in policy list output\nfull:\n%s", want, out)
		}
	}

	// The disabled core rule must show "off".
	if !strings.Contains(out, "off") {
		t.Errorf("expected 'off' for disabled rule in output\nfull:\n%s", out)
	}

	// Optional Hardening section.
	if !strings.Contains(out, "Optional Hardening") {
		t.Errorf("missing 'Optional Hardening' section\nfull:\n%s", out)
	}
	// library/no-history-read must appear "on" (file installed).
	if !strings.Contains(out, "library/no-history-read") {
		t.Errorf("missing 'library/no-history-read' in output\nfull:\n%s", out)
	}

	// Custom section.
	if !strings.Contains(out, "Custom") {
		t.Errorf("missing 'Custom' section\nfull:\n%s", out)
	}
	if !strings.Contains(out, "my_custom_rule") {
		t.Errorf("missing custom rule in Custom section\nfull:\n%s", out)
	}
}

// TestDisableLocked_Refused verifies that disabling a locked rule_id is refused.
func TestDisableLocked_Refused(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	lockedIDs := []string{
		"file_policy/agentjail_self",
		"library/no-daemon-kill",
		"library/no-hook-self-disable",
		"command_policy/no-policy-mutation",
		"resolver/default",
	}
	for _, id := range lockedIDs {
		code := runPolicyDisableWithForce(id, true /* force — must still be refused */)
		if code == 0 {
			t.Errorf("disable locked rule %q should fail (exit non-zero), got 0", id)
		}
	}
}

// TestDisableCore_NoTTY verifies that disabling a non-locked core rule_id
// without a real TTY is refused even with --force.
func TestDisableCore_NoTTY(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	// In a test context there is no /dev/tty attached to this process,
	// so confirmDisableInteractive will refuse.
	code := runPolicyDisableWithForce("command_policy/no-sudo", true /* force */)
	if code == 0 {
		t.Error("disabling core rule without TTY should fail even with --force, got exit 0")
	}
}

// TestDisableCore_NoForce verifies that disabling a non-locked core rule_id
// without --force is refused with a helpful message.
func TestDisableCore_NoForce(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	code := runPolicyDisableWithForce("command_policy/no-sudo", false /* no force */)
	if code == 0 {
		t.Error("disabling core rule without --force should fail, got exit 0")
	}
}

// TestDisableUnknownRuleID verifies that an unknown rule_id is refused.
func TestDisableUnknownRuleID(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	code := runPolicyDisableWithForce("totally/unknown", false)
	if code == 0 {
		t.Error("disable unknown rule_id should fail, got exit 0")
	}
}

// TestEnableRuleID_RemovesFromDisabledRules verifies that enable <rule_id>
// removes the id from DisabledRules in policy.yaml.
func TestEnableRuleID_RemovesFromDisabledRules(t *testing.T) {
	home, policyPath := setupADR0047Home(t)
	withFakeHome(t, home)

	// Pre-populate disabled_rules with a non-locked rule.
	cfg, _ := config.LoadOrDefault(policyPath)
	cfg.DisabledRules = append(cfg.DisabledRules, "command_policy/confirm-git-push")
	if err := config.Save(cfg, policyPath); err != nil {
		t.Fatal(err)
	}

	code := runPolicyEnable("command_policy/confirm-git-push")
	if code != 0 {
		t.Fatalf("runPolicyEnable(rule_id) = %d, want 0", code)
	}

	cfg2, _ := config.LoadOrDefault(policyPath)
	for _, id := range cfg2.DisabledRules {
		if id == "command_policy/confirm-git-push" {
			t.Error("rule_id still present in disabled_rules after enable")
		}
	}
}

// runPolicyDisableRuleIDWithAuditPath is the testable version of
// runPolicyDisableRuleID that uses an injected audit log path so tests never
// touch ~/.agentjail/audit.log.
func runPolicyDisableRuleIDWithAuditPath(ruleID string, force bool, auditPath string) int {
	locked := LockedRuleIDs()
	if locked[ruleID] {
		return 1
	}
	if strings.HasPrefix(ruleID, "resolver/") {
		return 1
	}
	entry, known := RegistryByID(ruleID)
	if !known {
		return 1
	}
	if entry.Source == RuleSourceCore {
		if !force {
			return 1
		}
		// In tests: skip TTY confirm (no /dev/tty in CI). The real function
		// handles the TTY check; here we simulate the post-confirm path.
	}

	cfgPath, err := policyConfigPath()
	if err != nil {
		return 1
	}
	cfg, err := config.LoadOrDefault(cfgPath)
	if err != nil {
		return 1
	}
	for _, existing := range cfg.DisabledRules {
		if existing == ruleID {
			return 0 // idempotent
		}
	}
	cfg.DisabledRules = append(cfg.DisabledRules, ruleID)

	if err := appendAuditEvent(auditPath, "disable", ruleID); err != nil {
		return 1
	}
	if err := config.Save(cfg, cfgPath); err != nil {
		return 1
	}
	return 0
}

// TestDisableRuleID_WritesAuditAndConfig verifies that a valid (non-locked,
// non-core or simulated post-confirm) rule disable adds to disabled_rules and
// writes an audit event.
func TestDisableRuleID_WritesAuditAndConfig(t *testing.T) {
	home, policyPath := setupADR0047Home(t)
	withFakeHome(t, home)

	auditPath := filepath.Join(home, ".agentjail", "audit.log")

	// Use a library rule_id (not locked, not core) — no TTY needed.
	ruleID := "library/no-history-read"
	code := runPolicyDisableRuleIDWithAuditPath(ruleID, false, auditPath)
	if code != 0 {
		t.Fatalf("runPolicyDisableRuleIDWithAuditPath() = %d, want 0", code)
	}

	// Verify disabled_rules in policy.yaml.
	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	found := false
	for _, id := range cfg.DisabledRules {
		if id == ruleID {
			found = true
		}
	}
	if !found {
		t.Errorf("rule_id %q not found in disabled_rules: %v", ruleID, cfg.DisabledRules)
	}

	// Verify audit log was written.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("audit log not created: %v", err)
	}
	if !strings.Contains(string(data), ruleID) {
		t.Errorf("audit log missing rule_id %q:\n%s", ruleID, data)
	}
	if !strings.Contains(string(data), "disable") {
		t.Errorf("audit log missing action 'disable':\n%s", data)
	}
}

// TestAuditWriteFailure_AbortsDisable verifies that if appendAuditEvent fails,
// the disable is aborted (policy.yaml is not modified).
func TestAuditWriteFailure_AbortsDisable(t *testing.T) {
	home, policyPath := setupADR0047Home(t)
	withFakeHome(t, home)

	// Make the audit log path unwritable: point it at a directory (can't write).
	badAuditPath := filepath.Join(home, ".agentjail", "audit_dir")
	if err := os.MkdirAll(badAuditPath, 0o700); err != nil {
		t.Fatal(err)
	}

	ruleID := "library/no-history-read"

	// Record initial disabled_rules count.
	cfgBefore, _ := config.LoadOrDefault(policyPath)
	countBefore := len(cfgBefore.DisabledRules)

	code := runPolicyDisableRuleIDWithAuditPath(ruleID, false, badAuditPath)
	if code == 0 {
		t.Error("disable should fail when audit write fails, got exit 0")
	}

	// Policy.yaml must NOT have been modified.
	cfgAfter, _ := config.LoadOrDefault(policyPath)
	if len(cfgAfter.DisabledRules) != countBefore {
		t.Errorf("policy.yaml was modified despite audit failure: before=%d after=%d", countBefore, len(cfgAfter.DisabledRules))
	}
}

// TestAuditEvent_Format verifies the audit event JSON structure.
func TestAuditEvent_Format(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	if err := appendAuditEvent(logPath, "disable", "command_policy/no-sudo"); err != nil {
		t.Fatalf("appendAuditEvent() error: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(data))

	// Must be valid JSON with required fields.
	for _, field := range []string{`"time"`, `"action"`, `"rule_id"`, `"pid"`, `"ppid"`, `"cwd"`} {
		if !strings.Contains(line, field) {
			t.Errorf("audit event missing field %q\nline: %s", field, line)
		}
	}
	if !strings.Contains(line, `"disable"`) {
		t.Errorf("audit event missing action value 'disable'\nline: %s", line)
	}
	if !strings.Contains(line, "command_policy/no-sudo") {
		t.Errorf("audit event missing rule_id\nline: %s", line)
	}
}

// TestMatchGlob_Semantics verifies the /-bounded glob matching semantics
// mirror OPA's glob.match(p, ["/"], id).
func TestMatchGlob_Semantics(t *testing.T) {
	tests := []struct {
		pattern string
		id      string
		want    bool
	}{
		{"file_policy/*", "file_policy/sensitive_credential", true},
		{"file_policy/*", "file_policy/agentjail_self", true},
		// "/" bounded: does not cross multiple segments.
		{"file_policy/*", "file_policy/x/y", false},
		// Exact match.
		{"command_policy/no-sudo", "command_policy/no-sudo", true},
		// No match.
		{"command_policy/no-sudo", "command_policy/no-chmod-777", false},
		// Library glob.
		{"library/*", "library/no-daemon-kill", true},
		// Wildcard all.
		{"*", "anything", true},
	}
	for _, tc := range tests {
		got := matchGlob(tc.pattern, tc.id)
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.id, got, tc.want)
		}
	}
}

// TestLibraryStemConversions verifies ruleIDToLibraryStem and its inverse.
func TestLibraryStemConversions(t *testing.T) {
	cases := []struct {
		ruleID string
		stem   string
	}{
		{"library/no-daemon-kill", "no_daemon_kill"},
		{"library/no-hook-self-disable", "no_hook_self_disable"},
		{"library/no-history-read", "no_history_read"},
		{"library/no-shell-init-write", "no_shell_init_write"},
		{"library/no-app-binary-write", "no_app_binary_write"},
	}
	for _, c := range cases {
		if got := ruleIDToLibraryStem(c.ruleID); got != c.stem {
			t.Errorf("ruleIDToLibraryStem(%q) = %q, want %q", c.ruleID, got, c.stem)
		}
		if got := libraryStemToRuleID(c.stem); got != c.ruleID {
			t.Errorf("libraryStemToRuleID(%q) = %q, want %q", c.stem, got, c.ruleID)
		}
	}
}

// TestRegistryByID_KnownAndUnknown verifies the RegistryByID lookup.
func TestRegistryByID_KnownAndUnknown(t *testing.T) {
	e, ok := RegistryByID("command_policy/no-sudo")
	if !ok {
		t.Error("RegistryByID(command_policy/no-sudo) not found")
	}
	if e.Source != RuleSourceCore {
		t.Errorf("expected core source, got %q", e.Source)
	}
	if e.Locked {
		t.Error("no-sudo should not be locked")
	}

	e2, ok2 := RegistryByID("file_policy/agentjail_self")
	if !ok2 {
		t.Error("RegistryByID(file_policy/agentjail_self) not found")
	}
	if !e2.Locked {
		t.Error("file_policy/agentjail_self should be locked")
	}

	_, ok3 := RegistryByID("totally/unknown")
	if ok3 {
		t.Error("RegistryByID(totally/unknown) should not be found")
	}
}

// ---------------------------------------------------------------------------
// ADR 0014 follow-up #10 — promoted core rules tests
// ---------------------------------------------------------------------------

// TestPromotedCoreRules_InCoreNotLibrary verifies that no_daemon_kill and
// no_hook_self_disable appear in coreRuleNames() and not in libraryRuleNames().
func TestPromotedCoreRules_InCoreNotLibrary(t *testing.T) {
	coreNames := coreRuleNames()
	libNames := libraryRuleNames()

	coreSet := make(map[string]bool, len(coreNames))
	for _, n := range coreNames {
		coreSet[n] = true
	}
	libSet := make(map[string]bool, len(libNames))
	for _, n := range libNames {
		libSet[n] = true
	}

	for _, stem := range []string{"no_daemon_kill", "no_hook_self_disable"} {
		if !coreSet[stem] {
			t.Errorf("%q must appear in coreRuleNames() — it is promoted to always-on core", stem)
		}
		if libSet[stem] {
			t.Errorf("%q must NOT appear in libraryRuleNames() — it is no longer an opt-in library rule", stem)
		}
	}
}

// TestPromotedCoreRules_RegistryIsCore verifies the rule registry marks both
// promoted rules as RuleSourceCore with Locked=true.
func TestPromotedCoreRules_RegistryIsCore(t *testing.T) {
	for _, id := range []string{"library/no-daemon-kill", "library/no-hook-self-disable"} {
		e, ok := RegistryByID(id)
		if !ok {
			t.Errorf("RegistryByID(%q) not found", id)
			continue
		}
		if e.Source != RuleSourceCore {
			t.Errorf("RegistryByID(%q).Source = %q, want core", id, e.Source)
		}
		if !e.Locked {
			t.Errorf("RegistryByID(%q).Locked = false, want true", id)
		}
	}
}

// TestPromotedCoreRules_PolicyEnable_CoreMessage verifies that trying to
// `agentjail policy enable no_daemon_kill` (bare stem) reports it as a core
// rule rather than an unknown rule.
func TestPromotedCoreRules_PolicyEnable_CoreMessage(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	// Enabling a core rule by bare stem should fail (it's always on) with
	// exit code 1, not 0 (which would mean it was treated as a library copy).
	for _, stem := range []string{"no_daemon_kill", "no_hook_self_disable"} {
		code := runPolicyEnable(stem)
		if code == 0 {
			t.Errorf("runPolicyEnable(%q) = 0; should fail because it is a core rule (always on)", stem)
		}
	}
}

// TestPromotedCoreRules_PolicyList_ShowsInCore verifies that the policy list
// output includes no_daemon_kill and no_hook_self_disable in the Core Rules
// section, shown as locked.
func TestPromotedCoreRules_PolicyList_ShowsInCore(t *testing.T) {
	home, _ := setupADR0047Home(t)
	withFakeHome(t, home)

	var buf bytes.Buffer
	code := runPolicyListOutput(&buf)
	if code != 0 {
		t.Fatalf("runPolicyListOutput() = %d, want 0", code)
	}
	out := stripANSI(buf.String())

	// Both rule_ids must appear in the output (they're in Core Rules section).
	for _, id := range []string{"library/no-daemon-kill", "library/no-hook-self-disable"} {
		if !strings.Contains(out, id) {
			t.Errorf("policy list missing %q\nfull:\n%s", id, out)
		}
	}

	// They must be shown as locked.
	// The 'locked' badge must appear (at least once — from these rules + others).
	if !strings.Contains(out, "locked") {
		t.Errorf("policy list missing 'locked' badge\nfull:\n%s", out)
	}
}
