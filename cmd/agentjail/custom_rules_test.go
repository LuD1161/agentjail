// custom_rules_test.go — tests for `agentjail policy add/remove` (ADR 0014 §5).
//
// All tests use t.TempDir() + injected HOME — no real ~/.agentjail/ is touched
// and SIGHUP is never sent to a real daemon (sighupDaemon() is a no-op when
// the daemon is not running).
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- helpers ----------------------------------------------------------------

// writeTempRego writes content to a .rego file in t.TempDir() and returns the
// full path.
func writeTempRego(t *testing.T, stem, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, stem+".rego")
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatalf("writeTempRego: %v", err)
	}
	return p
}

// setupFakeHome creates a fake ~/.agentjail/rules directory, sets HOME to it,
// and returns the fakeHome path and rules path.
func setupFakeHome(t *testing.T) (fakeHome, rulesPath string) {
	t.Helper()
	tmp := t.TempDir()
	fakeHome = filepath.Join(tmp, "home")
	rulesPath = filepath.Join(fakeHome, ".agentjail", "rules")
	if err := os.MkdirAll(rulesPath, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	orig := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", orig) })
	os.Setenv("HOME", fakeHome)
	return
}

// ---- valid custom rule rego -------------------------------------------------

const validCustomRego = `# @rule_id: custom/myrule/no-demo-cmd
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "demo-dangerous")
    r := {
        "action":  "deny",
        "rule_id": "custom/myrule/no-demo-cmd",
        "reason":  "demo dangerous command blocked",
        "impact":  "would run demo dangerous command",
    }
}
`

// ---- TestPolicyAdd_ValidRule -------------------------------------------------

func TestPolicyAdd_ValidRule(t *testing.T) {
	_, rulesPath := setupFakeHome(t)

	p := writeTempRego(t, "myrule", validCustomRego)

	code := runPolicyAdd(p)
	if code != 0 {
		t.Fatalf("runPolicyAdd() = %d, want 0", code)
	}

	// File must be installed.
	installed := filepath.Join(rulesPath, "myrule.rego")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("installed rule not found: %v", err)
	}

	// Policy list must show it under Custom.
	var buf bytes.Buffer
	listCode := runPolicyListOutput(&buf)
	if listCode != 0 {
		t.Fatalf("runPolicyListOutput() = %d, want 0", listCode)
	}
	out := stripANSI(buf.String())
	if !strings.Contains(out, "Custom") {
		t.Errorf("policy list missing 'Custom' section\noutput:\n%s", out)
	}
	if !strings.Contains(out, "custom/myrule/no-demo-cmd") {
		t.Errorf("policy list missing rule_id 'custom/myrule/no-demo-cmd'\noutput:\n%s", out)
	}
}

// ---- TestPolicyAdd_RejectsDecisionDeclaration --------------------------------

func TestPolicyAdd_RejectsDecisionDeclaration(t *testing.T) {
	setupFakeHome(t)

	badRego := `# @rule_id: custom/badfile/my-rule
package agentjail

import future.keywords.if

decision = {"action": "deny", "reason": "bad", "rule_id": "custom/badfile/my-rule"} if {
    input.tool_name == "Bash"
}
`
	p := writeTempRego(t, "badfile", badRego)

	code := runPolicyAdd(p)
	if code == 0 {
		t.Fatal("runPolicyAdd() should have failed (declares decision) but returned 0")
	}
}

// ---- TestPolicyAdd_RejectsNonCustomPrefix ------------------------------------

func TestPolicyAdd_RejectsNonCustomPrefix(t *testing.T) {
	setupFakeHome(t)

	// Uses "file_policy/x" instead of "custom/badprefix/x".
	badRego := `package agentjail

import future.keywords.if
import future.keywords.contains

# @rule_id: custom/badprefix/x

candidate contains r if {
    input.tool_name == "Bash"
    r := {
        "action":  "deny",
        "rule_id": "file_policy/x",
        "reason":  "bad",
        "impact":  "bad",
    }
}
`
	p := writeTempRego(t, "badprefix", badRego)

	code := runPolicyAdd(p)
	if code == 0 {
		t.Fatal("runPolicyAdd() should have failed (uses reserved prefix) but returned 0")
	}
}

// ---- TestPolicyAdd_RejectsWrongNamespacePrefix --------------------------------

// The @rule_id header has prefix but not `custom/<stem>/`.
func TestPolicyAdd_RejectsWrongNamespacePrefix(t *testing.T) {
	setupFakeHome(t)

	// The rule_id uses "custom/other/" not "custom/mywrong/".
	badRego := `# @rule_id: custom/other/my-rule
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "Bash"
    r := {
        "action":  "deny",
        "rule_id": "custom/other/my-rule",
        "reason":  "wrong namespace",
        "impact":  "bad",
    }
}
`
	p := writeTempRego(t, "mywrong", badRego)

	code := runPolicyAdd(p)
	if code == 0 {
		t.Fatal("runPolicyAdd() should have failed (wrong custom namespace prefix) but returned 0")
	}
}

// ---- TestPolicyAdd_RejectsBundleBreakingFile ---------------------------------

// A file that parses alone but breaks the full bundle at OPA compile time
// because it references an undefined function.  This is the kind of error
// that passes the static check (it has a valid package + candidate) but fails
// the full-bundle OPA compile that validateFullBundle performs.
func TestPolicyAdd_RejectsBundleBreakingFile(t *testing.T) {
	setupFakeHome(t)

	// References an undefined OPA built-in — OPA rejects this at
	// PrepareForEval time (rego_type_error: undefined function).
	breakingRego := `# @rule_id: custom/bundle_break/x
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    no_such_builtin_xyz_agentjail_test("trigger")
    r := {
        "action":  "deny",
        "rule_id": "custom/bundle_break/x",
        "reason":  "x",
        "impact":  "x",
    }
}
`
	p := writeTempRego(t, "bundle_break", breakingRego)

	code := runPolicyAdd(p)
	if code == 0 {
		t.Fatal("runPolicyAdd() should have failed (bundle compile error: undefined function) but returned 0")
	}
}

// ---- TestPolicyAdd_RejectsUnknownInputRef -----------------------------------

// The AGE-218 regression test: a rule referencing a field that is not on the
// hook input document must fail to install.
//
// This is the failure ADR 0016 accepted as a known cost. Before the input
// schema was wired, this file installed successfully — it is valid Rego, the
// authoring contract passes, and the bundle compiles. It just never fired.
// A silent no-op is the worst outcome for a security rule: it looks installed
// and reports healthy.
func TestPolicyAdd_RejectsUnknownInputRef(t *testing.T) {
	_, rulesPath := setupFakeHome(t)

	// input.aws_accont — a typo for input.aws_account. This is the verbatim
	// example ADR 0016 used to describe the gap.
	typoRego := `# @rule_id: custom/typo_rule/no-prod-aws
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.aws_accont == "999999999999"
    r := {
        "action":  "deny",
        "rule_id": "custom/typo_rule/no-prod-aws",
        "reason":  "prod AWS account is off limits",
        "impact":  "would touch the prod AWS account",
    }
}
`
	p := writeTempRego(t, "typo_rule", typoRego)

	var code int
	stderr := captureStderr(t, func() { code = runPolicyAdd(p) })

	if code == 0 {
		t.Fatal("runPolicyAdd() = 0 for a rule referencing input.aws_accont — " +
			"the rule would install clean and silently never fire")
	}

	// The error must name the offending reference and its line so the author
	// can act on it without guessing.
	if !strings.Contains(stderr, "input.aws_accont") {
		t.Errorf("stderr does not name the offending reference:\n%s", stderr)
	}
	if !strings.Contains(stderr, "typo_rule.rego:8") {
		t.Errorf("stderr does not name the offending line:\n%s", stderr)
	}
	if !strings.Contains(stderr, "aws_account") {
		t.Errorf("stderr does not list the valid fields:\n%s", stderr)
	}
	// ...and explain why a merely-undefined reference is worth failing on.
	if !strings.Contains(stderr, "never fire") {
		t.Errorf("stderr does not explain the silent-no-op stakes:\n%s", stderr)
	}

	// Fail closed: nothing may land in the rules dir.
	if _, err := os.Stat(filepath.Join(rulesPath, "typo_rule.rego")); !os.IsNotExist(err) {
		t.Error("rejected rule was installed anyway — policy add must fail closed")
	}
}

// The counterweight: the corrected rule installs. Guards against "fixing" the
// test above by rejecting aws_account access altogether. aws_account is
// omitempty and undefined for non-AWS calls, and referencing it must stay
// legal — a schema that rejected it would be worse than no schema.
func TestPolicyAdd_AcceptsOptionalInputRef(t *testing.T) {
	_, rulesPath := setupFakeHome(t)

	okRego := strings.Replace(`# @rule_id: custom/optional_rule/no-prod-aws
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.aws_accont == "999999999999"
    r := {
        "action":  "deny",
        "rule_id": "custom/optional_rule/no-prod-aws",
        "reason":  "prod AWS account is off limits",
        "impact":  "would touch the prod AWS account",
    }
}
`, "aws_accont", "aws_account", 1)

	p := writeTempRego(t, "optional_rule", okRego)
	if code := runPolicyAdd(p); code != 0 {
		t.Fatalf("runPolicyAdd() = %d for a valid input.aws_account reference, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(rulesPath, "optional_rule.rego")); err != nil {
		t.Errorf("valid rule not installed: %v", err)
	}
}

// ---- TestPolicyAdd_RejectsCollisionWithReservedPrefix -----------------------

func TestPolicyAdd_RejectsCollisionWithReservedPrefix(t *testing.T) {
	setupFakeHome(t)

	// Uses "resolver/xxx" which is a reserved prefix.
	badRego := `# @rule_id: custom/collision/my-rule
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "Bash"
    r := {
        "action":  "deny",
        "rule_id": "resolver/my-override",
        "reason":  "bad",
        "impact":  "bad",
    }
}
`
	p := writeTempRego(t, "collision", badRego)

	code := runPolicyAdd(p)
	if code == 0 {
		t.Fatal("runPolicyAdd() should have failed (reserved prefix in rule_id) but returned 0")
	}
}

// ---- TestPolicyRemove_RemovesCustomRule -------------------------------------

func TestPolicyRemove_RemovesCustomRule(t *testing.T) {
	_, rulesPath := setupFakeHome(t)

	// Install a valid rule first.
	p := writeTempRego(t, "myrule", validCustomRego)
	if code := runPolicyAdd(p); code != 0 {
		t.Fatalf("runPolicyAdd() = %d, setup failed", code)
	}

	installed := filepath.Join(rulesPath, "myrule.rego")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("installed rule not found: %v", err)
	}

	// Now remove it.
	code := runPolicyRemove("myrule")
	if code != 0 {
		t.Fatalf("runPolicyRemove() = %d, want 0", code)
	}

	// File must be gone.
	if _, err := os.Stat(installed); !os.IsNotExist(err) {
		t.Errorf("rule file should have been removed but still exists")
	}
}

// ---- TestPolicyRemove_RefusesCoreRule ----------------------------------------

func TestPolicyRemove_RefusesCoreRule(t *testing.T) {
	setupFakeHome(t)

	code := runPolicyRemove("command_policy")
	if code == 0 {
		t.Fatal("runPolicyRemove(command_policy) should have failed but returned 0")
	}
}

// ---- TestPolicyRemove_RefusesLibraryRule -------------------------------------

func TestPolicyRemove_RefusesLibraryRule(t *testing.T) {
	setupFakeHome(t)

	code := runPolicyRemove("no_history_read")
	if code == 0 {
		t.Fatal("runPolicyRemove(no_history_read) should have failed but returned 0")
	}
}

// ---- TestPolicyList_ShowsCustomSection --------------------------------------

func TestPolicyList_ShowsCustomSection(t *testing.T) {
	_, rulesPath := setupFakeHome(t)

	// Write a custom rule file directly into rulesPath (bypass add validation
	// to isolate the list rendering logic).
	ruleContent := `# @rule_id: custom/mylist/test-rule
package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
    input.tool_name == "Bash"
    r := {
        "action":  "deny",
        "rule_id": "custom/mylist/test-rule",
        "reason":  "test",
        "impact":  "test",
    }
}
`
	dst := filepath.Join(rulesPath, "mylist.rego")
	if err := os.WriteFile(dst, []byte(ruleContent), 0o640); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	code := runPolicyListOutput(&buf)
	if code != 0 {
		t.Fatalf("runPolicyListOutput() = %d, want 0", code)
	}

	out := stripANSI(buf.String())
	if !strings.Contains(out, "Custom") {
		t.Errorf("policy list missing 'Custom' section\noutput:\n%s", out)
	}
	if !strings.Contains(out, "custom/mylist/test-rule") {
		t.Errorf("policy list missing rule_id 'custom/mylist/test-rule'\noutput:\n%s", out)
	}
	if !strings.Contains(out, "on") {
		t.Errorf("policy list should show status 'on' for custom rule\noutput:\n%s", out)
	}
}

// ---- TestExtractRuleIDs -----------------------------------------------------

func TestExtractRuleIDs(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantIDs []string
	}{
		{
			name: "header only",
			src:  "# @rule_id: custom/foo/bar\npackage agentjail\n",
			wantIDs: []string{"custom/foo/bar"},
		},
		{
			name: "literal only",
			src:  `package agentjail
candidate contains r if {
    r := {"rule_id": "custom/foo/baz", "action": "deny", "reason": "x", "impact": "x"}
}
`,
			wantIDs: []string{"custom/foo/baz"},
		},
		{
			name: "both header and literal (deduped)",
			src:  "# @rule_id: custom/foo/bar\npackage agentjail\n" + `candidate contains r if { r := {"rule_id": "custom/foo/bar"} }`,
			wantIDs: []string{"custom/foo/bar"},
		},
		{
			name:    "literal in comment (skipped)",
			src:     "# \"rule_id\": \"custom/foo/commented\"\npackage agentjail\n",
			wantIDs: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := extractRuleIDs(c.src)
			if len(ids) != len(c.wantIDs) {
				t.Fatalf("extractRuleIDs() = %v, want %v", ids, c.wantIDs)
			}
			for i := range ids {
				if ids[i] != c.wantIDs[i] {
					t.Errorf("ids[%d] = %q, want %q", i, ids[i], c.wantIDs[i])
				}
			}
		})
	}
}

// ---- TestEnforceAuthoringContract -------------------------------------------

func TestEnforceAuthoringContract_MissingPackage(t *testing.T) {
	err := enforceAuthoringContract("# @rule_id: custom/foo/x\n", "foo")
	if err == nil {
		t.Fatal("expected error for missing package declaration")
	}
}

func TestEnforceAuthoringContract_DecisionDeclaration(t *testing.T) {
	src := "# @rule_id: custom/foo/x\npackage agentjail\ndecision = {}\n"
	err := enforceAuthoringContract(src, "foo")
	if err == nil {
		t.Fatal("expected error for decision declaration")
	}
}

func TestEnforceAuthoringContract_NoRuleIDs(t *testing.T) {
	src := "package agentjail\n"
	err := enforceAuthoringContract(src, "foo")
	if err == nil {
		t.Fatal("expected error when no rule_ids found")
	}
}

func TestEnforceAuthoringContract_ValidFile(t *testing.T) {
	err := enforceAuthoringContract(validCustomRego, "myrule")
	if err != nil {
		t.Fatalf("expected no error for valid file, got: %v", err)
	}
}
