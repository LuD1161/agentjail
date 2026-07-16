package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// candidateModule wraps a rule body into a compilable custom-rule module,
// matching the authoring contract enforced by `agentjail policy add`.
func candidateModule(body string) [][2]string {
	return [][2]string{{"t.rego", `package agentjail

import future.keywords.if
import future.keywords.contains

candidate contains r if {
` + body + `
	r := {"action": "deny", "rule_id": "custom/t/x", "reason": "r", "impact": "i"}
}
`}}
}

// TestHookInputSchemaMatchesStruct is the anti-drift guard. The schema is the
// contract Rego is type-checked against; HookInput is the contract the daemon
// actually marshals. If they diverge, a real field becomes un-referenceable
// (or a removed field stays referenceable) and the type check starts lying.
// One source of truth, enforced by construction (ADR 0034).
func TestHookInputSchemaMatchesStruct(t *testing.T) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(hookInputSchemaJSON, &schema); err != nil {
		t.Fatalf("unmarshal embedded schema: %v", err)
	}

	got := make([]string, 0, len(schema.Properties))
	for k := range schema.Properties {
		got = append(got, k)
	}
	sort.Strings(got)

	rt := reflect.TypeOf(HookInput{})
	want := make([]string, 0, rt.NumField())
	for i := range rt.NumField() {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Fatalf("HookInput.%s has no json tag — it would be invisible to Rego", rt.Field(i).Name)
		}
		want = append(want, strings.Split(tag, ",")[0])
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("hookinput.schema.json properties drifted from HookInput json tags\n schema: %v\n struct: %v\n"+
			"Update hookinput.schema.json to match — an unlisted field cannot be referenced from Rego at all.", got, want)
	}
}

// TestSchemaRejectsUnknownInputRef is the regression test for AGE-218: the
// exact failure ADR 0016 accepted as a known cost. Before the schema was
// wired, this module compiled clean, evaluated to undefined, and the rule
// silently never fired.
func TestSchemaRejectsUnknownInputRef(t *testing.T) {
	_, err := NewHookOPAEngine(context.Background(), candidateModule(`	input.aws_accont == "123456789012"`))
	if err == nil {
		t.Fatal("compile succeeded for input.aws_accont — the schema is not being type-checked; " +
			"a typo'd rule would install clean and silently never fire")
	}

	msg := err.Error()
	// The error must be actionable: it names the offending reference...
	if !strings.Contains(msg, "input.aws_accont") {
		t.Errorf("error does not name the offending reference:\n%s", msg)
	}
	// ...and the file + line it appears on.
	if !strings.Contains(msg, "t.rego:7") {
		t.Errorf("error does not name the offending line:\n%s", msg)
	}
	// ...and, usefully, the valid alternatives.
	if !strings.Contains(msg, "aws_account") {
		t.Errorf("error does not suggest the valid field set:\n%s", msg)
	}
}

// TestSchemaAllowsOptionalFields is the counterweight to the test above, and
// the distinction that makes the schema correct rather than merely strict.
// repo_root / aws_account / command_binaries are `omitempty` — they are
// legitimately absent for non-git / non-AWS / non-Bash calls. Referencing an
// absent-but-declared field is a normal, intentional Rego pattern (the rule
// simply doesn't match) and MUST stay legal. A schema that rejected these
// would be worse than no schema at all.
func TestSchemaAllowsOptionalFields(t *testing.T) {
	for _, body := range []string{
		`	input.aws_account == "123456789012"`,
		`	input.repo_root == "/repo"`,
		`	input.command_binaries[_] == "curl"`,
	} {
		if _, err := NewHookOPAEngine(context.Background(), candidateModule(body)); err != nil {
			t.Errorf("optional-field reference rejected — schema is too strict\n body: %s\n err: %v", body, err)
		}
	}
}

// TestSchemaAllowsFreeFormToolInput guards the other legitimate pattern:
// tool_input's key set belongs to the tool (Bash has .command, Write has
// .file_path, an MCP tool has whatever it wants), so it is declared as an
// untyped object and arbitrary sub-keys must remain referenceable.
func TestSchemaAllowsFreeFormToolInput(t *testing.T) {
	for _, body := range []string{
		`	contains(input.tool_input.command, "rm -rf")`,
		`	startswith(input.tool_input.file_path, "/etc")`,
		`	input.tool_input.some_future_mcp_arg == "x"`,
	} {
		if _, err := NewHookOPAEngine(context.Background(), candidateModule(body)); err != nil {
			t.Errorf("tool_input sub-key reference rejected — tool_input must stay free-form\n body: %s\n err: %v", body, err)
		}
	}
}

// TestSchemaTypeChecksFieldTypes shows the schema catches more than typos: a
// field used at the wrong type is also a rule that could never fire.
func TestSchemaTypeChecksFieldTypes(t *testing.T) {
	// command_binaries is array<string>; comparing it to a string is a
	// tautologically-false condition — the rule could never fire. The
	// author almost certainly meant input.command_binaries[_].
	_, err := NewHookOPAEngine(context.Background(), candidateModule(`	input.command_binaries == "curl"`))
	if err == nil {
		t.Error("compile succeeded comparing array<string> to string — a rule that can never fire")
	}
}

// TestSchemaAppliesToEvalNotJustCompile confirms the typed path still
// evaluates correctly end to end — the schema must not change runtime
// semantics for a valid rule, including when an optional field is absent.
func TestSchemaAppliesToEvalNotJustCompile(t *testing.T) {
	eng, err := NewHookOPAEngine(context.Background(), [][2]string{{"t.rego", `package agentjail

import future.keywords.if

default decision = {"action": "allow", "reason": "default", "rule_id": "d"}

decision = {"action": "deny", "reason": "aws prod", "rule_id": "custom/t/aws"} if {
	input.aws_account == "999999999999"
}
`}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// aws_account absent (non-AWS call): the rule must not fire, and eval
	// must not error just because an optional field is missing.
	got, err := eng.Eval(context.Background(), HookInput{HookEvent: "PreToolUse", ToolName: "Bash"})
	if err != nil {
		t.Fatalf("eval with absent optional field: %v", err)
	}
	if got.Action != "allow" {
		t.Errorf("absent aws_account: Action = %q, want %q", got.Action, "allow")
	}

	// aws_account present and matching: the rule fires.
	got, err = eng.Eval(context.Background(), HookInput{HookEvent: "PreToolUse", ToolName: "Bash", AWSAccount: "999999999999"})
	if err != nil {
		t.Fatalf("eval with present optional field: %v", err)
	}
	if got.Action != "deny" {
		t.Errorf("matching aws_account: Action = %q, want %q", got.Action, "deny")
	}
}
