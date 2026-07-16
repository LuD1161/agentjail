package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
)

// hookInputSchemaJSON is the JSON Schema for the OPA `input` document on the
// hook path. It mirrors HookInput's JSON tags; hookinput_schema_test.go
// asserts the two never drift.
//
//go:embed hookinput.schema.json
var hookInputSchemaJSON []byte

// Optional-field note (this is the part that is easy to get wrong):
// OPA's schema→type translation uses a schema's "properties" to build a
// static object type and IGNORES "required". Every declared property is
// therefore addressable from Rego whether or not it is required, which is
// exactly what the omitempty fields (repo_root, aws_account,
// command_binaries) need — they are undefined at eval time for non-git /
// non-AWS / non-Bash calls, and `input.aws_account` must stay a legal
// reference that simply doesn't match. "required" is retained in the schema
// as documentation of the daemon's contract.
//
// The teeth come from the other half of that translation: an object schema
// WITH properties yields a static type with no dynamic property, so a
// reference to any key not listed is a compile-time type error. That is what
// turns `input.aws_accont` from a silent undefined into a failed install.
// Conversely, `tool_input` is declared as a bare {"type": "object"} with no
// properties, which yields a dynamic any→any type, keeping
// `input.tool_input.<whatever>` legal — the key set there belongs to the
// tool, not to us.

var (
	hookSchemaOnce sync.Once
	hookSchemaSet  *ast.SchemaSet
	hookSchemaErr  error
)

// hookInputSchemaSet returns the ast.SchemaSet that types the `input`
// document for every module on the hook path.
//
// The schema is registered at ast.SchemaRootRef (the bare `schema` root), NOT
// at ast.InputRootRef. This is the one non-obvious part of the OPA API: a
// schema at the `schema` root is the compiler's *global* input type
// (ast.Compiler.inputType — see v1/ast/compile.go checkTypes), which is what
// `opa check --schema <file.json>` installs and what type-checks every module
// with no per-rule METADATA annotation. A schema filed under `input` is
// instead only addressable by name from a `# METADATA / schemas:` block, so
// putting it there compiles clean and silently type-checks nothing — the same
// class of silent no-op this whole change exists to eliminate.
//
// Parsed once and reused: the result is read-only and shared across every
// engine build (SIGHUP rebuilds included), so it stays off the reload path's
// cost (ADR 0002).
func hookInputSchemaSet() (*ast.SchemaSet, error) {
	hookSchemaOnce.Do(func() {
		var raw interface{}
		if err := json.Unmarshal(hookInputSchemaJSON, &raw); err != nil {
			hookSchemaErr = fmt.Errorf("parse embedded HookInput schema: %w", err)
			return
		}
		ss := ast.NewSchemaSet()
		ss.Put(ast.SchemaRootRef, raw)
		hookSchemaSet = ss
	})
	return hookSchemaSet, hookSchemaErr
}
