// shipped_rules_schema_test.go — every rule we ship must survive the input
// schema type-check (AGE-218, ADR 0016 addendum).
//
// This is the check that makes the schema worth having. `agentjail policy add`
// protects rules a user writes from today on; it does nothing for the rules
// already embedded in the binary. A shipped rule with a bad input.* reference
// would be a rule that looks installed, reports healthy in `policy list`, and
// silently never fires — so the shipped set is asserted here, at build time,
// not left to be discovered in the field.
//
// Scope: the embedded core + library trees are the rules the daemon actually
// evaluates (ADR 0009 — cmd/agentjail/policies is the runtime source of
// truth). The agentpolicy/policies/* candidate tree is exercised by `opa test`
// and shares this input shape; the legacy agentjail.default package does NOT
// (it has its own input document, see agentpolicy/internal/policy/policy.go)
// and is correctly out of scope here.
package main

import (
	"context"
	"strings"
	"testing"

	policy "github.com/LuD1161/agentjail/agentpolicy/policy"
)

// TestShippedRulesPassSchemaCheck compiles the full embedded bundle — the same
// module set validateFullBundle builds — under the schema + strict compile.
func TestShippedRulesPassSchemaCheck(t *testing.T) {
	var modules [][2]string
	for name, content := range allCoreRuleBytes() {
		modules = append(modules, [2]string{name + ".rego", string(content)})
	}
	for _, libName := range libraryRuleNames() {
		if content := libraryRuleContent(libName); content != nil {
			modules = append(modules, [2]string{libName + ".rego", string(content)})
		}
	}
	if len(modules) == 0 {
		t.Fatal("no embedded rules found — the embed globs are broken, and this test would pass vacuously")
	}

	if _, err := policy.NewHookOPAEngine(context.Background(), modules); err != nil {
		t.Fatalf("embedded core+library bundle (%d modules) failed the schema/strict compile.\n"+
			"If this names an unknown input.* ref, a SHIPPED rule has been silently doing nothing — "+
			"fix the rule, do not loosen the schema.\n%v", len(modules), err)
	}
}

// TestEachShippedRuleNamesOnlyKnownInputFields compiles each embedded rule on
// top of the core baseline individually, so a failure names the offending file
// instead of one aggregate error for the whole bundle.
func TestEachShippedRuleNamesOnlyKnownInputFields(t *testing.T) {
	core := map[string][]byte{}
	for name, content := range allCoreRuleBytes() {
		core[name] = content
	}

	baseline := make([][2]string, 0, len(core))
	for name, content := range core {
		baseline = append(baseline, [2]string{name + ".rego", string(content)})
	}

	for _, libName := range libraryRuleNames() {
		content := libraryRuleContent(libName)
		if content == nil {
			continue
		}
		t.Run(libName, func(t *testing.T) {
			mods := append(append([][2]string{}, baseline...), [2]string{libName + ".rego", string(content)})
			_, err := policy.NewHookOPAEngine(context.Background(), mods)
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), "undefined ref: input.") {
				t.Fatalf("library rule %s references a field the daemon never sends — "+
					"this rule cannot ever have fired:\n%v", libName, err)
			}
			t.Fatalf("library rule %s failed to compile: %v", libName, err)
		})
	}
}
