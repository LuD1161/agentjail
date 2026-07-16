// shipped_rules_schema_test.go — every rule we ship must survive the input
// schema type-check (AGE-218, ADR 0080-rego-both-tiers addendum).
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

// TestEachShippedRuleNamesOnlyKnownInputFields compiles each library rule on
// top of the core baseline individually, so a failure names the offending file
// instead of one aggregate error for the whole bundle.
//
// Core rules are not isolated the same way: they are interdependent (resolver
// reads the candidates), so the smallest unit that compiles is the whole core
// set. Core attribution comes from the compiler, which reports file:line —
// see TestShippedRulesPassSchemaCheck.
func TestEachShippedRuleNamesOnlyKnownInputFields(t *testing.T) {
	baseline := make([][2]string, 0)
	for name, content := range allCoreRuleBytes() {
		baseline = append(baseline, [2]string{name + ".rego", string(content)})
	}

	// The baseline must be known-good before any subtest runs. A bad input.*
	// ref in a CORE rule fails every subtest below, each one naming an innocent
	// library rule that compiles fine — a false accusation, and the exact
	// misattribution this per-file split exists to prevent. Fail once here
	// instead; the compiler error names the real culprit.
	if _, err := policy.NewHookOPAEngine(context.Background(), baseline); err != nil {
		t.Fatalf("core rule baseline (%d modules) does not compile, so the per-library "+
			"subtests are skipped — they would blame an innocent rule.\n"+
			"The error below names the offending core file and line:\n%v", len(baseline), err)
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
			// The baseline compiled above, so this failure is attributable to
			// the one module that was added: libName.
			if strings.Contains(err.Error(), "undefined ref: input.") {
				t.Fatalf("library rule %s references a field the daemon never sends — "+
					"this rule cannot ever have fired:\n%v", libName, err)
			}
			t.Fatalf("library rule %s failed to compile: %v", libName, err)
		})
	}
}
