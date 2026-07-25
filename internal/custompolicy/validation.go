// Package custompolicy validates the constrained Rego extension surface.
package custompolicy

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

const candidateRule = "candidate"

// ValidateModule permits custom modules to add only candidate entries to the
// agentjail package. Resolver helpers are deliberately not extensible: a
// second rule_disabled body could suppress locked candidates.
func ValidateModule(filename, source string) error {
	module, err := ast.ParseModule(filename, source)
	if err != nil {
		return fmt.Errorf("parse Rego: %w", err)
	}
	if module == nil || module.Package == nil || module.Package.Path.String() != "data.agentjail" {
		return fmt.Errorf("file must declare 'package agentjail'")
	}

	for _, rule := range module.Rules {
		if rule.Default || rule.Else != nil {
			return fmt.Errorf("custom rules cannot declare default or else rules")
		}
		if rule.Head.Ref().String() != candidateRule {
			return fmt.Errorf("custom rules may only declare %q entries; found %q", candidateRule, rule.Head.Ref())
		}
		switch rule.Head.DocKind() {
		case ast.PartialSetDoc, ast.PartialObjectDoc:
			// candidate contains r and candidate[r] are the supported extension forms.
		default:
			return fmt.Errorf("custom rule %q must be a partial candidate entry", rule.Head.Ref())
		}
	}
	return nil
}
