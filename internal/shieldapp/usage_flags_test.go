package shieldapp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// The usage text is a hand-maintained string while the flags are registered
// separately, so the two drift: --tunnel/--mitm/--no-mitm shipped undocumented
// and `-h` denied they existed. Interception posture especially has to be
// discoverable without launching (ADR 0077 D4).
//
// Structural because fs.Usage is a closure inside Run() with a local FlagSet:
// both sides are read from the source instead.
func TestUsageDocumentsEveryRegisteredFlag(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var registered []string
	var usageText strings.Builder

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Bool", "String", "Int":
			// fs.Bool("tunnel", ...) — first arg is the flag name.
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "fs" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if name, err := strconv.Unquote(lit.Value); err == nil {
					registered = append(registered, name)
				}
			}
		case "Fprintln", "Fprintf":
			// Collect every literal printed to stderr; the usage block is the
			// only place this file prints flag documentation.
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						usageText.WriteString(s)
						usageText.WriteString("\n")
					}
				}
			}
		}
		return true
	})

	if len(registered) == 0 {
		t.Fatal("found no registered flags in main.go — test is not reading what it thinks")
	}

	usage := usageText.String()
	for _, name := range registered {
		if !strings.Contains(usage, "--"+name) {
			t.Errorf("flag --%s is registered but absent from the usage text; `-h` would deny it exists", name)
		}
	}
}
