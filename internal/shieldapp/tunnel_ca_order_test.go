//go:build linux

package shieldapp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// CA injection must be the last fallible step before SetMITM: an injected CA
// with no live MITM breaks every TLS handshake (fail-closed, not fail-open).
// Regressed once; structural because reproducing needs an unopenable
// network.db. ADR 0077 (D6).
func TestCAInjectionIsLastFallibleStep(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tunnel_shield_linux.go", nil, 0)
	if err != nil {
		t.Fatalf("parse tunnel_shield_linux.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if g, ok := d.(*ast.FuncDecl); ok && g.Name.Name == "startTunnel" {
			fn = g
			break
		}
	}
	if fn == nil {
		t.Fatal("func startTunnel not found")
	}

	// Walk startTunnel in source order, recording the calls we care about.
	var order []string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == "setupTunnelCA" {
				order = append(order, "injectCA")
			}
		case *ast.SelectorExpr:
			switch f.Sel.Name {
			case "NewRequestStore":
				order = append(order, "openStore")
			case "SetMITM":
				order = append(order, "setMITM")
			}
		}
		return true
	})

	got := strings.Join(order, ",")
	const want = "openStore,injectCA,setMITM"
	if got != want {
		t.Errorf("startTunnel call order = %q, want %q\n"+
			"CA injection replaces the namespace trust store: anything fallible "+
			"between it and SetMITM can leave the agent trusting only agentjail "+
			"with no MITM live, breaking every TLS handshake (ADR 0077 D5).", got, want)
	}
}
