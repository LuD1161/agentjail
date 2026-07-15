package shieldapp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Run must call netns.MaybeRunReexec before anything else. The namespace holder
// and the hardened-exec shim re-enter this binary with a marker arg; if Run
// parses flags first, the holder never assumes its role and the TUN-fd handoff
// dies with "recv fd: EOF" -- the tunnel then fails open to netproxy, silently
// taking HTTP(S) policy with it.
//
// This regressed once already: the cmd/agentjail-shield -> internal/shieldapp
// port dropped the call, because main's thin entrypoint never had it and the
// build stayed green. Asserted structurally rather than behaviourally so it
// fails in CI on any host, with or without userns. ADR 0079, AGE-148.
func TestRunCallsMaybeRunReexecFirst(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var run *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "Run" && fn.Recv == nil {
			run = fn
			break
		}
	}
	if run == nil {
		t.Fatal("func Run not found in main.go")
	}
	if len(run.Body.List) == 0 {
		t.Fatal("func Run has an empty body")
	}

	call, ok := run.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("first statement of Run is %T, want the netns.MaybeRunReexec() call", run.Body.List[0])
	}
	sel, ok := call.X.(*ast.CallExpr)
	if !ok {
		t.Fatalf("first statement of Run is not a call: %T", call.X)
	}
	fn, ok := sel.Fun.(*ast.SelectorExpr)
	if !ok || fn.Sel.Name != "MaybeRunReexec" {
		t.Fatal("first statement of Run must be netns.MaybeRunReexec(); the tunnel's fd handoff breaks without it")
	}
	if pkg, ok := fn.X.(*ast.Ident); !ok || pkg.Name != "netns" {
		t.Fatal("first statement of Run must be netns.MaybeRunReexec(), not another package's")
	}
}
