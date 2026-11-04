//go:build linux && nativequalification

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/google/uuid"
)

func TestSourceFailureCleanupStoreExecutionAuthority(t *testing.T) {
	f := &fixture{}
	f.workflow.ID = uuid.New()
	for _, tc := range []struct {
		name, value string
		enabled     bool
	}{
		{"enabled", "true", true},
		{"disabled", "false", false},
		{"empty", "", false},
		{"noncanonical", "TRUE", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", tc.value)
			store := f.sourceFailureCleanupStore()
			if store.ExecutionEnabled != tc.enabled || store.WorkflowID != f.workflow.ID || store.DB != f.db {
				t.Fatalf("unexpected fixture authority: enabled=%v workflow=%s", store.ExecutionEnabled, store.WorkflowID)
			}
		})
	}
}

// The fixture must use the authority-bearing store for both preparation and
// subsequent lease checks. A default-constructed store disables execution.
func TestSourceFailureCleanupStoreCallSite(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "source_compensation.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var caller *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "finishOriginalSourceCompensation" {
			caller = f
		}
	}
	if caller == nil {
		t.Fatal("source compensation caller missing")
	}
	constructed, prepared, checks := 0, 0, 0
	ast.Inspect(caller.Body, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 {
			lhs, l := a.Lhs[0].(*ast.Ident)
			call, c := a.Rhs[0].(*ast.CallExpr)
			if l && c && lhs.Name == "store" {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "sourceFailureCleanupStore" {
					constructed++
				}
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "PrepareSourceFailureCleanup" {
			if len(call.Args) < 2 {
				t.Fatal("missing store argument")
			}
			id, ok := call.Args[1].(*ast.Ident)
			if !ok || id.Name != "store" {
				t.Fatal("preparation does not use source store")
			}
			prepared++
		}
		if sel.Sel.Name == "CheckSourceFailureCleanupLease" {
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "store" {
				t.Fatal("lease does not use source store")
			}
			checks++
		}
		return true
	})
	if constructed != 1 || prepared != 1 || checks != 2 {
		t.Fatalf("construct=%d prepare=%d checks=%d", constructed, prepared, checks)
	}
}
