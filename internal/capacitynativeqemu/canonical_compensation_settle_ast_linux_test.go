//go:build linux && nativequalification

package capacitynativeqemu

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The pre-settlement PG17 hook already performed the single write-once
// Observe for the child (public.capacity_canonical_source_cleanup_reads is
// keyed by child_grant_id). Settle must reuse that stored proof read-only;
// a second Observe fails on the primary key and exits Core.
func TestSettleCanonicalSourceChildReusesStoredObservation(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "canonical_compensation_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var settle *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "SettleCanonicalSourceChild" {
			settle = fn
		}
	}
	if settle == nil {
		t.Fatal("SettleCanonicalSourceChild not found")
	}
	counts := map[string]int{}
	ast.Inspect(settle.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				counts[sel.Sel.Name]++
			}
		}
		return true
	})
	if counts["ObserveCanonicalSourceCompensation"] != 0 {
		t.Fatal("Settle observes again; the write-once read row would be inserted twice")
	}
	if counts["CanonicalSourceCompensationObserved"] != 1 {
		t.Fatalf("Settle must read the stored observation exactly once, got %d", counts["CanonicalSourceCompensationObserved"])
	}
}
