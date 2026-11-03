//go:build linux && nativequalification

package message

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestPG17ReadQualificationIntent(t *testing.T) {
	original, err := os.ReadFile("../../repository/testdata/qualification_capacity_intent_null_baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err = json.Unmarshal(original, &members); err != nil {
		t.Fatal(err)
	}
	if string(members["native_pod_baseline"]) != "null" {
		t.Fatal("fixture must retain the observed null baseline")
	}
	dir := t.TempDir()
	for _, name := range []string{"canonical-floor-terminal-intent.json", "canonical-floor-next-intent.json", "source-live-partial-terminal.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			var generic model.CapacityIntent
			if _, err := q.ReadPrivate(context.Background(), path, &generic); err == nil {
				t.Fatal("generic private decoder unexpectedly accepted null baseline")
			}
			wire, got, err := pg17ReadQualificationIntent(context.Background(), path)
			if err != nil || !bytes.Equal(wire, original) || got.NativePodBaseline != nil {
				t.Fatalf("qualification intent or original bytes lost: %v", err)
			}
		})
	}
	for name, change := range map[string]func(map[string]json.RawMessage){
		"missing baseline": func(m map[string]json.RawMessage) { delete(m, "native_pod_baseline") },
		"null generation":  func(m map[string]json.RawMessage) { m["generation"] = json.RawMessage(`null`) },
		"unknown field":    func(m map[string]json.RawMessage) { m["unexpected"] = json.RawMessage(`1`) },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(original, &m); err != nil {
				t.Fatal(err)
			}
			change(m)
			wire, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "intent.json")
			if err = os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err = pg17ReadQualificationIntent(context.Background(), path); err == nil {
				t.Fatal("invalid intent accepted")
			}
		})
	}
	t.Run("duplicate keys", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "intent.json")
		wire := append([]byte(`{"phase":"preparing",`), original[1:]...)
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := pg17ReadQualificationIntent(context.Background(), path); err == nil {
			t.Fatal("duplicate key accepted")
		}
	})
	t.Run("nofollow and permissions", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "intent.json")
		if err := os.WriteFile(path, original, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := pg17ReadQualificationIntent(context.Background(), path); err == nil {
			t.Fatal("non-private file accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := pg17ReadQualificationIntent(context.Background(), link); err == nil {
			t.Fatal("symlink accepted")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := pg17ReadQualificationIntent(ctx, path); err == nil {
			t.Fatal("cancelled context accepted")
		}
	})
}

func TestPG17CompletedFloorIntentReadCallSites(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "workflows_capacity_pg17_compensation_nativequalification.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "PG17AssertFailedFloorAfterCompletion" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "pg17ReadQualificationIntent" {
				count++
			}
			return true
		})
	}
	if count != 2 {
		t.Fatalf("expected both original intent reads, found %d", count)
	}
}

func TestPG17PartialIntentReadCallSite(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "workflows_capacity_pg17_partial_nativequalification.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "assertPG17OriginalPartial" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "pg17ReadQualificationIntent" {
				count++
			}
			return true
		})
	}
	if count != 1 {
		t.Fatalf("expected the original partial terminal read, found %d", count)
	}
}
