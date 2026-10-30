//go:build linux && nativequalification

package repository

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Exercise the actual terminal join used by the next permission gate, using
// a real persisted intent fixture. No test-generated data grants authority.
func TestCanonicalFloorTerminalForNextPermission(t *testing.T) {
	var terminal model.CapacityIntent
	if err := DecodeQualificationCapacityIntent(capacityIntentFixture(t), &terminal); err != nil {
		t.Fatal(err)
	}
	terminal.Phase = "reconciled_failed_floor"
	terminal.FloorDegraded = true
	terminal.Assessment.Snapshot.Units = 1
	terminal.NativePodBaseline = nil
	current := terminal
	current.Generation++
	current.Phase = "preparing"
	current.BaselineSnapshot.Units = 1
	current.Decision.Reason = "protected_floor_recovery"
	current.Decision.Units = 2
	policy := model.Manifest{ID: terminal.PolicyID, Checksum: terminal.PolicyChecksum}

	encode := func(t *testing.T, intent model.CapacityIntent) []byte {
		t.Helper()
		wire, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := encode(t, terminal)
	var generic model.CapacityIntent
	if capacity.DecodeGuestLifecycle(wire, &generic) == nil {
		t.Fatal("generic decoder must continue refusing the null baseline")
	}
	if got, err := canonicalFloorTerminalForNextPermission(wire, capacity.BusinessCreationSHA256(wire), policy, current); err != nil || got.Generation != terminal.Generation || got.NativePodBaseline != nil {
		t.Fatalf("valid terminal refused: %v", err)
	}

	cases := []struct {
		name   string
		change func(*model.CapacityIntent, *model.CapacityIntent, *model.Manifest)
	}{
		{"policy id", func(_ *model.CapacityIntent, _ *model.CapacityIntent, p *model.Manifest) { p.ID = uuid.New() }},
		{"policy checksum", func(_ *model.CapacityIntent, _ *model.CapacityIntent, p *model.Manifest) { p.Checksum = "different" }},
		{"terminal phase", func(o *model.CapacityIntent, _ *model.CapacityIntent, _ *model.Manifest) { o.Phase = "preparing" }},
		{"terminal floor", func(o *model.CapacityIntent, _ *model.CapacityIntent, _ *model.Manifest) { o.FloorDegraded = false }},
		{"generation", func(_ *model.CapacityIntent, c *model.CapacityIntent, _ *model.Manifest) { c.Generation++ }},
		{"terminal units", func(o *model.CapacityIntent, _ *model.CapacityIntent, _ *model.Manifest) {
			o.Assessment.Snapshot.Units = 2
		}},
		{"baseline units", func(_ *model.CapacityIntent, c *model.CapacityIntent, _ *model.Manifest) {
			c.BaselineSnapshot.Units = 2
		}},
		{"decision reason", func(_ *model.CapacityIntent, c *model.CapacityIntent, _ *model.Manifest) { c.Decision.Reason = "other" }},
		{"decision units", func(_ *model.CapacityIntent, c *model.CapacityIntent, _ *model.Manifest) { c.Decision.Units = 1 }},
		{"current phase", func(_ *model.CapacityIntent, c *model.CapacityIntent, _ *model.Manifest) { c.Phase = "promoted" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, c, p := terminal, current, policy
			tc.change(&o, &c, &p)
			changed := encode(t, o)
			if _, err := canonicalFloorTerminalForNextPermission(changed, capacity.BusinessCreationSHA256(changed), p, c); err != ErrCapacityConflict {
				t.Fatalf("changed terminal join accepted: %v", err)
			}
		})
	}
	t.Run("digest", func(t *testing.T) {
		if _, err := canonicalFloorTerminalForNextPermission(wire, "wrong", policy, current); err != ErrCapacityConflict {
			t.Fatalf("wrong digest accepted: %v", err)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		fields["unexpected"] = json.RawMessage(`1`)
		changed, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := canonicalFloorTerminalForNextPermission(changed, capacity.BusinessCreationSHA256(changed), policy, current); err != ErrCapacityConflict {
			t.Fatalf("unknown field accepted: %v", err)
		}
	})
}

// Scope the syntactic guard to this persisted terminal and its caller; other
// closed lifecycle records must retain their generic decoder.
func TestCanonicalFloorTerminalDecoderCallSite(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "capacity_canonical_source_compensation_qualification.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || (fn.Name.Name != "CanonicalFloorNextPermission" && fn.Name.Name != "canonicalFloorTerminalForNextPermission") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				counts[fn.Name.Name+":"+id.Name]++
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Name.Name == "canonicalFloorTerminalForNextPermission" && sel.Sel.Name == "DecodeGuestLifecycle" {
				t.Error("persisted terminal must not use the generic lifecycle decoder")
			}
			return true
		})
	}
	if counts["CanonicalFloorNextPermission:canonicalFloorTerminalForNextPermission"] != 1 || counts["canonicalFloorTerminalForNextPermission:DecodeQualificationCapacityIntent"] != 1 {
		t.Fatal("terminal gate is not bound to the qualification decoder", counts)
	}
}
