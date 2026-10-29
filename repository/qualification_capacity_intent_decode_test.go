//go:build linux && nativequalification

package repository

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// The raw public.capacity_intents.intent row Core stored in LAB run
// a31e59c1eefa4647. Its nil native pod baseline is stored as JSON null, which
// the shared Guest lifecycle decoder refuses.
func capacityIntentFixture(t *testing.T) []byte {
	return sourceFailureCleanupFixture(t, "qualification_capacity_intent_null_baseline.json")
}

func capacityIntentWithMember(t *testing.T, name string, value string) []byte {
	t.Helper()
	members := closedMembersOf(t, capacityIntentFixture(t))
	members[name] = json.RawMessage(value)
	return closedWireOf(t, members)
}

func TestDecodeQualificationCapacityIntentAcceptsLabNullBaselineRow(t *testing.T) {
	wire := capacityIntentFixture(t)
	var shared model.CapacityIntent
	if capacity.DecodeGuestLifecycle(wire, &shared) == nil {
		t.Fatal("the shared Guest lifecycle decoder unexpectedly accepts the null baseline row")
	}
	var got model.CapacityIntent
	if err := DecodeQualificationCapacityIntent(wire, &got); err != nil {
		t.Fatalf("LAB intent row refused: %v", err)
	}
	if got.NativePodBaseline != nil {
		t.Fatalf("null baseline decoded as %#v, want nil", got.NativePodBaseline)
	}
	var want model.CapacityIntent
	if err := json.Unmarshal(wire, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded intent differs from json.Unmarshal of the original wire:\n got %#v\nwant %#v", got, want)
	}
	if got.LeaseOwner != "be594c25-9d99-4037-8195-6843c660f55b" || got.LeaseExecutorID != "481bfd03-5234-471a-95de-fc6810ab0fa8" || !got.RecoveryOnly || got.Generation != 2 || got.FencingToken != 3 || got.LeaseExpiresAt == nil {
		t.Fatalf("unredacted lease identity lost: %#v", got)
	}
}

func TestDecodeQualificationCapacityIntentPreservesEmptyAndNonEmptyBaseline(t *testing.T) {
	var empty model.CapacityIntent
	if err := DecodeQualificationCapacityIntent(capacityIntentWithMember(t, "native_pod_baseline", `[]`), &empty); err != nil {
		t.Fatalf("empty baseline refused: %v", err)
	}
	if empty.NativePodBaseline == nil || len(empty.NativePodBaseline) != 0 {
		t.Fatalf("empty baseline decoded as %#v, want non-nil []", empty.NativePodBaseline)
	}
	var one model.CapacityIntent
	if err := DecodeQualificationCapacityIntent(capacityIntentWithMember(t, "native_pod_baseline", `["a"]`), &one); err != nil {
		t.Fatalf("baseline [\"a\"] refused: %v", err)
	}
	if !reflect.DeepEqual(one.NativePodBaseline, []string{"a"}) {
		t.Fatalf("baseline decoded as %#v", one.NativePodBaseline)
	}
}

func TestDecodeQualificationCapacityIntentRefusesNonClosedWire(t *testing.T) {
	base := capacityIntentFixture(t)
	members := closedMembersOf(t, base)
	cases := map[string][]byte{}
	for name := range members {
		if name == "native_pod_baseline" {
			continue
		}
		cases["null "+name] = capacityIntentWithMember(t, name, `null`)
	}
	for name := range qualificationCapacityIntentOptional {
		cases["null optional "+name] = capacityIntentWithMember(t, name, `null`)
	}
	for _, name := range []string{"namespace", "policy_id", "generation", "fencing_token", "phase", "recovery_only", "native_hpa_generation", "native_pod_baseline", "baseline_snapshot", "decision", "assessment", "updated_at", "policy_name", "policy_checksum", "environment", "domain", "dimension"} {
		missing := closedMembersOf(t, base)
		delete(missing, name)
		cases["missing "+name] = closedWireOf(t, missing)
	}
	cases["unknown member"] = capacityIntentWithMember(t, "unexpected", `1`)
	cases["duplicate top-level member"] = []byte(strings.Replace(string(base), `{"phase": "preparing",`, `{"phase": "preparing", "phase": "preparing",`, 1))
	cases["duplicate nested member"] = []byte(strings.Replace(string(base), `"decision": {"clock": {`, `"decision": {"floor": 1, "clock": {`, 1))
	cases["unknown nested member"] = []byte(strings.Replace(string(base), `"decision": {"clock": {`, `"decision": {"extra": 1, "clock": {`, 1))
	cases["trailing data"] = append(append([]byte{}, base...), []byte(` {}`)...)
	cases["baseline number element"] = capacityIntentWithMember(t, "native_pod_baseline", `[1]`)
	cases["baseline null element"] = capacityIntentWithMember(t, "native_pod_baseline", `["a",null]`)
	cases["baseline object element"] = capacityIntentWithMember(t, "native_pod_baseline", `[{}]`)
	cases["baseline string"] = capacityIntentWithMember(t, "native_pod_baseline", `"a"`)
	cases["baseline object"] = capacityIntentWithMember(t, "native_pod_baseline", `{}`)
	cases["typed scalar mismatch"] = capacityIntentWithMember(t, "generation", `"2"`)
	cases["array wire"] = []byte(`[]`)
	cases["null wire"] = []byte(`null`)
	cases["empty wire"] = nil
	for name, wire := range cases {
		if strings.Contains(name, "duplicate") || strings.Contains(name, "unknown nested") {
			if string(wire) == string(base) {
				t.Fatalf("%s: fixture replacement did not apply", name)
			}
		}
		sentinel := model.CapacityIntent{Phase: "untouched"}
		if err := DecodeQualificationCapacityIntent(wire, &sentinel); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if sentinel.Phase != "untouched" {
			t.Fatalf("%s: output written on refusal", name)
		}
	}
	if DecodeQualificationCapacityIntent(base, nil) == nil {
		t.Fatal("nil output accepted")
	}
}

// The optional declaration must stay exactly the omitempty member set of
// model.CapacityIntent, and native_pod_baseline must stay a required []string.
func TestQualificationCapacityIntentDeclarationMatchesModel(t *testing.T) {
	fields, ok := qualificationClosedFields(reflect.TypeOf(model.CapacityIntent{}), nil, qualificationCapacityIntentOptional)
	if !ok {
		t.Fatal("optional declaration differs from the model's omitempty members")
	}
	if fields[qualificationCapacityIntentNullableBaseline] != reflect.TypeOf([]string{}) || qualificationCapacityIntentOptional[qualificationCapacityIntentNullableBaseline] {
		t.Fatal("native_pod_baseline must be a required []string")
	}
}

// The native fixture reads raw capacity_intents rows only through the closed
// qualification decoder, and recoveryCleanupProof reads the unredacted row
// instead of the public, lease-redacting Observe.
//
// Scope of the misuse guard: it is syntactic and covers only this fixture
// package. Within a function it marks identifiers declared with
// `var x model.CapacityIntent` or `var x *model.CapacityIntent`, and
// identifiers assigned from `model.CapacityIntent{}`, `&model.CapacityIntent{}`
// or `new(model.CapacityIntent)`, then refuses DecodeGuestLifecycle(_, &x) or
// DecodeGuestLifecycle(_, x) on them. It does not resolve types through
// go/types, so struct fields and values of other origins are not seen, and
// internal/capacitynativeqemu (whose realm_linux.go is pinned by the LAB
// overlay and still decodes the private intent with the shared decoder) is
// not scanned.
func TestNativeFixtureIntentRowsUseQualificationDecoder(t *testing.T) {
	type site struct{ file, function string }
	expected := map[site]int{
		{"canonical_compensation.go", "prepareCanonicalSourceChild"}:   1,
		{"postloss_reissue.go", "reissueCanonicalPostlossChild"}:       1,
		{"source_compensation.go", "finishOriginalSourceCompensation"}: 1,
		{"canonical_recovery_cleanup.go", "recoveryCleanupProof"}:      1,
	}
	fset := token.NewFileSet()
	parsed := closedGuardParseDir(t, fset, "../cmd/native-guest-lifecycle-fixture")
	if len(parsed) == 0 {
		t.Fatal("no fixture files scanned")
	}
	found := map[site]int{}
	recoveryProofSeen := false
	for file, f := range parsed {
		alias := closedGuardRepositoryImport(f)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			intents := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.ValueSpec:
					if nativeFixtureIsCapacityIntent(v.Type) {
						for _, name := range v.Names {
							intents[name.Name] = true
						}
					}
					for i, value := range v.Values {
						if i < len(v.Names) && nativeFixtureIsCapacityIntentValue(value) {
							intents[v.Names[i].Name] = true
						}
					}
				case *ast.AssignStmt:
					for i, value := range v.Rhs {
						if i >= len(v.Lhs) || !nativeFixtureIsCapacityIntentValue(value) {
							continue
						}
						if id, ok := v.Lhs[i].(*ast.Ident); ok {
							intents[id.Name] = true
						}
					}
				}
				return true
			})
			if fn.Name.Name == "recoveryCleanupProof" {
				recoveryProofSeen = true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if fn.Name.Name == "recoveryCleanupProof" && sel.Sel.Name == "Observe" {
					t.Fatalf("%s: recoveryCleanupProof calls the lease-redacting Observe", file)
				}
				if x, ok := sel.X.(*ast.Ident); ok && alias != "" && x.Name == alias && sel.Sel.Name == "DecodeQualificationCapacityIntent" {
					found[site{file, fn.Name.Name}]++
				}
				if sel.Sel.Name == "DecodeGuestLifecycle" && len(call.Args) == 2 {
					target := call.Args[1]
					if u, ok := target.(*ast.UnaryExpr); ok && u.Op == token.AND {
						target = u.X
					}
					if id, ok := target.(*ast.Ident); ok && intents[id.Name] {
						t.Fatalf("%s:%s: capacity intent row decoded by the shared Guest lifecycle decoder", file, fn.Name.Name)
					}
					if nativeFixtureIsCapacityIntentValue(call.Args[1]) {
						t.Fatalf("%s:%s: capacity intent value decoded by the shared Guest lifecycle decoder", file, fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	if !recoveryProofSeen {
		t.Fatal("recoveryCleanupProof not found")
	}
	if !reflect.DeepEqual(found, expected) {
		t.Fatalf("qualification intent decoder call sites differ:\n got %v\nwant %v", found, expected)
	}
}

// nativeFixtureIsCapacityIntentValue reports model.CapacityIntent{...},
// &model.CapacityIntent{...} and new(model.CapacityIntent).
func nativeFixtureIsCapacityIntentValue(expr ast.Expr) bool {
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = u.X
	}
	switch v := expr.(type) {
	case *ast.CompositeLit:
		return nativeFixtureIsCapacityIntent(v.Type)
	case *ast.CallExpr:
		id, ok := v.Fun.(*ast.Ident)
		return ok && id.Name == "new" && len(v.Args) == 1 && nativeFixtureIsCapacityIntent(v.Args[0])
	}
	return false
}

func nativeFixtureIsCapacityIntent(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "model" && sel.Sel.Name == "CapacityIntent"
}

func TestCanonicalSourceRedeemChildBound(t *testing.T) {
	workflow := uuid.New()
	executor := uuid.NewString()
	parentID, childID, sha := uuid.NewString(), uuid.NewString(), "eligibility-sha"
	parent := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: parentID}, WorkflowID: workflow, Generation: 2}
	child := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: childID, CompensationOf: parentID}, WorkflowID: workflow, Generation: 2, ExecutorID: executor}
	if !canonicalSourceRedeemChildBound(child, parent, childID, parentID, sha, sha, executor) {
		t.Fatal("exact canonical child refused")
	}
	type mutation struct {
		name                                     string
		child, parent                            capacityMutationRecord
		childID, linked, linkedSHA, sha, recover string
	}
	mutate := func(name string, f func(m *mutation)) mutation {
		m := mutation{name: name, child: child, parent: parent, childID: childID, linked: parentID, linkedSHA: sha, sha: sha, recover: executor}
		f(&m)
		return m
	}
	for _, m := range []mutation{
		mutate("empty child id", func(m *mutation) { m.childID = "" }),
		mutate("other child id", func(m *mutation) { m.childID = uuid.NewString() }),
		mutate("not a compensation", func(m *mutation) { m.child.Grant.CompensationOf = "" }),
		mutate("compensation of another parent", func(m *mutation) { m.child.Grant.CompensationOf = uuid.NewString() }),
		mutate("empty parent id", func(m *mutation) { m.parent.Grant.GrantID = ""; m.child.Grant.CompensationOf = ""; m.linked = "" }),
		mutate("child is the parent", func(m *mutation) {
			m.child.Grant.GrantID = parentID
			m.childID = parentID
			m.child.Grant.CompensationOf = parentID
		}),
		mutate("unlinked child", func(m *mutation) { m.linked = uuid.NewString() }),
		mutate("other eligibility", func(m *mutation) { m.linkedSHA = "other" }),
		mutate("empty eligibility", func(m *mutation) { m.linkedSHA, m.sha = "", "" }),
		mutate("other workflow", func(m *mutation) { m.child.WorkflowID = uuid.New() }),
		mutate("nil workflows", func(m *mutation) { m.child.WorkflowID, m.parent.WorkflowID = uuid.Nil, uuid.Nil }),
		mutate("other generation", func(m *mutation) { m.child.Generation = m.parent.Generation + 1 }),
		mutate("earlier generation", func(m *mutation) { m.child.Generation = m.parent.Generation - 1 }),
		mutate("invalid executor", func(m *mutation) { m.child.ExecutorID, m.recover = "not-a-uuid", "not-a-uuid" }),
		mutate("nil executor", func(m *mutation) { m.child.ExecutorID, m.recover = uuid.Nil.String(), uuid.Nil.String() }),
		mutate("other recovery executor", func(m *mutation) { m.recover = uuid.NewString() }),
	} {
		if canonicalSourceRedeemChildBound(m.child, m.parent, m.childID, m.linked, m.linkedSHA, m.sha, m.recover) {
			t.Fatalf("%s: accepted", m.name)
		}
	}
}

// A scoped store, or an unscoped store without a child, is returned unchanged
// without touching the transaction.
func TestCanonicalSourceRedeemLeaseStoreKeepsScopedStore(t *testing.T) {
	scoped := CapacityStore{WorkflowID: uuid.New(), ExecutorID: uuid.NewString()}
	got, err := scoped.canonicalSourceRedeemLeaseStoreTx(context.Background(), nil, capacityMutationRecord{}, uuid.NewString(), "sha", uuid.NewString())
	if err != nil || got.WorkflowID != scoped.WorkflowID || got.ExecutorID != scoped.ExecutorID {
		t.Fatalf("scoped store changed: %v %#v", err, got)
	}
	unscoped := CapacityStore{}
	got, err = unscoped.canonicalSourceRedeemLeaseStoreTx(context.Background(), nil, capacityMutationRecord{}, "", "sha", uuid.NewString())
	if err != nil || got.WorkflowID != uuid.Nil {
		t.Fatalf("unscoped store without a child changed: %v %#v", err, got)
	}
}
