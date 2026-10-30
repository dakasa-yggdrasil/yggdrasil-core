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
// Scope of the misuse guard: it is syntactic and covers the fixture package
// and internal/capacitynativeqemu. Within a function it marks identifiers
// declared with `var x model.CapacityIntent` or `var x *model.CapacityIntent`,
// and identifiers assigned from `model.CapacityIntent{}`,
// `&model.CapacityIntent{}` or `new(model.CapacityIntent)`, then refuses a
// refused decoder called as decoder(_, &x) or decoder(_, x) on them. It does
// not resolve types through go/types, so struct fields and values of other
// origins are not seen.
func TestNativeFixtureIntentRowsUseQualificationDecoder(t *testing.T) {
	expected := map[nativeIntentSite]int{
		{"canonical_compensation.go", "prepareCanonicalSourceChild"}:   1,
		{"postloss_reissue.go", "reissueCanonicalPostlossChild"}:       1,
		{"source_compensation.go", "finishOriginalSourceCompensation"}: 1,
		{"canonical_recovery_cleanup.go", "recoveryCleanupProof"}:      1,
	}
	found, functions := nativeIntentDecoderScan(t, "../cmd/native-guest-lifecycle-fixture", "DecodeGuestLifecycle")
	if !functions["recoveryCleanupProof"] {
		t.Fatal("recoveryCleanupProof not found")
	}
	if !reflect.DeepEqual(found, expected) {
		t.Fatalf("qualification intent decoder call sites differ:\n got %v\nwant %v", found, expected)
	}
}

// internal/capacitynativeqemu reads the private source-fence capacity_intents
// row only through the closed qualification decoder. Its package-local
// closedJSON routes a struct pointer to the shared Guest lifecycle decoder,
// which refuses the stored null native pod baseline, so it is refused too.
func TestNativeQEMUIntentRowsUseQualificationDecoder(t *testing.T) {
	expected := map[nativeIntentSite]int{
		{"realm_linux.go", "sourceFencePrivateIntent"}: 1,
	}
	found, functions := nativeIntentDecoderScan(t, "../internal/capacitynativeqemu", "DecodeGuestLifecycle", "closedJSON")
	if !functions["sourceFencePrivateIntent"] || !functions["closedJSON"] {
		t.Fatal("sourceFencePrivateIntent or closedJSON not found")
	}
	if !reflect.DeepEqual(found, expected) {
		t.Fatalf("qualification intent decoder call sites differ:\n got %v\nwant %v", found, expected)
	}
	// The decoder guard above is syntactic. Independently of how a new reader
	// would decode, only sourceFencePrivateIntent may name the table at all.
	readers := nativeIntentSQLReaders(t, "../internal/capacitynativeqemu")
	if want := map[nativeIntentSite]int{{"realm_linux.go", "sourceFencePrivateIntent"}: 1}; !reflect.DeepEqual(readers, want) {
		t.Fatalf("capacity_intents readers differ:\n got %v\nwant %v", readers, want)
	}
}

// nativeIntentSQLReaders returns, per function of the non-test Go files of
// dir, the number of string literals that mention capacity_intents. A literal
// outside any function body is reported under the function name "".
func nativeIntentSQLReaders(t *testing.T, dir string) map[nativeIntentSite]int {
	t.Helper()
	fset := token.NewFileSet()
	parsed := closedGuardParseDir(t, fset, dir)
	if len(parsed) == 0 {
		t.Fatalf("no files scanned in %s", dir)
	}
	readers := map[nativeIntentSite]int{}
	for file, f := range parsed {
		for _, decl := range f.Decls {
			name := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				name = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "capacity_intents") {
					readers[nativeIntentSite{file, name}]++
				}
				return true
			})
		}
	}
	return readers
}

type nativeIntentSite struct{ file, function string }

// nativeIntentDecoderScan parses the non-test Go files of dir, fails on any
// refused decoder applied to a capacity intent identifier or value, and
// returns the DecodeQualificationCapacityIntent call sites and the set of
// function names seen.
func nativeIntentDecoderScan(t *testing.T, dir string, refused ...string) (map[nativeIntentSite]int, map[string]bool) {
	t.Helper()
	refusedNames := map[string]bool{}
	for _, name := range refused {
		refusedNames[name] = true
	}
	fset := token.NewFileSet()
	parsed := closedGuardParseDir(t, fset, dir)
	if len(parsed) == 0 {
		t.Fatalf("no files scanned in %s", dir)
	}
	found := map[nativeIntentSite]int{}
	functions := map[string]bool{}
	for file, f := range parsed {
		alias := closedGuardRepositoryImport(f)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			functions[fn.Name.Name] = true
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
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
					if fn.Name.Name == "recoveryCleanupProof" && callee == "Observe" {
						t.Fatalf("%s: recoveryCleanupProof calls the lease-redacting Observe", file)
					}
					if x, ok := fun.X.(*ast.Ident); ok && alias != "" && x.Name == alias && callee == "DecodeQualificationCapacityIntent" {
						found[nativeIntentSite{file, fn.Name.Name}]++
					}
				case *ast.Ident:
					callee = fun.Name
				}
				if refusedNames[callee] && len(call.Args) == 2 {
					target := call.Args[1]
					if u, ok := target.(*ast.UnaryExpr); ok && u.Op == token.AND {
						target = u.X
					}
					if id, ok := target.(*ast.Ident); ok && intents[id.Name] {
						t.Fatalf("%s:%s: capacity intent row decoded by %s", file, fn.Name.Name, callee)
					}
					if nativeFixtureIsCapacityIntentValue(call.Args[1]) {
						t.Fatalf("%s:%s: capacity intent value decoded by %s", file, fn.Name.Name, callee)
					}
				}
				return true
			})
		}
	}
	return found, functions
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
