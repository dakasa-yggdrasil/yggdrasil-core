//go:build linux && nativequalification

package repository

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"testing"
	"time"
)

// Bytes Core itself published (json.Marshal of the provider's
// IndependentReturn) in LAB run cf304c435e1546ab; the shared Guest lifecycle
// decoder refused them because json.RawMessage is not a closed array.
func qualificationNativeReadFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/qualification_core_recovery_fresh_native_read.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func qualificationNativeReadMembersOf(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	return members
}

func qualificationNativeReadWire(t *testing.T, members map[string]json.RawMessage) []byte {
	t.Helper()
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeQualificationNativeReadAcceptsCoreWire(t *testing.T) {
	raw := qualificationNativeReadFixture(t)
	var native qualificationNativeRead
	if err := decodeQualificationNativeRead(raw, &native); err != nil {
		t.Fatalf("real Core native read refused: %v", err)
	}
	if native.Schema != "core_independent_original_qemu_read_v1" || native.QMPPeerPID != 675 || native.OriginalDiskFD != 11 || native.StartedAt.IsZero() || native.ReadReturnedAt.Before(native.StartedAt) || native.CloseReturnedAt.Before(native.ReadReturnedAt) {
		t.Fatal("real Core native read decoded to the wrong operands")
	}
	if !native.CloseReturnedAt.Equal(time.Date(2026, 10, 29, 7, 31, 38, 406670219, time.UTC)) {
		t.Fatal("close return not decoded from the wire")
	}
	members := qualificationNativeReadMembersOf(t, raw)
	// The later identity checks compare decoded values, so each raw member
	// must carry exactly the original member's JSON value.
	for name, got := range map[string]json.RawMessage{"original": native.Original, "before": native.Before, "after": native.After, "original_disk": native.OriginalDisk, "uuid": native.UUID, "status": native.Status, "io": native.IO} {
		var a, b any
		if json.Unmarshal(got, &a) != nil || json.Unmarshal(members[name], &b) != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("raw member %s not preserved", name)
		}
	}
	for _, process := range []json.RawMessage{native.Before, native.After} {
		var actual struct {
			PID        int    `json:"pid"`
			PPID       int    `json:"ppid"`
			StartTicks uint64 `json:"start_ticks"`
			StatSHA256 string `json:"stat_sha256"`
		}
		if json.Unmarshal(process, &actual) != nil || actual.PID == 0 || actual.StartTicks == 0 || len(actual.StatSHA256) != 64 {
			t.Fatal("process identity not decodable from raw member")
		}
	}
}

// The closed member set is exactly the provider wire's, and every raw member
// has a declared JSON kind.
func TestQualificationNativeReadMatchesCoreWireMembers(t *testing.T) {
	members := qualificationNativeReadMembersOf(t, qualificationNativeReadFixture(t))
	allowed := qualificationNativeReadMembers()
	if len(allowed) != 18 || len(members) != len(allowed) {
		t.Fatalf("closed member set has %d members, wire has %d", len(allowed), len(members))
	}
	for name := range members {
		if !allowed[name] {
			t.Fatalf("wire member %s not in the closed set", name)
		}
	}
	raw := reflect.TypeOf(json.RawMessage{})
	shapes := 0
	for _, f := range reflect.VisibleFields(reflect.TypeOf(qualificationNativeRead{})) {
		if f.Type != raw {
			continue
		}
		shapes++
		name := f.Tag.Get("json")
		if _, ok := qualificationNativeReadRawShapes[name]; !ok {
			t.Fatalf("raw member %s has no declared JSON kind", name)
		}
	}
	if shapes != len(qualificationNativeReadRawShapes) {
		t.Fatal("declared JSON kinds do not match the raw members")
	}
}

func TestDecodeQualificationNativeReadRefusesNonClosedWire(t *testing.T) {
	fixture := qualificationNativeReadFixture(t)
	withMember := func(name, value string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			members := qualificationNativeReadMembersOf(t, fixture)
			members[name] = json.RawMessage(value)
			return qualificationNativeReadWire(t, members)
		}
	}
	for _, tc := range []struct {
		name string
		wire func(*testing.T) []byte
	}{
		{"extra_key", withMember("extra", `1`)},
		{"missing_key", func(t *testing.T) []byte {
			members := qualificationNativeReadMembersOf(t, fixture)
			delete(members, "io")
			return qualificationNativeReadWire(t, members)
		}},
		{"missing_scalar_key", func(t *testing.T) []byte {
			members := qualificationNativeReadMembersOf(t, fixture)
			delete(members, "original_disk_fd")
			return qualificationNativeReadWire(t, members)
		}},
		{"duplicate_key", func(*testing.T) []byte {
			return append([]byte(`{"schema":"core_independent_original_qemu_read_v1",`), fixture[1:]...)
		}},
		{"nested_duplicate_key", func(*testing.T) []byte {
			return bytes.Replace(fixture, []byte(`"before":{"pid"`), []byte(`"before":{"pid":1,"pid"`), 1)
		}},
		{"case_folded_key", func(*testing.T) []byte {
			return bytes.Replace(fixture, []byte(`"schema":"core_independent`), []byte(`"Schema":"core_independent`), 1)
		}},
		{"trailing_bytes", func(*testing.T) []byte { return append(append([]byte{}, fixture...), 'x') }},
		{"trailing_value", func(*testing.T) []byte { return append(append([]byte{}, fixture...), []byte(`{}`)...) }},
		{"original_null", withMember("original", `null`)},
		{"original_string", withMember("original", `"original"`)},
		{"original_array", withMember("original", `[]`)},
		{"before_number", withMember("before", `1`)},
		{"io_object", withMember("io", `{}`)},
		{"io_null", withMember("io", `null`)},
		{"started_at_null", withMember("started_at", `null`)},
		{"qmp_peer_pid_string", withMember("qmp_peer_pid", `"675"`)},
		{"not_object", func(*testing.T) []byte { return []byte(`[]`) }},
		{"empty", func(*testing.T) []byte { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var native qualificationNativeRead
			if err := decodeQualificationNativeRead(tc.wire(t), &native); err == nil {
				t.Fatal("non-closed native read accepted")
			}
			if !reflect.DeepEqual(native, qualificationNativeRead{}) {
				t.Fatal("refused native read populated the output")
			}
		})
	}
	if decodeQualificationNativeRead(fixture, nil) == nil {
		t.Fatal("nil output accepted")
	}
}

// Both qualification call sites decode the native read with the closed
// helper; neither may fall back to the shared Guest lifecycle decoder (which
// refuses every RawMessage object) or to a second, drifting struct.
func TestQualificationNativeReadCallSitesUseClosedDecoder(t *testing.T) {
	for file, function := range map[string]string{
		"source_recovery_cleanup_qualification.go":           "CompleteSourceRecoveryCleanupRead",
		"capacity_canonical_postloss_fresh_qualification.go": "AppendCanonicalPostlossFreshRead",
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "decodeQualificationNativeRead" {
						calls++
						if fn.Name.Name != function || len(node.Args) != 2 {
							t.Fatalf("%s: closed native decoder called outside %s", file, function)
						}
						if id, ok := node.Args[0].(*ast.Ident); !ok || id.Name != "nativeWire" {
							t.Fatalf("%s: closed native decoder not given the original wire", file)
						}
					}
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "DecodeGuestLifecycle" {
						for _, arg := range node.Args {
							if id, ok := arg.(*ast.Ident); ok && id.Name == "nativeWire" {
								t.Fatalf("%s: native read decoded by the Guest lifecycle decoder", file)
							}
						}
					}
				case *ast.ValueSpec:
					if fn.Name.Name != function {
						return true
					}
					for _, name := range node.Names {
						if name.Name != "native" {
							continue
						}
						if id, ok := node.Type.(*ast.Ident); !ok || id.Name != "qualificationNativeRead" {
							t.Fatalf("%s: native read is not the shared qualification type", file)
						}
					}
				}
				return true
			})
		}
		if calls != 1 {
			t.Fatalf("%s: closed native decoder call not unique", file)
		}
	}
}

// The recovery-cleanup epoch is later compared with reflect.DeepEqual against
// its own JSON round-trip. A driver time in any zero-offset or local Location,
// normalised with UTC(), must equal what json.Unmarshal of the RFC3339 wire
// returns; without UTC() it does not.
func TestQualificationEpochTimeUTCMatchesJSONRoundTrip(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 34, 56, 789012000, time.UTC)
	roundTrip := func(v time.Time) time.Time {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var decoded time.Time
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for _, loc := range []*time.Location{time.FixedZone("", 0), time.FixedZone("BRT", -3*60*60), time.Local} {
		driver := base.In(loc)
		if !reflect.DeepEqual(driver.UTC(), roundTrip(driver.UTC())) {
			t.Fatalf("%v: UTC-normalised time differs from its JSON round-trip", loc)
		}
	}
	if reflect.DeepEqual(base.In(time.FixedZone("", 0)), roundTrip(base.In(time.FixedZone("", 0)))) {
		t.Fatal("un-normalised FixedZone time unexpectedly equals its round-trip; the UTC() guard is untested")
	}
	if withMonotonic := time.Now(); !reflect.DeepEqual(withMonotonic.UTC(), roundTrip(withMonotonic.UTC())) {
		t.Fatal("UTC() did not strip the monotonic reading")
	}
}
