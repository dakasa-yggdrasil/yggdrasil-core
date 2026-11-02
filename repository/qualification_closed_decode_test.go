//go:build linux && nativequalification

package repository

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

// The signed authority row (capacity_source_failure_cleanup_originals,
// authority_wire) Core stored in LAB run e9a48e275adc4df4. The shared Guest
// lifecycle decoder refused its body at canonicalCleanupHistory because the
// qemu and original_disk raw members are objects.
func sourceFailureCleanupFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sourceFailureCleanupBodyFixture(t *testing.T) []byte {
	return sourceFailureCleanupFixture(t, "qualification_source_failure_cleanup_body.json")
}

// A physical record built from the producer type
// (capacitynativeqemu.SourceFailureCleanupPhysical) with the LAB body's qemu
// and original_disk values; the run failed before the physical step.
func sourceFailureCleanupPhysicalFixture(t *testing.T) []byte {
	return sourceFailureCleanupFixture(t, "qualification_source_failure_cleanup_physical.json")
}

func closedMembersOf(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	return members
}

func closedWireOf(t *testing.T, members map[string]json.RawMessage) []byte {
	t.Helper()
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeSourceFailureCleanupBodyAcceptsLabAuthorityBody(t *testing.T) {
	var authority SourceFailureCleanupAuthority
	if err := capacity.DecodeGuestLifecycle(sourceFailureCleanupFixture(t, "qualification_source_failure_cleanup_authority.json"), &authority); err != nil {
		t.Fatalf("LAB authority envelope refused: %v", err)
	}
	raw := sourceFailureCleanupBodyFixture(t)
	if !bytes.Equal(authority.Body, raw) {
		t.Fatal("body fixture is not the LAB authority's signed body")
	}
	// The regression: the shared decoder refuses the real body.
	var shared SourceFailureCleanupBody
	if capacity.DecodeGuestLifecycle(raw, &shared) == nil {
		t.Fatal("shared Guest lifecycle decoder unexpectedly accepts object raw members; the closed decoder is untested")
	}
	var b SourceFailureCleanupBody
	if err := decodeSourceFailureCleanupBody(authority.Body, &b); err != nil {
		t.Fatalf("LAB authority body refused: %v", err)
	}
	if b.Schema != "original_source_recovery_failure_cleanup_authority_v1" || b.Mode != "recovery_failure_cleanup_only" || b.NativeCase != "canonical_postloss_unprotected_failed_create_reissue" || b.Slot != 2 || b.ParentGrantID != "12880aad-e885-4ac4-9ad5-d8649dc13d39" || b.AuthorityID != "b349426d-79d2-43b6-a7de-a4908c883d82" || b.SourceDirectoryDevice != 66305 || b.SourceDirectoryInode != 1392461 || b.BaselineMembers != 1 || b.ProductionQualified || b.PositiveQuiescence {
		t.Fatal("LAB authority body decoded to the wrong operands")
	}
	if b.Recovery == nil || b.Recovery.Schema != "original_source_recovery_cleanup_epoch_v1" || b.Recovery.FencingToken != 3 || !b.Recovery.FreshObservedAt.Equal(time.Date(2026, 10, 29, 7, 58, 46, 494185188, time.UTC)) {
		t.Fatal("recovery epoch not decoded from the wire")
	}
	if !b.IssuedAt.Equal(time.Date(2026, 10, 29, 7, 58, 47, 389184208, time.UTC)) || !b.CleanupDeadline.Equal(b.OriginalProvisioningDeadline) {
		t.Fatal("authority times not decoded from the wire")
	}
	// Signed-body byte comparisons need the exact member bytes.
	if string(b.QEMU) != `{"pid":724,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}` || string(b.OriginalDisk) != `{"device":66305,"inode":1392523}` {
		t.Fatal("raw members are not the wire's exact bytes")
	}
	// sourceFailureCleanupCurrentRead and recoveryNativeIdentity decode the
	// raw members; they must succeed on what the closed decoder returns.
	var process struct {
		PID        int    `json:"pid"`
		PPID       int    `json:"ppid"`
		StartTicks uint64 `json:"start_ticks"`
		StatSHA256 string `json:"stat_sha256"`
	}
	var disk GuestNativeQEMUOriginalDisk
	if capacity.DecodeGuestLifecycle(b.QEMU, &process) != nil || process.PID != 724 || process.PPID != 664 || process.StartTicks != 83188716 || capacity.DecodeGuestLifecycle(b.OriginalDisk, &disk) != nil || disk.Device != 66305 || disk.Inode != 1392523 {
		t.Fatal("raw members not decodable as the producer's typed values")
	}
}

// The original (non-recovery) cleanup body omits the omitempty recovery epoch.
func TestDecodeSourceFailureCleanupBodyAcceptsAbsentRecovery(t *testing.T) {
	members := closedMembersOf(t, sourceFailureCleanupBodyFixture(t))
	delete(members, "recovery")
	members["schema"] = json.RawMessage(`"original_source_failure_cleanup_authority_v1"`)
	var b SourceFailureCleanupBody
	if err := decodeSourceFailureCleanupBody(closedWireOf(t, members), &b); err != nil {
		t.Fatalf("body without recovery refused: %v", err)
	}
	if b.Recovery != nil || b.Schema != "original_source_failure_cleanup_authority_v1" || len(b.QEMU) == 0 {
		t.Fatal("body without recovery decoded to the wrong operands")
	}
}

func TestDecodeSourceFailureCleanupBodyRefusesNonClosedWire(t *testing.T) {
	fixture := sourceFailureCleanupBodyFixture(t)
	withMember := func(name, value string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			members[name] = json.RawMessage(value)
			return closedWireOf(t, members)
		}
	}
	without := func(name string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			delete(members, name)
			return closedWireOf(t, members)
		}
	}
	replace := func(old, new string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			if !bytes.Contains(fixture, []byte(old)) {
				t.Fatalf("fixture lacks %s", old)
			}
			return bytes.Replace(fixture, []byte(old), []byte(new), 1)
		}
	}
	for _, tc := range []struct {
		name string
		wire func(*testing.T) []byte
	}{
		{"extra_key", withMember("extra", `1`)},
		{"missing_qemu", without("qemu")},
		{"missing_original_disk", without("original_disk")},
		{"missing_scalar_key", without("slot")},
		{"missing_bool_key", without("positive_quiescence")},
		{"missing_time_key", without("cleanup_deadline")},
		{"duplicate_key", func(*testing.T) []byte {
			return append([]byte(`{"schema":"original_source_recovery_failure_cleanup_authority_v1",`), fixture[1:]...)
		}},
		{"qemu_nested_duplicate_key", replace(`"qemu":{"pid":724`, `"qemu":{"pid":1,"pid":724`)},
		{"original_disk_nested_duplicate_key", replace(`"original_disk":{"device":66305`, `"original_disk":{"device":1,"device":66305`)},
		{"recovery_nested_duplicate_key", replace(`"recovery":{"schema"`, `"recovery":{"generation":2,"schema"`)},
		{"recovery_nested_missing_key", func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			recovery := closedMembersOf(t, members["recovery"])
			delete(recovery, "fresh_observed_at")
			members["recovery"] = closedWireOf(t, recovery)
			return closedWireOf(t, members)
		}},
		{"recovery_nested_extra_key", func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			recovery := closedMembersOf(t, members["recovery"])
			recovery["extra"] = json.RawMessage(`1`)
			members["recovery"] = closedWireOf(t, recovery)
			return closedWireOf(t, members)
		}},
		{"recovery_null", withMember("recovery", `null`)},
		{"recovery_array", withMember("recovery", `[]`)},
		{"case_folded_key", replace(`"schema":"original_source_recovery_failure_cleanup_authority_v1"`, `"Schema":"original_source_recovery_failure_cleanup_authority_v1"`)},
		{"trailing_bytes", func(*testing.T) []byte { return append(append([]byte{}, fixture...), 'x') }},
		{"trailing_value", func(*testing.T) []byte { return append(append([]byte{}, fixture...), []byte(`{}`)...) }},
		{"qemu_null", withMember("qemu", `null`)},
		{"qemu_string", withMember("qemu", `"qemu"`)},
		{"qemu_array", withMember("qemu", `[]`)},
		{"qemu_number", withMember("qemu", `724`)},
		{"original_disk_null", withMember("original_disk", `null`)},
		{"original_disk_array", withMember("original_disk", `[66305,1392523]`)},
		{"original_disk_bool", withMember("original_disk", `true`)},
		{"qemu_extra_key", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b","extra":1}`)},
		{"qemu_missing_pid", withMember("qemu", `{"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_missing_stat_sha256", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":83188716}`)},
		{"qemu_case_folded_key", withMember("qemu", `{"PID":724,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_pid_null", withMember("qemu", `{"pid":null,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_pid_string", withMember("qemu", `{"pid":"724","ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_start_ticks_negative", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":-1,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_empty_object", withMember("qemu", `{}`)},
		{"original_disk_extra_key", withMember("original_disk", `{"device":66305,"inode":1392523,"extra":1}`)},
		{"original_disk_missing_inode", withMember("original_disk", `{"device":66305}`)},
		{"original_disk_missing_device", withMember("original_disk", `{"inode":1392523}`)},
		{"original_disk_inode_null", withMember("original_disk", `{"device":66305,"inode":null}`)},
		{"original_disk_device_string", withMember("original_disk", `{"device":"66305","inode":1392523}`)},
		{"original_disk_empty_object", withMember("original_disk", `{}`)},
		{"issued_at_null", withMember("issued_at", `null`)},
		{"issued_at_number", withMember("issued_at", `1`)},
		{"schema_null", withMember("schema", `null`)},
		{"slot_string", withMember("slot", `"2"`)},
		{"production_qualified_string", withMember("production_qualified", `"false"`)},
		{"source_directory_device_negative", withMember("source_directory_device", `-1`)},
		{"not_object", func(*testing.T) []byte { return []byte(`[]`) }},
		{"empty_object", func(*testing.T) []byte { return []byte(`{}`) }},
		{"empty", func(*testing.T) []byte { return nil }},
		{"oversized", func(*testing.T) []byte {
			return append(append([]byte{}, fixture[:len(fixture)-1]...), []byte(`,"pad":"`+strings.Repeat("a", capacity.GuestBootstrapLimit)+`"}`)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b SourceFailureCleanupBody
			if err := decodeSourceFailureCleanupBody(tc.wire(t), &b); err == nil {
				t.Fatal("non-closed authority body accepted")
			}
			if !reflect.DeepEqual(b, SourceFailureCleanupBody{}) {
				t.Fatal("refused authority body populated the output")
			}
		})
	}
	if decodeSourceFailureCleanupBody(fixture, nil) == nil {
		t.Fatal("nil output accepted")
	}
}

func TestDecodeSourceFailureCleanupPhysicalAcceptsProducerWire(t *testing.T) {
	raw := sourceFailureCleanupPhysicalFixture(t)
	var shared SourceFailureCleanupPhysical
	if capacity.DecodeGuestLifecycle(raw, &shared) == nil {
		t.Fatal("shared Guest lifecycle decoder unexpectedly accepts object raw members; the closed decoder is untested")
	}
	var f SourceFailureCleanupPhysical
	if err := decodeSourceFailureCleanupPhysical(raw, &f); err != nil {
		t.Fatalf("producer physical record refused: %v", err)
	}
	if f.Schema != "original_source_recovery_failure_cleanup_physical_v1" || f.Scope != "host_owned_recovery_failure_cleanup_only_not_positive_retirement" || f.Slot != 2 || f.OriginalSignal != 9 || f.OriginalWaitCode != -9 || !f.OriginalStderrEOF || f.AbsenceClass != "ENOENT" || f.PositiveQuiescence || f.ProductionQualified || f.OriginalDirectoryCloseReturnedAt.Before(f.OriginalPinStartedAt) {
		t.Fatal("physical record decoded to the wrong operands")
	}
	var b SourceFailureCleanupBody
	if err := decodeSourceFailureCleanupBody(sourceFailureCleanupBodyFixture(t), &b); err != nil {
		t.Fatal(err)
	}
	// ValidateSourceFailureCleanupTerminalTx compares with bytes.Equal and
	// canonicalOwnedPhysicalTx with reflect.DeepEqual.
	if !bytes.Equal(f.QEMU, b.QEMU) || !bytes.Equal(f.OriginalDisk, b.OriginalDisk) || !reflect.DeepEqual(f.QEMU, b.QEMU) || !reflect.DeepEqual(f.OriginalDisk, b.OriginalDisk) || f.ResourceID != b.ResourceID || f.CoreSource != b.CoreSource || f.GuestSource != b.GuestSource {
		t.Fatal("physical raw members do not match the authority body's")
	}
}

func TestDecodeSourceFailureCleanupPhysicalRefusesNonClosedWire(t *testing.T) {
	fixture := sourceFailureCleanupPhysicalFixture(t)
	withMember := func(name, value string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			members[name] = json.RawMessage(value)
			return closedWireOf(t, members)
		}
	}
	without := func(name string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			members := closedMembersOf(t, fixture)
			delete(members, name)
			return closedWireOf(t, members)
		}
	}
	for _, tc := range []struct {
		name string
		wire func(*testing.T) []byte
	}{
		{"extra_key", withMember("extra", `1`)},
		{"recovery_key", withMember("recovery", `{}`)},
		{"missing_qemu", without("qemu")},
		{"missing_original_disk", without("original_disk")},
		{"missing_scalar_key", without("original_signal")},
		{"missing_time_key", without("original_directory_close_returned_at")},
		{"duplicate_key", func(*testing.T) []byte {
			return append([]byte(`{"schema":"original_source_recovery_failure_cleanup_physical_v1",`), fixture[1:]...)
		}},
		{"qemu_nested_duplicate_key", func(*testing.T) []byte {
			return bytes.Replace(fixture, []byte(`"qemu":{"pid":724`), []byte(`"qemu":{"pid":724,"pid":724`), 1)
		}},
		{"case_folded_key", func(*testing.T) []byte {
			return bytes.Replace(fixture, []byte(`"absence_class"`), []byte(`"Absence_class"`), 1)
		}},
		{"trailing_bytes", func(*testing.T) []byte { return append(append([]byte{}, fixture...), 'x') }},
		{"trailing_value", func(*testing.T) []byte { return append(append([]byte{}, fixture...), []byte(`[]`)...) }},
		{"qemu_null", withMember("qemu", `null`)},
		{"qemu_array", withMember("qemu", `[]`)},
		{"original_disk_string", withMember("original_disk", `"disk"`)},
		{"original_disk_null", withMember("original_disk", `null`)},
		{"qemu_extra_key", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b","extra":1}`)},
		{"qemu_missing_pid", withMember("qemu", `{"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_missing_stat_sha256", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":83188716}`)},
		{"qemu_case_folded_key", withMember("qemu", `{"PID":724,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_pid_null", withMember("qemu", `{"pid":null,"ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_pid_string", withMember("qemu", `{"pid":"724","ppid":664,"start_ticks":83188716,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_start_ticks_negative", withMember("qemu", `{"pid":724,"ppid":664,"start_ticks":-1,"stat_sha256":"e0ae57da8bb085943dfae6d2a595e7572cfd18c671fbc9b1d76c8745da605d7b"}`)},
		{"qemu_empty_object", withMember("qemu", `{}`)},
		{"original_disk_extra_key", withMember("original_disk", `{"device":66305,"inode":1392523,"extra":1}`)},
		{"original_disk_missing_inode", withMember("original_disk", `{"device":66305}`)},
		{"original_disk_missing_device", withMember("original_disk", `{"inode":1392523}`)},
		{"original_disk_inode_null", withMember("original_disk", `{"device":66305,"inode":null}`)},
		{"original_disk_device_string", withMember("original_disk", `{"device":"66305","inode":1392523}`)},
		{"original_disk_empty_object", withMember("original_disk", `{}`)},
		{"original_pin_started_at_null", withMember("original_pin_started_at", `null`)},
		{"original_signal_string", withMember("original_signal", `"9"`)},
		{"original_stderr_eof_null", withMember("original_stderr_eof", `null`)},
		{"not_object", func(*testing.T) []byte { return []byte(`"physical"`) }},
		{"empty", func(*testing.T) []byte { return []byte{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f SourceFailureCleanupPhysical
			if err := decodeSourceFailureCleanupPhysical(tc.wire(t), &f); err == nil {
				t.Fatal("non-closed physical record accepted")
			}
			if !reflect.DeepEqual(f, SourceFailureCleanupPhysical{}) {
				t.Fatal("refused physical record populated the output")
			}
		})
	}
	if decodeSourceFailureCleanupPhysical(fixture, nil) == nil {
		t.Fatal("nil output accepted")
	}
}

// The closed member sets are exactly the producer wires', every raw member
// has a declared JSON kind and only recovery is optional.
func TestSourceFailureCleanupClosedMembersMatchProducerWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typ      reflect.Type
		wire     []byte
		members  int
		optional map[string]bool
	}{
		{"body", reflect.TypeOf(SourceFailureCleanupBody{}), sourceFailureCleanupBodyFixture(t), 37, sourceFailureCleanupBodyOptional},
		{"physical", reflect.TypeOf(SourceFailureCleanupPhysical{}), sourceFailureCleanupPhysicalFixture(t), 28, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields, ok := qualificationClosedFields(tc.typ, sourceFailureCleanupRawShapes, tc.optional)
			if !ok || len(fields) != tc.members {
				t.Fatalf("closed member set invalid (%d members)", len(fields))
			}
			wire := closedMembersOf(t, tc.wire)
			if len(wire) != len(fields) {
				t.Fatalf("wire has %d members, closed set %d", len(wire), len(fields))
			}
			for name := range wire {
				if _, ok := fields[name]; !ok {
					t.Fatalf("wire member %s not in the closed set", name)
				}
			}
			for name, shape := range sourceFailureCleanupRawShapes {
				if fields[name] != qualificationRawMessageType || wire[name][0] != shape {
					t.Fatalf("raw member %s does not have its declared kind", name)
				}
			}
		})
	}
}

type closedUndeclaredRaw struct {
	A json.RawMessage `json:"a"`
}
type closedScalar struct {
	A string `json:"a"`
}
type closedNestedRaw struct {
	A struct {
		B json.RawMessage `json:"b"`
	} `json:"a"`
}
type closedOmitempty struct {
	A string `json:"a,omitempty"`
}

// A declaration that does not match its type exactly fails closed, so a later
// field change cannot silently bypass the kind or presence rules.
func TestDecodeQualificationClosedRefusesMismatchedDeclaration(t *testing.T) {
	object := map[string]byte{"a": '{'}
	for _, tc := range []struct {
		name     string
		wire     string
		out      any
		shapes   map[string]byte
		optional map[string]bool
		accept   bool
	}{
		{"declared_raw_accepted", `{"a":{}}`, &closedUndeclaredRaw{}, object, nil, true},
		{"undeclared_raw", `{"a":{}}`, &closedUndeclaredRaw{}, nil, nil, false},
		{"raw_kind_not_json_container", `{"a":"x"}`, &closedUndeclaredRaw{}, map[string]byte{"a": '"'}, nil, false},
		{"declared_kind_for_absent_field", `{"a":{}}`, &closedUndeclaredRaw{}, map[string]byte{"a": '{', "z": '{'}, nil, false},
		{"scalar_accepted", `{"a":"x"}`, &closedScalar{}, nil, nil, true},
		{"kind_declared_on_scalar", `{"a":"x"}`, &closedScalar{}, object, nil, false},
		{"optional_on_required", `{"a":"x"}`, &closedScalar{}, nil, map[string]bool{"a": true}, false},
		{"optional_names_absent_field", `{"a":"x"}`, &closedScalar{}, nil, map[string]bool{"z": true}, false},
		{"nested_raw", `{"a":{"b":{}}}`, &closedNestedRaw{}, nil, nil, false},
		{"omitempty_undeclared", `{"a":"x"}`, &closedOmitempty{}, nil, nil, false},
		{"omitempty_declared_present", `{"a":"x"}`, &closedOmitempty{}, nil, map[string]bool{"a": true}, true},
		{"omitempty_declared_absent", `{}`, &closedOmitempty{}, nil, map[string]bool{"a": true}, true},
		{"omitempty_declared_false", `{"a":"x"}`, &closedOmitempty{}, nil, map[string]bool{"a": false}, false},
		{"not_pointer", `{"a":"x"}`, closedScalar{}, nil, nil, false},
		{"nil_pointer", `{"a":"x"}`, (*closedScalar)(nil), nil, nil, false},
		{"nil_interface", `{"a":"x"}`, nil, nil, nil, false},
		{"pointer_to_non_struct", `{"a":"x"}`, new(map[string]string), nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := decodeQualificationClosed([]byte(tc.wire), tc.out, tc.shapes, tc.optional)
			if tc.accept && err != nil {
				t.Fatalf("matching declaration refused: %v", err)
			}
			if !tc.accept && err == nil {
				t.Fatal("mismatched declaration accepted")
			}
		})
	}
}

// Every qualification site that decodes the source failure cleanup body or
// physical record uses the closed decoders; none may fall back to the shared
// Guest lifecycle decoder (which refuses every RawMessage object). The scan
// covers this package and the packages that consume its cleanup types
// (controllers/message, cmd/native-guest-lifecycle-fixture and
// internal/capacitynativeqemu): today those see the guarded types only through
// this package's own decoders, so any reference to them there must first be
// added to this guard.
func TestSourceFailureCleanupCallSitesUseClosedDecoder(t *testing.T) {
	type site struct{ file, function, decoder, wire string }
	expected := map[site]int{
		{"source_failure_cleanup_terminal_qualification.go", "ValidateSourceFailureCleanupTerminalTx", "decodeSourceFailureCleanupBody", "a.Body"}:    1,
		{"source_failure_cleanup_terminal_qualification.go", "ValidateSourceFailureCleanupTerminalTx", "decodeSourceFailureCleanupPhysical", "pw"}:    1,
		{"capacity_canonical_source_compensation_qualification.go", "canonicalCleanupHistory", "decodeSourceFailureCleanupBody", "body"}:              1,
		{"capacity_canonical_source_compensation_qualification.go", "canonicalOwnedPhysicalTx", "decodeSourceFailureCleanupPhysical", "physicalWire"}: 1,
		{"capacity_failed_floor_source.go", "sourceFloorCapacityTransaction", "decodeSourceFailureCleanupBody", "authority.Body"}:                     1,
		{"qualification_native_read.go", "decodeQualificationNativeRead", "decodeQualificationClosed", "wire"}:                                        1,
		{"qualification_closed_decode.go", "decodeSourceFailureCleanupBody", "decodeQualificationClosed", "wire"}:                                     1,
		{"qualification_closed_decode.go", "decodeSourceFailureCleanupPhysical", "decodeQualificationClosed", "wire"}:                                 1,
	}
	closed := map[string]bool{"decodeSourceFailureCleanupBody": true, "decodeSourceFailureCleanupPhysical": true, "decodeQualificationClosed": true}
	fset := token.NewFileSet()
	parsed := closedGuardParseDir(t, fset, ".")
	found := map[site]int{}
	for file, f := range parsed {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && closed[id.Name] {
					if len(call.Args) < 2 {
						t.Fatalf("%s: %s call without wire and output", file, id.Name)
					}
					found[site{file, fn.Name.Name, id.Name, closedDecoderWireArg(call.Args[0])}]++
				}
				return true
			})
		}
	}
	if !reflect.DeepEqual(found, expected) {
		t.Fatalf("closed decoder call sites differ:\n got %v\nwant %v", found, expected)
	}
	if bad := guestLifecycleGuardedDecodes(parsed, closedGuardTypes, ""); len(bad) != 0 {
		t.Fatalf("guarded types decoded by the Guest lifecycle decoder: %v", bad)
	}
	for _, dir := range []string{"../controllers/message", "../cmd/native-guest-lifecycle-fixture", "../internal/capacitynativeqemu"} {
		consumers := closedGuardParseDir(t, fset, dir)
		if len(consumers) == 0 {
			t.Fatalf("%s: no Go files scanned", dir)
		}
		for file, f := range consumers {
			alias := closedGuardRepositoryImport(f)
			if alias == "" {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == alias && closedGuardTypes[sel.Sel.Name] {
						t.Fatalf("%s/%s: %s.%s referenced outside the closed decoders; extend this guard first", dir, file, alias, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
}

var closedGuardTypes = map[string]bool{"SourceFailureCleanupBody": true, "SourceFailureCleanupPhysical": true, "qualificationNativeRead": true}

const closedGuardRepositoryPath = "github.com/dakasa-yggdrasil/yggdrasil-core/repository"

// The guard's detector flags every shape of a guarded output it can resolve
// syntactically: declared, defined and composite-literal variables, pointers,
// parameters, struct fields, and local aliases or defined types.
func TestGuestLifecycleGuardedDecodesDetectsEveryShape(t *testing.T) {
	const source = `package repository

type bodyAlias = SourceFailureCleanupBody
type bodyDefined SourceFailureCleanupBody
type holder struct {
	Body     SourceFailureCleanupBody
	Physical *SourceFailureCleanupPhysical
	Other    string
}

func varDecl(w []byte)            { var b SourceFailureCleanupBody; capacity.DecodeGuestLifecycle(w, &b) }
func varInit(w []byte)            { var b = SourceFailureCleanupBody{}; capacity.DecodeGuestLifecycle(w, &b) }
func shortDecl(w []byte)          { b := SourceFailureCleanupBody{}; capacity.DecodeGuestLifecycle(w, &b) }
func shortPointer(w []byte)       { b := &SourceFailureCleanupPhysical{}; capacity.DecodeGuestLifecycle(w, b) }
func shortNew(w []byte)           { b := new(qualificationNativeRead); capacity.DecodeGuestLifecycle(w, b) }
func pointerDecl(w []byte)        { var b *SourceFailureCleanupBody; capacity.DecodeGuestLifecycle(w, b) }
func literal(w []byte)            { capacity.DecodeGuestLifecycle(w, &SourceFailureCleanupBody{}) }
func newCall(w []byte)            { capacity.DecodeGuestLifecycle(w, new(SourceFailureCleanupPhysical)) }
func param(w []byte, b *SourceFailureCleanupBody) { capacity.DecodeGuestLifecycle(w, b) }
func valueParam(w []byte, b SourceFailureCleanupBody) { capacity.DecodeGuestLifecycle(w, &b) }
func field(w []byte, h holder)    { capacity.DecodeGuestLifecycle(w, &h.Body) }
func pointerField(w []byte, h holder) { capacity.DecodeGuestLifecycle(w, h.Physical) }
func alias(w []byte)              { var b bodyAlias; capacity.DecodeGuestLifecycle(w, &b) }
func defined(w []byte)            { b := bodyDefined{}; capacity.DecodeGuestLifecycle(w, &b) }
func paren(w []byte)              { var b SourceFailureCleanupBody; capacity.DecodeGuestLifecycle(w, &(b)) }
func closedMirror(w []byte)       { var p sourceFailureCleanupQEMU; capacity.DecodeGuestLifecycle(w, &p) }
func otherField(w []byte, h holder) { capacity.DecodeGuestLifecycle(w, &h.Other) }
`
	const consumer = `package message

import repo "github.com/dakasa-yggdrasil/yggdrasil-core/repository"

func consumerVar(w []byte)   { var b repo.SourceFailureCleanupBody; capacity.DecodeGuestLifecycle(w, &b) }
func consumerShort(w []byte) { b := &repo.SourceFailureCleanupPhysical{}; capacity.DecodeGuestLifecycle(w, b) }
`
	fset := token.NewFileSet()
	parse := func(name, src string) map[string]*ast.File {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]*ast.File{name: f}
	}
	got := map[string]bool{}
	for _, name := range guestLifecycleGuardedDecodes(parse("source.go", source), closedGuardTypes, "") {
		got[name] = true
	}
	files := parse("consumer.go", consumer)
	for _, name := range guestLifecycleGuardedDecodes(files, closedGuardTypes, closedGuardRepositoryImport(files["consumer.go"])) {
		got[name] = true
	}
	want := map[string]bool{}
	for _, fn := range []string{"varDecl", "varInit", "shortDecl", "shortPointer", "shortNew", "pointerDecl", "literal", "newCall", "param", "valueParam", "field", "pointerField", "alias", "defined", "paren"} {
		want["source.go:"+fn] = true
	}
	want["consumer.go:consumerVar"], want["consumer.go:consumerShort"] = true, true
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("guarded decode detector differs:\n got %v\nwant %v", got, want)
	}
}

// closedGuardParseDir parses the non-test Go files of dir.
func closedGuardParseDir(t *testing.T, fset *token.FileSet, dir string) map[string]*ast.File {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string]*ast.File{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed[filepath.Base(file)] = f
	}
	return parsed
}

// closedGuardRepositoryImport returns the local name of this package's import
// in f, or "" when f does not import it.
func closedGuardRepositoryImport(f *ast.File) string {
	for _, spec := range f.Imports {
		if strings.Trim(spec.Path.Value, "`\"") != closedGuardRepositoryPath {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return "repository"
	}
	return ""
}

// guestLifecycleGuardedDecodes returns "file:function" for every
// DecodeGuestLifecycle call whose output resolves syntactically to a guarded
// type. qualifier is "" inside this package, else the local import name the
// guarded types are selected through. Local aliases and defined types of a
// guarded type are guarded too, and so are struct fields of a guarded type.
func guestLifecycleGuardedDecodes(files map[string]*ast.File, guardedNames map[string]bool, qualifier string) []string {
	guarded := map[string]bool{}
	for name := range guardedNames {
		guarded[name] = true
	}
	isGuarded := func(expr ast.Expr) bool {
		for {
			switch e := expr.(type) {
			case *ast.ParenExpr:
				expr = e.X
				continue
			case *ast.StarExpr:
				expr = e.X
				continue
			case *ast.Ident:
				return qualifier == "" && guarded[e.Name] || guarded["."+e.Name]
			case *ast.SelectorExpr:
				x, ok := e.X.(*ast.Ident)
				return ok && qualifier != "" && x.Name == qualifier && guardedNames[e.Sel.Name]
			}
			return false
		}
	}
	// Local aliases and defined types, to a fixpoint.
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				spec, ok := n.(*ast.TypeSpec)
				if !ok || !isGuarded(spec.Type) {
					return true
				}
				key := spec.Name.Name
				if qualifier != "" {
					key = "." + key
				}
				if !guarded[key] {
					guarded[key], changed = true, true
				}
				return true
			})
		}
	}
	fields := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if st, ok := n.(*ast.StructType); ok {
				for _, field := range st.Fields.List {
					if isGuarded(field.Type) {
						for _, name := range field.Names {
							fields[name.Name] = true
						}
					}
				}
			}
			return true
		})
	}
	// guardedValue reports whether expr builds a guarded value or pointer:
	// T{}, &T{} or new(T).
	guardedValue := func(expr ast.Expr) bool {
		if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
			expr = u.X
		}
		switch e := expr.(type) {
		case *ast.CompositeLit:
			return isGuarded(e.Type)
		case *ast.CallExpr:
			id, ok := e.Fun.(*ast.Ident)
			return ok && id.Name == "new" && len(e.Args) == 1 && isGuarded(e.Args[0])
		}
		return false
	}
	var out []string
	for file, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Names bound to a guarded value or pointer in this function.
			typed := map[string]bool{}
			for _, list := range []*ast.FieldList{fn.Recv, fn.Type.Params, fn.Type.Results} {
				if list == nil {
					continue
				}
				for _, field := range list.List {
					if isGuarded(field.Type) {
						for _, name := range field.Names {
							typed[name.Name] = true
						}
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.ValueSpec:
					for i, name := range s.Names {
						if (s.Type != nil && isGuarded(s.Type)) || (i < len(s.Values) && guardedValue(s.Values[i])) {
							typed[name.Name] = true
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range s.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && guardedValue(s.Rhs[i]) {
							typed[id.Name] = true
						}
					}
				}
				return true
			})
			flagged := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || flagged {
					return !flagged
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DecodeGuestLifecycle" || len(call.Args) != 2 {
					return true
				}
				target := call.Args[1]
				for {
					if p, ok := target.(*ast.ParenExpr); ok {
						target = p.X
						continue
					}
					if u, ok := target.(*ast.UnaryExpr); ok && u.Op == token.AND {
						target = u.X
						continue
					}
					break
				}
				switch e := target.(type) {
				case *ast.Ident:
					flagged = typed[e.Name]
				case *ast.SelectorExpr:
					flagged = fields[e.Sel.Name]
				default:
					flagged = guardedValue(call.Args[1]) || guardedValue(target)
				}
				return !flagged
			})
			if flagged {
				out = append(out, file+":"+fn.Name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// The qemu raw member closes against a mirror of the producer's
// capacitynativeqemu.Process (which imports this package, so it is read from
// source); original_disk's producer type is an alias of
// GuestNativeQEMUOriginalDisk.
func TestSourceFailureCleanupQEMUMirrorsProducerProcess(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "internal", "capacitynativeqemu", "original_linux.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var producer []string
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != "Process" {
			return true
		}
		for _, field := range spec.Type.(*ast.StructType).Fields.List {
			typ, ok := field.Type.(*ast.Ident)
			if !ok || len(field.Names) != 1 || field.Tag == nil {
				t.Fatal("producer Process field shape changed")
			}
			producer = append(producer, field.Names[0].Name+" "+typ.Name+" "+strings.Trim(field.Tag.Value, "`"))
		}
		return false
	})
	var mirror []string
	typ := reflect.TypeOf(sourceFailureCleanupQEMU{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		mirror = append(mirror, field.Name+" "+field.Type.String()+" "+string(field.Tag))
	}
	if len(producer) == 0 || !reflect.DeepEqual(producer, mirror) {
		t.Fatalf("qemu mirror differs from the producer Process:\n got %v\nwant %v", mirror, producer)
	}
	diskFile, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "internal", "capacitynativeqemu", "destroy_linux.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliased := false
	ast.Inspect(diskFile, func(n ast.Node) bool {
		if spec, ok := n.(*ast.TypeSpec); ok && spec.Name.Name == "OriginalDisk" && spec.Assign.IsValid() {
			if sel, ok := spec.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "GuestNativeQEMUOriginalDisk" {
				aliased = true
			}
		}
		return true
	})
	if !aliased {
		t.Fatal("producer OriginalDisk is no longer an alias of GuestNativeQEMUOriginalDisk")
	}
}

// closedDecoderWireArg renders a call's wire argument (an identifier or a selector).
func closedDecoderWireArg(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return closedDecoderWireArg(e.X) + "." + e.Sel.Name
	}
	return "?"
}
