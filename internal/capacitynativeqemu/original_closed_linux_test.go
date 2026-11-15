//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Structural parser inputs only: no process, QMP socket, provider call, source
// override or original lifecycle is supplied by these Go tests. The zero native
// lifetime deliberately cannot pass CheckCreator after its wire is decoded.
func originalClosedCreatorWire(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(CreatorReturn{OriginalIO: []OriginalIO{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func originalClosedIndependentWire(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(IndependentReturn{Original: CreatorReturn{OriginalIO: []OriginalIO{}}, IO: []OriginalIO{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOriginalNativeQEMUClosedSourceBytes(t *testing.T) {
	creator := originalClosedCreatorWire(t)
	t.Run("complete_struct_requires_explicit_false", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON(creator, &decoded) != nil || decoded.NativeStatusReadback.SingleStep || decoded.OriginalClosesReturned || decoded.OriginalIO == nil {
			t.Fatal("explicit false/empty native structural facts lost")
		}
	})
	t.Run("typed_wire_is_not_original_native_proof", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON(creator, &decoded) != nil {
			t.Fatal("closed structural input unexpectedly refused")
		}
		at := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
		if CheckCreator(decoded, 2, "", "", "", "", at, at.Add(time.Second), at.Add(2*time.Second)) == nil {
			t.Fatal("typed metadata became an original QEMU create proof")
		}
	})
	for _, name := range []string{"omitted_singlestep", "null_singlestep", "singlestep_alias", "singlestep_fold_duplicate", "singlestep_duplicate", "unknown_nested_status", "unknown_nested_lifetime", "unknown_nested_peer", "omitted_original_close", "null_original_io", "omitted_original_io", "uuid_case_alias", "trailing_record", "root_array", "root_null", "wire_oversize"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), creator...)
			switch name {
			case "omitted_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false,`), nil, 1)
			case "null_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":null`), 1)
			case "singlestep_alias":
				raw = bytes.Replace(raw, []byte(`"singlestep":`), []byte(`"SingleStep":`), 1)
			case "singlestep_fold_duplicate":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":false,"SingleStep":false`), 1)
			case "singlestep_duplicate":
				raw = bytes.Replace(raw, []byte(`"singlestep":false`), []byte(`"singlestep":false,"singlestep":false`), 1)
			case "unknown_nested_status":
				raw = bytes.Replace(raw, []byte(`"native_status_readback":{`), []byte(`"native_status_readback":{"caller_complete":true,`), 1)
			case "unknown_nested_lifetime":
				raw = bytes.Replace(raw, []byte(`"qemu":{`), []byte(`"qemu":{"native_verified":true,`), 1)
			case "unknown_nested_peer":
				raw = bytes.Replace(raw, []byte(`"qmp_original_peer":{`), []byte(`"qmp_original_peer":{"same_owner":true,`), 1)
			case "omitted_original_close":
				raw = bytes.Replace(raw, []byte(`"original_closes_returned":false,`), nil, 1)
			case "null_original_io":
				raw = bytes.Replace(raw, []byte(`"original_io":[]`), []byte(`"original_io":null`), 1)
			case "omitted_original_io":
				raw = bytes.Replace(raw, []byte(`"original_io":[],`), nil, 1)
			case "uuid_case_alias":
				raw = bytes.Replace(raw, []byte(`"UUID":`), []byte(`"uuid":`), 1)
			case "trailing_record":
				raw = append(raw, []byte(`{}`)...)
			case "root_array":
				raw = []byte(`[]`)
			case "root_null":
				raw = []byte(`null`)
			case "wire_oversize":
				raw = append(raw, []byte(strings.Repeat(" ", capacity.GuestBootstrapLimit))...)
			}
			var decoded CreatorReturn
			if closedJSON(raw, &decoded) == nil {
				t.Fatal("omitted/aliased/duplicate native source fact accepted")
			}
		})
	}
	for _, name := range []string{"independent_omitted_nested_singlestep", "independent_unknown_nested", "independent_alias_native_tuple"} {
		t.Run(name, func(t *testing.T) {
			raw := originalClosedIndependentWire(t)
			switch name {
			case "independent_omitted_nested_singlestep":
				raw = bytes.Replace(raw, []byte(`"singlestep":false,`), nil, 1)
			case "independent_unknown_nested":
				raw = bytes.Replace(raw, []byte(`"before":{`), []byte(`"before":{"kernel_complete":true,`), 1)
			case "independent_alias_native_tuple":
				raw = bytes.Replace(raw, []byte(`"resource_id":`), []byte(`"ResourceID":`), 1)
			}
			var decoded IndependentReturn
			if closedJSON(raw, &decoded) == nil {
				t.Fatal("independent read accepted a foreign nested source shape")
			}
		})
	}
	originalFailureClockAuthenticationContracts(t)
}

func TestOriginalNativeQEMUMetadataDecoderSeparate(t *testing.T) {
	t.Run("unknown_qmp_metadata_is_read_only_shape", func(t *testing.T) {
		var metadata map[string]json.RawMessage
		if closedJSON([]byte(`{"QMP":{"version":{"qemu":{"major":10}},"capabilities":[]}}`), &metadata) != nil || metadata["QMP"] == nil {
			t.Fatal("QMP transport metadata grammar was confused with a privileged source DTO")
		}
	})
	for _, test := range []struct{ name, raw string }{
		{"map_duplicate_key", `{"QMP":{},"QMP":{}}`},
		{"map_fold_duplicate_key", `{"QMP":{},"qmp":{}}`},
		{"map_nested_fold_duplicate", `{"QMP":{"version":{},"Version":{}}}`},
		{"map_trailing_record", `{"QMP":{}} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var metadata map[string]json.RawMessage
			if closedJSON([]byte(test.raw), &metadata) == nil {
				t.Fatal("ambiguous metadata object accepted")
			}
		})
	}
	t.Run("same_metadata_cannot_decode_privileged_source", func(t *testing.T) {
		var decoded CreatorReturn
		if closedJSON([]byte(`{"QMP":{"version":{},"capabilities":[]}}`), &decoded) == nil {
			t.Fatal("QMP metadata supplied privileged original create fields")
		}
	})
}

// Pure signed records inside the existing structural Source root; no Native
// effect, database, HTTP call or new census name is created by these vectors.
func originalFailureClockAuthenticationContracts(t *testing.T) {
	at := time.Now().UTC().Add(50 * time.Millisecond)
	deadline := at.Add(-time.Millisecond)
	guest := strings.Repeat("a", 40)
	core := strings.Repeat("b", 40)
	digest := strings.Repeat("c", 64)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: "10000000-0000-0000-0000-000000000001", Slot: 2, OriginalDeadline: deadline}
	witness := model.CapacityGuestOriginalCreateWitness{PreregistrationID: pre.PreregistrationID, ObservedAt: deadline.Add(-3 * time.Second), CoreSourceCommit: core, Tuple: model.CapacityGuestNativeTuple{Provider: "native-qemu", Slot: 2, ResourceID: "20000000-0000-0000-0000-000000000002"}}
	validation := &Realm{Request: SourceRequest{NativeCase: "held_hello_original_deadline", SourceCommit: guest, OriginalContextDeadline: at.Add(time.Second)}, Profile: model.CapacityGuestProtectedProfileManifest{OwnerBinarySHA256: digest}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'f'}, ed25519.SeedSize))
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	returned := deadline.Add(100 * time.Microsecond)
	fact := QualificationFailedOwnerReturn{OriginalReturnedAt: returned, OriginalBodySHA256: capacity.BusinessCreationSHA256(nil), ErrorClass: "original_owner_error"}
	journalStart := returned.Add(100 * time.Microsecond)
	exit := -9
	record := QualificationFailureRecord{Schema: "original_qualification_failed_owner_returns_v1", NativeCase: validation.Request.NativeCase, SourceCommit: guest, Scope: "failed_original_owners_diagnostic_not_capacity_admission_or_quiescence", Phase: "original_preownership_failure", Tuple: witness.Tuple, PreregistrationID: pre.PreregistrationID, OriginalCreateWitnessSHA256: capacity.GuestRetirementSHA(witness), OriginalProvisioningDeadline: deadline, OriginalOperationDeadline: deadline, Runtime: model.CapacityGuestRetirementLifetime{PID: 2, StartTicks: 1, SourceCommit: guest, BinarySHA256: digest}, OriginalChild: model.CapacityGuestRetirementNativeProcess{PID: 3, StartTicks: 2}, OriginalStartCalledAt: deadline.Add(-2 * time.Second), OriginalStartReturnedAt: deadline.Add(-time.Second), OriginalWait: fact, OriginalExitCode: &exit, OriginalOutputEOFAndClose: fact, OriginalDiagnosticEOFAndClose: fact, NativeCensusErrorClass: "original_census_error", RecordedAt: at, ProducerPublicKey: public, ProvisioningJournal: &QualificationProvisioningJournalRead{LastSequence: 1, LastState: "possible_profile_start", LastRecordSHA256: digest, OriginalReadStartedAt: journalStart, OriginalReadReturnedAt: journalStart.Add(100 * time.Microsecond), OriginalCloseReturnedAt: journalStart.Add(200 * time.Microsecond), Records: []QualificationProvisioningRecordRead{{Sequence: 1, OriginalRecordSHA256: digest, OriginalReadReturnedAt: journalStart.Add(50 * time.Microsecond), OriginalCloseReturnedAt: journalStart.Add(75 * time.Microsecond)}}}}
	sign := func(v *QualificationFailureRecord) []byte {
		v.Signature = ""
		signature, err := capacity.GuestLifecycleSignature(key, *v)
		if err != nil {
			t.Fatal(err)
		}
		v.Signature = signature
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	wire := sign(&record)
	if validation.ValidateOriginalFailure(record, pre, witness, public, record.RecordedAt) != nil {
		t.Fatal("declared complete signed negative record invalid")
	}
	if validation.ValidateOriginalFailure(record, pre, witness, public, record.RecordedAt.Add(-time.Nanosecond)) == nil {
		t.Fatal("downstream future-time guard weakened")
	}
	auth := originalFailureClockTarget(validation, pre, witness, public)
	if target, ok := auth([]byte("{}"), wire); !ok || target != record.RecordedAt {
		t.Fatal("fully signed failure target refused")
	}
	for _, raw := range [][]byte{[]byte(`{"unknown":true}`), append(append([]byte{}, wire...), ' '), append(append([]byte{}, wire...), []byte("{}")...)} {
		if _, ok := auth([]byte("{}"), raw); ok {
			t.Fatal("malformed/noncanonical response acquired wait")
		}
	}
	for _, request := range [][]byte{nil, []byte(" {}"), []byte(`{"schema":"canonical_postloss_fresh_failure_request_v1"}`), []byte(`{"schema":"canonical_recovery_fresh_failure_request_v1"}`)} {
		if _, ok := auth(request, wire); ok {
			t.Fatal("foreign/fresh request acquired original report wait")
		}
	}
	for _, mutate := range []func(*QualificationFailureRecord){
		func(v *QualificationFailureRecord) { v.NativeCase = "foreign" }, func(v *QualificationFailureRecord) { v.SourceCommit = core }, func(v *QualificationFailureRecord) { v.Tuple.ResourceID = "foreign" }, func(v *QualificationFailureRecord) { v.PreregistrationID = "foreign" }, func(v *QualificationFailureRecord) { v.OriginalCreateWitnessSHA256 = digest }, func(v *QualificationFailureRecord) { v.Runtime.PID = 1 }, func(v *QualificationFailureRecord) { v.Runtime.BinarySHA256 = strings.Repeat("d", 64) }, func(v *QualificationFailureRecord) { v.OriginalProvisioningDeadline = at }, func(v *QualificationFailureRecord) { v.OriginalWait.OriginalReturnedAt = at.Add(time.Second) }, func(v *QualificationFailureRecord) { v.RecordedAt = time.Time{} }, func(v *QualificationFailureRecord) { v.ProducerPublicKey = "foreign" },
	} {
		var changed QualificationFailureRecord
		if capacity.DecodeGuestLifecycle(wire, &changed) != nil {
			t.Fatal("fixture decode")
		}
		mutate(&changed)
		bad := sign(&changed)
		if _, ok := auth([]byte("{}"), bad); ok {
			t.Fatal("foreign signed identity/lifetime/chronology acquired wait")
		}
	}
	unsigned := record
	unsigned.Signature = ""
	bad, _ := json.Marshal(unsigned)
	if _, ok := auth([]byte("{}"), bad); ok {
		t.Fatal("unsigned report acquired wait")
	}
	foreignPre := pre
	foreignPre.PreregistrationID = "foreign"
	if _, ok := originalFailureClockTarget(validation, foreignPre, witness, public)([]byte("{}"), wire); ok {
		t.Fatal("foreign sealed pre acquired wait")
	}
	foreignWitness := witness
	foreignWitness.PreregistrationNonceSHA256 = digest
	if _, ok := originalFailureClockTarget(validation, pre, foreignWitness, public)([]byte("{}"), wire); ok {
		t.Fatal("foreign sealed nonce/witness acquired wait")
	}
	if _, ok := originalFailureClockTarget(validation, pre, witness, "foreign")([]byte("{}"), wire); ok {
		t.Fatal("foreign trusted producer key acquired wait")
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(after, wire) {
		t.Fatal("immutable signed failure changed")
	}
}
