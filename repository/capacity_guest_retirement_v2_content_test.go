package repository

import (
	"bytes"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Decoder operands only. This neither creates a DB parent nor claims an SDK
// call, native authority, approved profile or actual retirement completion.
func nativeAbsenceV2Unit() (GuestNativeAbsenceReturnV2, model.CapacityPolicySpec, capacityMutationRecord) {
	now := time.Now().UTC()
	native := now.Add(24 * time.Hour)
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }
	b := model.CapacityMutationBinding{Name: "writers", EnsureCapability: "ensure_ec2_instance", DestroyCapability: "terminate_ec2_instance", IntegrationInstanceID: "original-instance", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "writers", ProtectedSlots: 1, MaxSlots: 2, OriginalProviderSourceCommit: strings.Repeat("a", 40), Slots: []model.CapacityMutationSlotBinding{{Slot: 2, DesiredSpec: &model.CapacityMutationSpecV1{}}}}
	g := model.CapacityMutationGrant{GrantID: "12345678-1234-4234-8234-123456789011", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.DestroyCapability, RequestSHA256: strings.Repeat("b", 64), ExpectedResourceID: "i-1234567890abcdef0", ExpectedResourceCreatedAt: stamp(native.Add(-time.Hour)), State: "settled"}
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-1234567890abcdef0", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-1234567890abcdef0", RequiresAbsence: true}}
	s := &model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: "12345678-1234-4234-8234-123456789012", RequestSHA256: g.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: g.ExpectedResourceID, ResourceCreatedAt: g.ExpectedResourceCreatedAt, ActionID: "native-terminate-request", NextActionIDs: []string{}, AuxiliaryResources: aux, AuxiliaryInventoryComplete: true}
	s.OriginalProviderDestroyReturn = &model.CapacityOriginalProviderDestroyReturn{Schema: "aws_original_terminate_instances_return_v1", Provider: "aws", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: g.GrantID, AttemptID: s.AttemptID, RequestSHA256: g.RequestSHA256, ResourceID: g.ExpectedResourceID, ResourceCreatedAt: g.ExpectedResourceCreatedAt, ActionID: s.ActionID, NextActionIDs: []string{}, CalledAt: stamp(native.Add(-4 * time.Second)), ReturnedAt: stamp(native.Add(-3 * time.Second)), ContextDeadline: stamp(native.Add(time.Second)), ResponseStatus: 200, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 500}
	original := capacityMutationRecord{Grant: g, Binding: b, AttemptID: s.AttemptID, Settlement: s}
	observation := &model.CapacityVMRetirementObservation{AWSRetirementLifecycle: &model.CapacityAWSRetirementLifecycle{Schema: "aws_original_terminate_and_native_absence_v1", RequestID: s.ActionID, EC2State: "terminated", ObservedAt: native}, CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: g.ExpectedResourceID, CreatedAt: g.ExpectedResourceCreatedAt}, DestroyGrantID: g.GrantID, DestroyGrantState: g.State, OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: stamp(native.Add(-time.Second)), NextActions: []model.CapacityVMActionObservation{}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: aux[0].Kind, ID: aux[0].ID, Absent: true, ObservedAt: stamp(native)}, {Kind: aux[1].Kind, ID: aux[1].ID, Absent: true, ObservedAt: stamp(native)}}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: stamp(native.Add(-2 * time.Second)), ObservedAt: stamp(native)}
	c := GuestNativePoweroffReadV2{Schema: "original_core_guest_native_poweroff_read_challenge_v2", ReadID: "12345678-1234-4234-8234-123456789013", IntentID: "12345678-1234-4234-8234-123456789014", IntentSHA256: strings.Repeat("a", 64), OriginalCallerSHA256: strings.Repeat("b", 64), MutationBindingSHA256: capacity.GuestRetirementSHA(b), AdapterSourceCommit: b.OriginalProviderSourceCommit, Tuple: model.CapacityGuestNativeTuple{ResourceID: g.ExpectedResourceID, CreatedAt: g.ExpectedResourceCreatedAt}, IssuedAtCore: now, OriginalDeadlineCore: now.Add(5 * time.Second)}
	out := GuestNativeAbsenceReturnV2{Schema: "original_core_guest_native_absence_return_v2", Challenge: c, DestroyGrantID: g.GrantID, OriginalDestroyReceiptSHA256: capacity.GuestRetirementSHA(guestMutationReceiptV2(original)), Status: "observed", Observation: observation, StartedAtCore: now.Add(time.Millisecond), OriginalReturnedAtCore: now.Add(2 * time.Millisecond)}
	p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{b}, Profiles: []model.CapacityProfile{{Name: b.ProfileName, Provider: "aws"}}}
	return out, p, original
}
func TestGuestRetirementV2NativeReadContentRequiresWholeOriginalReturn(t *testing.T) {
	t.Run("authority_diagnostic_preserves_and_rehydrates_actual_transport", testGuestAuthorityDiagnosticV2)
	t.Run("actual_lifecycle_DTO_closed_roundtrips", testGuestLifecycleActualDTOClosedRoundtrips)
	t.Run("confirmed_state_keeps_actual_original_settled_receipt", testGuestConfirmedNativeAbsenceContentV2)
	for _, kind := range []string{"original_native_clock_ahead", "late_original_return", "renewed_budget", "wrong_receipt", "wrong_binding", "wrong_tuple", "wrong_source", "context_failed", "call_failed", "unknown_outcome", "lost_transport", "missing_original_destroy", "create_receipt_reuse", "unknown_eni", "retained_volume", "wrong_original_request"} {
		t.Run(kind, func(t *testing.T) {
			r, p, original := nativeAbsenceV2Unit()
			switch kind {
			case "late_original_return":
				r.OriginalReturnedAtCore = r.Challenge.OriginalDeadlineCore
			case "renewed_budget":
				r.Challenge.OriginalDeadlineCore = r.Challenge.OriginalDeadlineCore.Add(time.Nanosecond)
			case "wrong_receipt":
				r.OriginalDestroyReceiptSHA256 = strings.Repeat("e", 64)
			case "wrong_binding":
				r.Challenge.MutationBindingSHA256 = strings.Repeat("e", 64)
			case "wrong_tuple":
				r.Challenge.Tuple.ResourceID = "other"
			case "wrong_source":
				r.Challenge.AdapterSourceCommit = strings.Repeat("e", 40)
			case "context_failed":
				r.OriginalContextFailed = true
			case "call_failed":
				r.CallFailed = true
			case "unknown_outcome":
				original.Settlement.Outcome = "uncertain"
			case "lost_transport":
				original.Settlement.TransportCompleted = false
			case "missing_original_destroy":
				original.Settlement.OriginalProviderDestroyReturn = nil
			case "create_receipt_reuse":
				original.Settlement.OriginalProviderCreateReturn = original.Settlement.OriginalProviderDestroyReturn
				original.Settlement.OriginalProviderDestroyReturn = nil
			case "unknown_eni":
				r.Observation.AuxiliaryResources = r.Observation.AuxiliaryResources[:1]
			case "retained_volume":
				r.Observation.AuxiliaryResources[0].Absent = false
			case "wrong_original_request":
				original.Settlement.OriginalProviderDestroyReturn.RequestSHA256 = strings.Repeat("e", 64)
			}
			_, err := guestNativeAbsenceContentV2(r, p, original)
			if (err == nil) != (kind == "original_native_clock_ahead") {
				t.Fatalf("content admitted=%v kind=%s", err == nil, kind)
			}
		})
	}
}

func testGuestAuthorityDiagnosticV2(t *testing.T) {
	observation := model.CapacityGuestRetirementObservationV2{HoldReasons: []string{}}
	observation.Record.Intent.Writers = []model.CapacityGuestRetirementWriter{}
	body, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"original_rehydrated", "diagnostic_alone", "body_lost", "body_changed", "context_failed", "close_failed", "reversed_return", "null_marker"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			original := capacity.GuestOriginalHTTPReturn{StartedAt: now, DoStartedAt: now.Add(time.Millisecond), DoReturnedAt: now.Add(2 * time.Millisecond), ReadReturnedAt: now.Add(3 * time.Millisecond), CloseReturnedAt: now.Add(4 * time.Millisecond), DriverReturnedAt: now.Add(5 * time.Millisecond), Status: 200, Body: body, ReceivedBodyBytes: len(body), ResponseSHA256: capacity.BusinessCreationSHA256(body), ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(body), RetainedPrefixSHA256: capacity.BusinessCreationSHA256(body)}
			switch kind {
			case "context_failed":
				original.OriginalContextFailed = true
			case "close_failed":
				original.CloseFailed = true
			case "reversed_return":
				original.DriverReturnedAt = original.StartedAt
			}
			wire, err := guestAuthorityTransportDiagnosticV2(original)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "null_marker" {
				wire = bytes.Replace(wire, []byte(`"Body":""`), []byte(`"Body":null`), 1)
			}
			var returned capacity.GuestOriginalHTTPReturn
			if err = capacity.DecodeGuestLifecycle(wire, &returned); kind == "null_marker" {
				if err == nil {
					t.Fatal("null original body became retained empty bytes")
				}
				return
			}
			if err != nil || returned.Body == nil || len(returned.Body) != 0 {
				t.Fatal("diagnostic could not be decoded before rehydration", err)
			}
			if kind != "diagnostic_alone" {
				returned.Body = append([]byte(nil), body...)
			}
			switch kind {
			case "body_lost":
				returned.Body = nil
			case "body_changed":
				returned.Body[0] = '['
			}
			var actual model.CapacityGuestRetirementObservationV2
			if (capacity.GuestOriginalHTTPDecode(returned, &actual) == nil) != (kind == "original_rehydrated") {
				t.Fatal("diagnostic, missing body or failed transport gained original return", kind)
			}
			if kind == "original_rehydrated" && (!reflect.DeepEqual(actual, observation) || !reflect.DeepEqual(returned, original)) {
				t.Fatal("original body/hash/count/times/false facts changed")
			}
		})
	}
}

func testGuestConfirmedNativeAbsenceContentV2(t *testing.T) {
	for _, kind := range []string{"actual_original_receipt", "missing_receipt", "receipt_hash_changed", "receipt_state_confirmed", "receipt_grant_changed", "receipt_attempt_changed", "receipt_deadline_changed", "current_state_settled", "current_state_unknown", "current_proof_missing", "current_proof_changed", "current_settlement_changed", "original_expired", "original_context_failed", "nonce_changed", "source_changed"} {
		t.Run(kind, func(t *testing.T) {
			r, p, current := nativeAbsenceV2Unit()
			receipt := guestMutationReceiptV2(current)
			r.OriginalDestroyReceipt = &receipt
			wire, err := json.Marshal(r)
			var roundtrip GuestNativeAbsenceReturnV2
			decodeErr := capacity.DecodeGuestLifecycle(wire, &roundtrip)
			again, encodeErr := json.Marshal(roundtrip)
			if err != nil || decodeErr != nil || encodeErr != nil || !bytes.Equal(wire, again) {
				t.Fatal("actual Core absence return with receipt cannot roundtrip", err, decodeErr)
			}
			proof, err := guestNativeAbsenceContentV2(r, p, current)
			if err != nil {
				t.Fatal("valid original receipt fixture", err)
			}
			proof.ObservedAt = time.Now().UTC()
			current.Grant.State, current.Proof = "confirmed", &proof
			switch kind {
			case "missing_receipt":
				r.OriginalDestroyReceipt = nil
			case "receipt_hash_changed":
				r.OriginalDestroyReceiptSHA256 = strings.Repeat("e", 64)
			case "receipt_state_confirmed":
				receipt.Grant.State = "confirmed"
			case "receipt_grant_changed":
				receipt.Grant.RequestSHA256 = strings.Repeat("e", 64)
			case "receipt_attempt_changed":
				receipt.AttemptID = "other-attempt"
			case "receipt_deadline_changed":
				receipt.Grant.ExpiresAt = time.Now().UTC()
			case "current_state_settled":
				current.Grant.State = "settled"
			case "current_state_unknown":
				current.Grant.State = "unknown"
			case "current_proof_missing":
				current.Proof = nil
			case "current_proof_changed":
				current.Proof.ResourceAbsent = false
			case "current_settlement_changed":
				current.Settlement.ActionID = "other-action"
			case "original_expired":
				r.OriginalReturnedAtCore = r.Challenge.OriginalDeadlineCore
			case "original_context_failed":
				r.OriginalContextFailed = true
			case "nonce_changed":
				r.Challenge.OriginalCallerSHA256 = "invalid"
			case "source_changed":
				r.Challenge.AdapterSourceCommit = strings.Repeat("e", 40)
			}
			beforeCurrent := current.Grant
			beforeReceipt := receipt.Grant
			actual, err := guestConfirmedNativeAbsenceContentV2(r, p, current)
			if (err == nil) != (kind == "actual_original_receipt") {
				t.Fatal("incompatible confirmed/current/original join", kind, err)
			}
			if err == nil && !reflect.DeepEqual(actual, *current.Proof) {
				t.Fatal("confirmation proof altered")
			}
			if !reflect.DeepEqual(beforeCurrent, current.Grant) || !reflect.DeepEqual(beforeReceipt, receipt.Grant) {
				t.Fatal("current or historical state rewritten")
			}
		})
	}
}

// Shape-only records, using the actual exported DTOs read from storage. Empty
// arrays/maps are explicit grammar operands, never signed/native authority.
func testGuestLifecycleActualDTOClosedRoundtrips(t *testing.T) {
	absence, _, _ := nativeAbsenceV2Unit()
	for _, specimen := range []any{
		absence,
		capacity.GuestOriginalHTTPReturn{},
		GuestNativePoweroffReturnV2{Plan: &model.CapacityVMFleetPlan{Server: &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: "native", CreatedAt: "native-created"}}}},
		GuestOriginalCallerReturn{},
		guestRetirementV2NonceReturn{},
		model.CapacityGuestRetirementRequestV2{},
		model.CapacityGuestRetirementObservationV2{},
		model.CapacityGuestRetirementObservation{},
		model.CapacityGuestOriginalProvisioningPreregistration{},
		model.CapacityGuestOriginalCreateWitness{},
		model.CapacityGuestOriginalProvisioningRegistration{Result: model.CapacityGuestOriginalProvisioningResult{ProductionClock: &model.CapacityGuestProductionProvisioningClockV2{}}},
		model.CapacityGuestOriginalProvisioningReceipt{},
		model.CapacityGuestRuntimeSnapshot{},
	} {
		t.Run(reflect.TypeOf(specimen).Name(), func(t *testing.T) {
			value := reflect.New(reflect.TypeOf(specimen))
			value.Elem().Set(reflect.ValueOf(specimen))
			var explicitCollections func(reflect.Value)
			explicitCollections = func(v reflect.Value) {
				if v.Kind() == reflect.Pointer {
					if !v.IsNil() {
						explicitCollections(v.Elem())
					}
					return
				}
				switch v.Kind() {
				case reflect.Struct:
					for n := 0; n < v.NumField(); n++ {
						if v.Field(n).CanSet() {
							explicitCollections(v.Field(n))
						}
					}
				case reflect.Slice:
					if v.IsNil() {
						v.Set(reflect.MakeSlice(v.Type(), 0, 0))
					}
				case reflect.Map:
					if v.IsNil() {
						v.Set(reflect.MakeMap(v.Type()))
					}
				}
			}
			explicitCollections(value.Elem())
			wire, err := json.Marshal(value.Interface())
			decoded := reflect.New(value.Elem().Type())
			decodeErr := capacity.DecodeGuestLifecycle(wire, decoded.Interface())
			again, encodeErr := json.Marshal(decoded.Interface())
			if err != nil || decodeErr != nil || encodeErr != nil || !bytes.Equal(wire, again) {
				t.Fatal("actual lifecycle DTO refuses its own closed JSON", value.Elem().Type(), err, decodeErr, encodeErr)
			}
		})
	}
	t.Run("original_HTTP_explicit_tags_preserve_original_bytes", func(t *testing.T) {
		original := capacity.GuestOriginalHTTPReturn{StartedAt: time.Now().UTC(), Body: []byte{0, 1, 254}}
		typ := reflect.TypeOf(original)
		fields := make([]reflect.StructField, typ.NumField())
		for n := range fields {
			fields[n] = typ.Field(n)
			if fields[n].Tag.Get("json") != fields[n].Name {
				t.Fatal("original HTTP JSON field renamed")
			}
			fields[n].Tag = ""
		}
		legacy := reflect.New(reflect.StructOf(fields)).Elem()
		actual := reflect.ValueOf(original)
		for n := range fields {
			legacy.Field(n).Set(actual.Field(n))
		}
		before, beforeErr := json.Marshal(legacy.Interface())
		after, afterErr := json.Marshal(original)
		if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
			t.Fatal("explicit tags changed historical original HTTP bytes")
		}
	})
	t.Run("embedded_native_tuple_stays_required_and_closed", func(t *testing.T) {
		wire, err := json.Marshal(absence.Observation)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"exact", "missing_id", "missing_created", "unknown", "duplicate_id", "null_id"} {
			t.Run(kind, func(t *testing.T) {
				var object map[string]json.RawMessage
				if json.Unmarshal(wire, &object) != nil {
					t.Fatal("original object")
				}
				switch kind {
				case "missing_id":
					delete(object, "id")
				case "missing_created":
					delete(object, "created_at")
				case "unknown":
					object["assume_absence"] = json.RawMessage("true")
				case "null_id":
					object["id"] = json.RawMessage("null")
				}
				candidate, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "duplicate_id" {
					candidate = append([]byte(`{"id":"duplicate",`), candidate[1:]...)
				}
				var decoded model.CapacityVMRetirementObservation
				if (capacity.DecodeGuestLifecycle(candidate, &decoded) == nil) != (kind == "exact") {
					t.Fatal("embedded native fields lost closed shape", kind)
				}
			})
		}
	})
}
