package repository

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
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
