package capacity

import (
	"fmt"
	"regexp"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func awsRetirementAuxiliary(aux []model.CapacityMutationAuxiliaryResource) bool {
	if len(aux) != 2 {
		return false
	}
	for n, a := range aux {
		prefix, kind := "vol-", "aws_ebs_volume"
		if n == 1 {
			prefix, kind = "eni-", "aws_network_interface"
		}
		if a.Kind != kind || !a.RequiresAbsence || !regexp.MustCompile(`^`+prefix+`(?:[0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(a.ID) {
			return false
		}
	}
	return true
}

func AWSOriginalDestroyLifecycleComplete(b model.CapacityMutationBinding, g model.CapacityMutationGrant, s *model.CapacityMutationSettleRequest, proof model.CapacityMutationProof, now time.Time) bool {
	l := proof.AWSRetirementLifecycle
	if !AWSOriginalMutationPair(b) || s == nil || s.OriginalProviderDestroyReturn == nil || s.OriginalProviderCreateReturn != nil || s.OriginalProviderDestroyReturn.Schema != "aws_original_terminate_instances_return_v1" || s.OriginalProviderDestroyReturn.Provider != "aws" || s.OriginalProviderDestroyReturn.AdapterSourceCommit != b.OriginalProviderSourceCommit || g.Capability != b.DestroyCapability || g.CompensationOf != "" || !s.TransportCompleted || s.Outcome != "accepted" || s.ActionID == "" || s.ActionID != s.OriginalProviderDestroyReturn.ActionID || len(s.NextActionIDs) != 0 || !s.AuxiliaryInventoryComplete || !awsRetirementAuxiliary(s.AuxiliaryResources) || proof.GrantID != g.GrantID || proof.BindingName != b.Name || proof.Slot != g.Slot || proof.RequestSHA256 != g.RequestSHA256 || proof.ResourceID != g.ExpectedResourceID || proof.ResourceCreatedAt != g.ExpectedResourceCreatedAt || !proof.ResourceAbsent || !proof.OwnerVerified || !proof.SpecVerified || proof.AWSInstanceLifecycle != nil || proof.ProviderNativeIdentity != nil || proof.ActionsTerminal || proof.ActionsSuccessful || proof.ActionsFailed || proof.ActionHistoryComplete || len(proof.ActionIDs) != 0 || proof.ObservedCreationGrantID != "" || proof.CompensationIdentityVerified || len(proof.AuxiliaryAbsent) != 2 || l == nil {
		return false
	}
	for n, a := range proof.AuxiliaryAbsent {
		if a != s.AuxiliaryResources[n] {
			return false
		}
	}
	return l.Schema == "aws_original_terminate_and_native_absence_v1" && l.RequestID == s.ActionID && (l.EC2State == "terminated" || l.EC2State == "not_found") && l.ObservedAt.Equal(proof.ObservedAt) && Fresh(l.ObservedAt, now, 30)
}

func awsVMRetirementProof(p model.CapacityPolicySpec, b model.CapacityMutationBinding, r model.CapacityMutationReceipt, o model.CapacityVMRetirementObservation, now time.Time, receiptRef string) (model.CapacityMutationProof, error) {
	var out model.CapacityMutationProof
	fail := fmt.Errorf("exact original AWS termination and complete retained native absence required")
	g := r.Grant
	l := o.AWSRetirementLifecycle
	if !AWSOriginalMutationPair(b) || (g.State != "settled" && g.State != "confirmed") || g.Capability != b.DestroyCapability || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.CompensationOf != "" || g.Slot <= b.ProtectedSlots || g.Slot > b.MaxSlots || g.GrantID == "" || !ValidDigest(g.RequestSHA256) || !regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`).MatchString(g.ExpectedResourceID) || r.Outcome != "accepted" || !r.TransportCompleted || r.ResourceID != g.ExpectedResourceID || r.ResourceCreatedAt != g.ExpectedResourceCreatedAt || r.ActionID == "" || len(r.ActionID) > 128 || len(r.NextActionIDs) != 0 || !r.AuxiliaryInventoryComplete || !awsRetirementAuxiliary(r.AuxiliaryResources) || o.DestroyGrantID != g.GrantID || o.DestroyGrantState != g.State || o.CompensationOf != "" || o.ID != r.ResourceID || o.CreatedAt != r.ResourceCreatedAt || o.OriginalOutcome != "accepted" || !o.OriginalTransportCompleted || !o.ServerAbsent || !o.ServerAbsenceComplete || o.ServerStatus != "" || o.DeleteAction != (model.CapacityVMRetirementAction{}) || o.NextActions == nil || len(o.NextActions) != 0 || !o.AuxiliaryInventoryComplete || !o.BillableResourcesAbsent || !o.RetirementComplete || o.HoldReasons == nil || len(o.HoldReasons) != 0 || o.BillingExposure != nil || o.InvoiceReconciled || o.WriterQuiescenceEvidence || o.ProviderFencingEvidence || receiptRef == "" || len(receiptRef) > 512 || l == nil || l.Schema != "aws_original_terminate_and_native_absence_v1" || l.RequestID != r.ActionID || (l.EC2State != "terminated" && l.EC2State != "not_found") {
		return out, fail
	}
	if _, err := vmApprovedSlot(b, g.Slot); err != nil {
		return out, fail
	}
	start, a := vmTime(o.ObservationStartedAt, p, now)
	server, z := vmTime(o.ServerObservedAt, p, now)
	end, c := vmTime(o.ObservedAt, p, now)
	created, e := time.Parse(time.RFC3339Nano, o.CreatedAt)
	if a != nil || z != nil || c != nil || e != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != o.CreatedAt || created.After(start) || start.After(server) || server.After(end) || end.After(now) || end.Sub(start) > 60*time.Second || !l.ObservedAt.Equal(end) || o.AuxiliaryResources == nil || len(o.AuxiliaryResources) != 2 {
		return out, fail
	}
	absent := make([]model.CapacityMutationAuxiliaryResource, 0, 2)
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID || !a.Absent {
			return out, fail
		}
		at, e := vmTime(a.ObservedAt, p, now)
		if e != nil || at.Before(start) || at.After(end) {
			return out, fail
		}
		absent = append(absent, r.AuxiliaryResources[n])
	}
	copyLifecycle := *l
	return model.CapacityMutationProof{AWSRetirementLifecycle: &copyLifecycle, GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, ResourceID: o.ID, ResourceCreatedAt: o.CreatedAt, RequestSHA256: g.RequestSHA256, ObservedAt: end, ReceiptRef: receiptRef, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: []string{}, AuxiliaryAbsent: absent}, nil
}
