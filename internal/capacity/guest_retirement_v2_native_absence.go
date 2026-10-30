package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// This content-only decoder grants neither freshness nor mutation authority.
// Native timestamps retain their own clock. The owning V2 repository must join
// a pre-read challenge, actual complete Core five-second RPC return, immutable
// original destroy settlement, and Core PG custody before publishing a proof.
func guestRetirementV2CanonicalTime(raw string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != raw {
		return at, fmt.Errorf("noncanonical native timestamp")
	}
	return at, nil
}

func GuestRetirementV2NativeAbsenceContent(p model.CapacityPolicySpec, b model.CapacityMutationBinding, original model.CapacityMutationReceipt, observed model.CapacityVMRetirementObservation, receiptRef string) (model.CapacityMutationProof, error) {
	var out model.CapacityMutationProof
	configured, configuredErr := VMObservationBinding(p, b.Name)
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			if provider != "" {
				return out, fmt.Errorf("duplicate native profile")
			}
			provider = profile.Provider
		}
	}
	if configuredErr != nil || !reflect.DeepEqual(configured, b) || !businessSource.MatchString(b.OriginalProviderSourceCommit) || (provider != "aws" && provider != "hetzner") || provider == "aws" && !AWSOriginalMutationPair(b) || provider == "hetzner" && (b.EnsureCapability != "ensure_server" || b.DestroyCapability != "destroy_server") {
		return out, fmt.Errorf("exact source-owned native retirement binding required")
	}

	if AWSOriginalMutationPair(b) {
		return guestRetirementV2AWSAbsenceContent(b, original, observed, receiptRef)
	}
	if observed.AWSRetirementLifecycle != nil {
		return out, fmt.Errorf("AWS retirement lifecycle requires its exact source-pinned AWS binding")
	}
	g := original.Grant
	refuse := fmt.Errorf("exact original native retirement readback required")
	if (g.State != "settled" && g.State != "confirmed") || g.Capability != b.DestroyCapability || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.GrantID == "" || g.RequestSHA256 == "" || g.ExpectedResourceID == "" || g.ExpectedResourceCreatedAt == "" || original.Outcome != "accepted" || !original.TransportCompleted || observed.DestroyGrantID != g.GrantID || observed.DestroyGrantState != g.State || observed.CompensationOf != g.CompensationOf || observed.ID != g.ExpectedResourceID || observed.CreatedAt != g.ExpectedResourceCreatedAt || observed.OriginalOutcome != original.Outcome || observed.OriginalTransportCompleted != original.TransportCompleted || !observed.ServerAbsent || !observed.ServerAbsenceComplete || observed.ServerStatus != "" || !observed.AuxiliaryInventoryComplete || !original.AuxiliaryInventoryComplete || !observed.BillableResourcesAbsent || !observed.RetirementComplete || observed.HoldReasons == nil || len(observed.HoldReasons) != 0 || observed.InvoiceReconciled || observed.WriterQuiescenceEvidence || observed.ProviderFencingEvidence || receiptRef == "" || len(receiptRef) > 2048 {
		return out, refuse
	}
	if _, err := vmApprovedSlot(b, g.Slot); err != nil || (g.Slot <= b.ProtectedSlots && g.CompensationOf == "") {
		return out, refuse
	}
	start, e1 := guestRetirementV2CanonicalTime(observed.ObservationStartedAt)
	server, e2 := guestRetirementV2CanonicalTime(observed.ServerObservedAt)
	end, e3 := guestRetirementV2CanonicalTime(observed.ObservedAt)
	created, e4 := time.Parse(time.RFC3339Nano, observed.CreatedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != observed.CreatedAt || start.After(server) || server.After(end) || end.Sub(start) > 60*time.Second {
		return out, refuse
	}
	if original.ResourceID != "" && (original.ResourceID != observed.ID || original.ResourceCreatedAt != observed.CreatedAt) {
		return out, refuse
	}
	main := observed.DeleteAction
	if original.ActionID == "" || !main.Known || !main.Observed || main.ID != original.ActionID || main.Status != "success" || main.Command != "delete_server" || main.ErrorCode != "" || observed.NextActions == nil || len(observed.NextActions) != len(original.NextActionIDs) || len(observed.NextActions) > 32 {
		return out, refuse
	}
	// The closed main-action DTO has no separate observation timestamp. Use
	// only the ORIGINAL whole readback's returned-at upper bound for freshness;
	// never invent the time of that GET. Successors retain their actual stamps.
	collection := model.CapacityVMActionCollection{ResourceID: observed.ID, ResourceCreatedAt: observed.CreatedAt, Complete: true, ObservedAt: observed.ObservedAt, Actions: []model.CapacityVMActionObservation{{ID: main.ID, Status: main.Status, Command: main.Command, ResourceID: observed.ID, StartedAt: main.StartedAt, FinishedAt: main.FinishedAt, ErrorCode: main.ErrorCode, ObservedAt: observed.ObservedAt}}}
	for n, action := range observed.NextActions {
		if action.ID != original.NextActionIDs[n] {
			return out, refuse
		}
		collection.Actions = append(collection.Actions, action)
	}
	ids, err := guestRetirementV2ActionContent(collection, observed.ID, true)
	if err != nil {
		return out, refuse
	}
	if observed.AuxiliaryResources == nil || len(observed.AuxiliaryResources) != len(original.AuxiliaryResources) || len(observed.AuxiliaryResources) > 16 {
		return out, refuse
	}
	owned := map[string]model.CapacityMutationAuxiliaryResource{}
	for _, aux := range original.AuxiliaryResources {
		key := aux.Kind + "/" + aux.ID
		if aux.Kind == "" || aux.ID == "" || len(aux.Kind) > 64 || len(aux.ID) > 128 || strings.ContainsAny(key, "\x00\r\n") || owned[key].ID != "" {
			return out, refuse
		}
		owned[key] = aux
	}
	absent := []model.CapacityMutationAuxiliaryResource{}
	seen := map[string]bool{}
	for n, aux := range observed.AuxiliaryResources {
		key := aux.Kind + "/" + aux.ID
		if owned[key].ID == "" || seen[key] || !aux.Absent || original.AuxiliaryResources[n].Kind != aux.Kind || original.AuxiliaryResources[n].ID != aux.ID {
			return out, refuse
		}
		at, err := guestRetirementV2CanonicalTime(aux.ObservedAt)
		if err != nil || at.Before(start) || at.After(end) {
			return out, refuse
		}
		seen[key] = true
		absent = append(absent, model.CapacityMutationAuxiliaryResource{Kind: aux.Kind, ID: aux.ID, RequiresAbsence: true})
	}
	if !vmRetirementExposureBound(p, original, observed, created, start, end) {
		return out, refuse
	}
	out = model.CapacityMutationProof{GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, ResourceID: observed.ID, ResourceCreatedAt: observed.CreatedAt, RequestSHA256: g.RequestSHA256, ObservedAt: end, ReceiptRef: receiptRef, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: ids, ActionsTerminal: true, ActionsSuccessful: true, AuxiliaryAbsent: absent, CompensationIdentityVerified: g.CompensationOf != ""}
	return out, nil
}

func guestRetirementV2AWSAbsenceContent(b model.CapacityMutationBinding, r model.CapacityMutationReceipt, o model.CapacityVMRetirementObservation, receiptRef string) (model.CapacityMutationProof, error) {
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
	start, a := guestRetirementV2CanonicalTime(o.ObservationStartedAt)
	server, z := guestRetirementV2CanonicalTime(o.ServerObservedAt)
	end, c := guestRetirementV2CanonicalTime(o.ObservedAt)
	created, e := time.Parse(time.RFC3339Nano, o.CreatedAt)
	if a != nil || z != nil || c != nil || e != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != o.CreatedAt || start.After(server) || server.After(end) || end.Sub(start) > 60*time.Second || !l.ObservedAt.Equal(end) || o.AuxiliaryResources == nil || len(o.AuxiliaryResources) != 2 {
		return out, fail
	}
	absent := make([]model.CapacityMutationAuxiliaryResource, 0, 2)
	for n, a := range o.AuxiliaryResources {
		if a.Kind != r.AuxiliaryResources[n].Kind || a.ID != r.AuxiliaryResources[n].ID || !a.Absent {
			return out, fail
		}
		at, e := guestRetirementV2CanonicalTime(a.ObservedAt)
		if e != nil || at.Before(start) || at.After(end) {
			return out, fail
		}
		absent = append(absent, r.AuxiliaryResources[n])
	}
	copyLifecycle := *l
	return model.CapacityMutationProof{AWSRetirementLifecycle: &copyLifecycle, GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, ResourceID: o.ID, ResourceCreatedAt: o.CreatedAt, RequestSHA256: g.RequestSHA256, ObservedAt: end, ReceiptRef: receiptRef, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: []string{}, AuxiliaryAbsent: absent}, nil
}

func guestRetirementV2ActionContent(c model.CapacityVMActionCollection, resourceID string, success bool) ([]string, error) {
	if !c.Complete || c.ResourceID != resourceID || len(c.Actions) == 0 || len(c.Actions) > 64 {
		return nil, fmt.Errorf("native action collection is incomplete or mismatched")
	}
	if _, err := guestRetirementV2CanonicalTime(c.ObservedAt); err != nil {
		return nil, err
	}
	created, err := time.Parse(time.RFC3339Nano, c.ResourceCreatedAt)
	if err != nil || created.IsZero() {
		return nil, fmt.Errorf("native action collection lacks immutable resource lifetime")
	}
	seen := map[string]bool{}
	ids := []string{}
	failed := false
	for _, action := range c.Actions {
		if action.ID == "" || len(action.ID) > 256 || seen[action.ID] || action.ResourceID != resourceID || action.ProviderFencingEvidence || action.Command == "" || action.Status == "running" || (action.Status != "success" && action.Status != "error") || action.FinishedAt == "" {
			return nil, fmt.Errorf("native action is not exact terminal evidence")
		}
		if _, err := guestRetirementV2CanonicalTime(action.ObservedAt); err != nil {
			return nil, err
		}
		start, e1 := time.Parse(time.RFC3339Nano, action.StartedAt)
		end, e2 := time.Parse(time.RFC3339Nano, action.FinishedAt)
		if e1 != nil || e2 != nil || start.IsZero() || start.UTC().Format(time.RFC3339Nano) != action.StartedAt || end.UTC().Format(time.RFC3339Nano) != action.FinishedAt || end.Before(start) {
			return nil, fmt.Errorf("native action lifecycle timestamps invalid")
		}
		if success && action.Status != "success" {
			return nil, fmt.Errorf("native action did not succeed")
		}
		failed = failed || action.Status == "error"
		seen[action.ID] = true
		ids = append(ids, action.ID)
	}
	if !success && !failed {
		return nil, fmt.Errorf("failed candidate contains no actual terminal error")
	}
	return ids, nil
}
