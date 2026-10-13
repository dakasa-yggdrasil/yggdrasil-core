package capacity

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const (
	VMObserveInventory      = "observe_fleet_inventory"
	VMObserveFailedCreation = "observe_failed_server_creation"
	VMObserveServer         = "observe_servers"
	VMObserveAction         = "observe_server_action"
)

// DecodeVMObservation accepts only the pinned closed VM protocol. Neither a
// workflow-supplied map nor unknown secret/evidence fields can become a proof.
func DecodeVMObservation(value any, out any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2<<20 {
		return fmt.Errorf("native observation is invalid or exceeds its bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return fmt.Errorf("native VM observation schema mismatch")
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("native VM observation has trailing data")
	}
	return nil
}

func VMObservationBinding(p model.CapacityPolicySpec, name string) (model.CapacityMutationBinding, error) {
	for _, b := range p.MutationBindings {
		if b.Name == name {
			return b, nil
		}
	}
	return model.CapacityMutationBinding{}, fmt.Errorf("native observation binding is outside policy scope")
}

func vmApprovedSlot(b model.CapacityMutationBinding, slot int) (model.CapacityMutationSlotBinding, error) {
	for _, s := range b.Slots {
		if s.Slot == slot && s.DesiredSpec != nil {
			return s, nil
		}
	}
	return model.CapacityMutationSlotBinding{}, fmt.Errorf("native observation slot is not explicitly approved")
}

func vmTime(raw string, p model.CapacityPolicySpec, now time.Time) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || at.UTC().Format(time.RFC3339Nano) != raw || !Fresh(at, now, p.MaxEvidenceAgeSeconds) {
		return at, fmt.Errorf("native observation timestamp is missing, stale or noncanonical")
	}
	return at, nil
}

func vmNoAuthority(plan model.CapacityVMFleetPlan) error {
	if plan.ProviderFencingEvidence || plan.WarmReadinessEvidence || plan.BusinessReadyEvidence {
		return fmt.Errorf("native VM read cannot claim fencing, warmth or business readiness")
	}
	return nil
}

func vmProjection(b model.CapacityMutationBinding, slot int, spec model.CapacityMutationSpecV1) (model.CapacityMutationSlotBinding, error) {
	approved, err := vmApprovedSlot(b, slot)
	if err != nil {
		return approved, err
	}
	spec.Capability = b.EnsureCapability
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = "", ""
	if spec != *approved.DesiredSpec {
		return approved, fmt.Errorf("native desired projection differs from the exact approved slot")
	}
	return approved, nil
}

func vmLabelDigest(digest string) string {
	raw, err := hex.DecodeString(digest)
	if err != nil {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
}

func vmServer(p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot model.CapacityMutationSlotBinding, s model.CapacityVMServerObservation, partial bool, now time.Time) (time.Time, error) {
	at, err := vmTime(s.ObservedAt, p, now)
	if err != nil {
		return at, err
	}
	created, e := time.Parse(time.RFC3339Nano, s.CreatedAt)
	if e != nil || created.IsZero() || created.After(now.Add(5*time.Second)) || created.UTC().Format(time.RFC3339Nano) != s.CreatedAt || s.ID == "" || len(s.ID) > 128 || strings.ContainsAny(s.ID, "/ \t\r\n") || s.Name != slot.DesiredSpec.NativeName || s.Labels == nil || s.Labels["yggdrasil.io/owner"] == "" || s.Labels["yggdrasil.io/scope"] != vmLabelDigest(b.ScopeChecksum) || s.Labels["yggdrasil.io/spec"] != vmLabelDigest(slot.DesiredSpec.ProfileChecksum) || s.Labels["yggdrasil.io/profile"] != b.ProfileName || s.Labels["yggdrasil.io/slot"] != strconv.Itoa(slot.Slot) {
		return at, fmt.Errorf("native server immutable identity, owner or approved scope differs")
	}
	for key, value := range s.Labels {
		if len(value) > 128 || (key != "yggdrasil.io/owner" && key != "yggdrasil.io/scope" && key != "yggdrasil.io/spec" && key != "yggdrasil.io/profile" && key != "yggdrasil.io/slot" && key != "yggdrasil.io/intent") {
			return at, fmt.Errorf("native observation label is outside the closed slot protocol")
		}
	}
	if partial {
		if s.PhysicalSpecVerified || !s.CompensationIdentityVerified {
			return at, fmt.Errorf("failed partial lifetime cannot claim a verified physical spec")
		}
	} else if !s.PhysicalSpecVerified || s.CompensationIdentityVerified {
		return at, fmt.Errorf("normal native member lacks verified physical configuration")
	}
	return at, nil
}

// VMInventoryProofs validates complete physical membership. It deliberately
// produces no CapacityAssessment, healthy floor or useful unit count.
func VMInventoryProofs(p model.CapacityPolicySpec, b model.CapacityMutationBinding, inv model.CapacityVMFleetInventory, parentID string, failedSlot int, now time.Time, receipt string) ([]model.CapacityMutationProof, error) {
	started, err := vmTime(inv.ObservationStartedAt, p, now)
	if err != nil {
		return nil, err
	}
	finished, err := vmTime(inv.ObservedAt, p, now)
	if err != nil || finished.Before(started) || finished.Sub(started) > 65*time.Second {
		return nil, fmt.Errorf("native inventory window is incomplete or outside bounds")
	}
	if !inv.Complete || inv.AtomicProviderSnapshot || inv.ProviderFencingEvidence || inv.WarmReadinessEvidence || inv.BusinessReadyEvidence || inv.IntegrationInstanceID != b.IntegrationInstanceID || inv.ScopeChecksum != b.ScopeChecksum || inv.ProfileName != b.ProfileName || inv.ProtectedSlots != b.ProtectedSlots || inv.MaxSlots != b.MaxSlots || len(inv.Members) > b.MaxSlots || len(inv.MissingSlots) > b.MaxSlots {
		return nil, fmt.Errorf("native inventory completeness, scope or authority mismatch")
	}
	if len(b.Slots) == 0 || b.Slots[0].DesiredSpec == nil || inv.ProfileChecksum != b.Slots[0].DesiredSpec.ProfileChecksum || inv.AdmissionChecksum != b.Slots[0].DesiredSpec.AdmissionChecksum {
		return nil, fmt.Errorf("native inventory profile revision differs, including empty membership")
	}
	if (parentID == "") != (inv.FailedCreation == nil) || (parentID != "" && (inv.FailedCreation.ParentGrantID != parentID || failedSlot < 1)) {
		return nil, fmt.Errorf("native unresolved candidate differs from fixed requested parent")
	}
	seenSlots, seenIDs := map[int]bool{}, map[string]bool{}
	failedMemberSeen := false
	proofs := []model.CapacityMutationProof{}
	for _, member := range inv.Members {
		if member.Slot < 1 || member.Slot > b.MaxSlots || seenSlots[member.Slot] || seenIDs[member.Server.ID] || member.Protected != (member.Slot <= b.ProtectedSlots) || member.Unresolved != (parentID != "" && member.Slot == failedSlot) {
			return nil, fmt.Errorf("native inventory member duplicated, out of bounds or ambiguously unresolved")
		}
		slot, err := vmProjection(b, member.Slot, member.DesiredSpec)
		if err != nil || member.DesiredSpec.Capability != b.EnsureCapability || member.DesiredSpec.ExpectedResourceID != "" || member.DesiredSpec.ExpectedResourceCreatedAt != "" || member.RequestSHA256 != slot.DesiredSpecSHA256 || inv.ProfileChecksum != slot.DesiredSpec.ProfileChecksum || inv.AdmissionChecksum != slot.DesiredSpec.AdmissionChecksum {
			return nil, fmt.Errorf("native inventory projection or revision mismatch")
		}
		at, err := vmServer(p, b, slot, member.Server, member.Unresolved, now)
		if err != nil {
			return nil, err
		}
		seenSlots[member.Slot], seenIDs[member.Server.ID] = true, true
		if member.Unresolved {
			failedMemberSeen = true
			failed, err := VMFailedCreationProof(p, b, *inv.FailedCreation, parentID, failedSlot, now, receipt)
			if err != nil || failed.ResourceID != member.Server.ID || failed.ResourceCreatedAt != member.Server.CreatedAt {
				return nil, fmt.Errorf("unresolved member differs from authenticated failed candidate")
			}
			continue
		}
		proofs = append(proofs, model.CapacityMutationProof{BindingName: b.Name, Slot: member.Slot, RequestSHA256: slot.DesiredSpecSHA256, ResourceID: member.Server.ID, ResourceCreatedAt: member.Server.CreatedAt, OwnerVerified: true, SpecVerified: true, ObservedAt: at, ReceiptRef: receipt})
	}
	for _, slot := range inv.MissingSlots {
		if slot < 1 || slot > b.MaxSlots || seenSlots[slot] {
			return nil, fmt.Errorf("native missing-slot partition duplicated or outside bounds")
		}
		seenSlots[slot] = true
	}
	if len(seenSlots) != b.MaxSlots || (parentID != "" && !failedMemberSeen) {
		return nil, fmt.Errorf("native inventory does not cover every configured slot")
	}
	return proofs, nil
}

// VMServerPlanProof handles only native identity/spec evidence. An absent
// destroy read verifies the approved historical tuple, never a current physical
// server or the absence of delayed provider writers.
func VMServerPlanProof(p model.CapacityPolicySpec, b model.CapacityMutationBinding, plan model.CapacityVMFleetPlan, r model.CapacityMutationReceipt, status string, now time.Time, receipt string) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	g := r.Grant
	if !r.TransportCompleted || (r.Outcome != "accepted" && r.Outcome != "uncertain") || g.CompensationOf != "" || g.BindingName != b.Name || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || (g.Capability != b.EnsureCapability && g.Capability != b.DestroyCapability) {
		return proof, fmt.Errorf("native readback has no exact settled owning transport")
	}
	slot, err := vmProjection(b, g.Slot, plan.DesiredSpec)
	if err != nil || plan.DesiredSpec.Capability != VMObserveServer || vmNoAuthority(plan) != nil || plan.CompensationOf != "" || plan.CompensationIdentityVerified || plan.Protected != (g.Slot <= b.ProtectedSlots) {
		return proof, fmt.Errorf("native server plan differs from approved ordinary slot")
	}
	at, err := vmTime(plan.ObservedAt, p, now)
	if err != nil {
		return proof, err
	}
	proof = model.CapacityMutationProof{GrantID: g.GrantID, BindingName: b.Name, Slot: g.Slot, RequestSHA256: g.RequestSHA256, ObservedAt: at, ReceiptRef: receipt, OwnerVerified: true, SpecVerified: true}
	if plan.Server == nil {
		if status != "absent" || g.Capability != b.DestroyCapability || g.ExpectedResourceID == "" || g.ExpectedResourceCreatedAt == "" || plan.DesiredSpec.ExpectedResourceID != g.ExpectedResourceID || plan.DesiredSpec.ExpectedResourceCreatedAt != g.ExpectedResourceCreatedAt || !r.AuxiliaryInventoryComplete {
			return proof, fmt.Errorf("absent native server lacks exact historical destroy authority")
		}
		proof.ResourceID, proof.ResourceCreatedAt, proof.ResourceAbsent = g.ExpectedResourceID, g.ExpectedResourceCreatedAt, true
		seen := map[string]bool{}
		for _, aux := range plan.AuxiliaryResources {
			if !aux.Absent || aux.Kind == "" || aux.ID == "" || seen[aux.Kind+"/"+aux.ID] {
				return proof, fmt.Errorf("auxiliary absence is incomplete or duplicated")
			}
			if _, err := vmTime(aux.ObservedAt, p, now); err != nil {
				return proof, err
			}
			seen[aux.Kind+"/"+aux.ID] = true
			proof.AuxiliaryAbsent = append(proof.AuxiliaryAbsent, model.CapacityMutationAuxiliaryResource{Kind: aux.Kind, ID: aux.ID, RequiresAbsence: true})
		}
		if len(plan.AuxiliaryResources) > 16 {
			return proof, fmt.Errorf("auxiliary absence exceeds its bound")
		}
		for _, aux := range r.AuxiliaryResources {
			if aux.RequiresAbsence && !seen[aux.Kind+"/"+aux.ID] {
				return proof, fmt.Errorf("persisted auxiliary absence is missing")
			}
		}
	} else {
		if status != "observed" || g.Capability != b.EnsureCapability {
			return proof, fmt.Errorf("native mutation has not reached its observed target")
		}
		if _, err := vmServer(p, b, slot, *plan.Server, false, now); err != nil {
			return proof, err
		}
		if plan.Server.Labels["yggdrasil.io/intent"] != g.GrantID {
			return proof, fmt.Errorf("native creation lacks owning grant label")
		}
		proof.ResourceID, proof.ResourceCreatedAt = plan.Server.ID, plan.Server.CreatedAt
		proof.ObservedCreationGrantID = g.GrantID
	}
	if r.ResourceID != "" && (r.ResourceID != proof.ResourceID || r.ResourceCreatedAt != proof.ResourceCreatedAt) {
		return proof, fmt.Errorf("native lifetime differs from owning settlement")
	}
	return proof, nil
}

func VMFailedCreationProof(p model.CapacityPolicySpec, b model.CapacityMutationBinding, c model.CapacityVMFailedCreationCandidate, parentID string, slotNumber int, now time.Time, receipt string) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	slot, err := vmProjection(b, slotNumber, c.Plan.DesiredSpec)
	if err != nil {
		return proof, err
	}
	if err = vmNoAuthority(c.Plan); err != nil {
		return proof, err
	}
	if c.ParentGrantID != parentID || c.Plan.DesiredSpec.Capability != b.EnsureCapability || c.Plan.DesiredSpec.ExpectedResourceID != "" || c.Plan.DesiredSpec.ExpectedResourceCreatedAt != "" || c.Plan.Protected != (slotNumber <= b.ProtectedSlots) || c.Plan.CompensationOf != "" || c.Plan.RequestSHA256 != slot.DesiredSpecSHA256 || c.Plan.Server == nil || !c.Plan.CompensationIdentityVerified || !c.ActionHistoryComplete || !c.ActionsTerminal || !c.ActionsFailed || c.NativeActionsInflight != 0 || !c.Actions.Complete || c.Actions.CreationGrantID != parentID || c.Actions.ResourceID != c.Plan.Server.ID || c.Actions.ResourceCreatedAt != c.Plan.Server.CreatedAt || c.Plan.Server.Labels["yggdrasil.io/intent"] != parentID {
		return proof, fmt.Errorf("failed candidate source or complete history mismatch")
	}
	if _, err := vmTime(c.Plan.ObservedAt, p, now); err != nil {
		return proof, err
	}
	at, err := vmServer(p, b, slot, *c.Plan.Server, true, now)
	if err != nil {
		return proof, err
	}
	ids, err := VMActionProof(p, c.Actions, c.Plan.Server.ID, now, false)
	if err != nil {
		return proof, err
	}
	proof = model.CapacityMutationProof{GrantID: parentID, BindingName: b.Name, Slot: slotNumber, RequestSHA256: slot.DesiredSpecSHA256, ResourceID: c.Plan.Server.ID, ResourceCreatedAt: c.Plan.Server.CreatedAt, OwnerVerified: true, CompensationIdentityVerified: true, ObservedCreationGrantID: parentID, ActionIDs: ids, ActionsTerminal: true, ActionsFailed: true, ActionHistoryComplete: true, ObservedAt: at, ReceiptRef: receipt}
	return proof, nil
}

func VMActionProof(p model.CapacityPolicySpec, c model.CapacityVMActionCollection, resourceID string, now time.Time, success bool) ([]string, error) {
	if !c.Complete || c.ResourceID != resourceID || len(c.Actions) == 0 || len(c.Actions) > 64 {
		return nil, fmt.Errorf("native action collection is incomplete or mismatched")
	}
	if _, err := vmTime(c.ObservedAt, p, now); err != nil {
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
		if _, err := vmTime(action.ObservedAt, p, now); err != nil {
			return nil, err
		}
		start, e1 := time.Parse(time.RFC3339Nano, action.StartedAt)
		end, e2 := time.Parse(time.RFC3339Nano, action.FinishedAt)
		if e1 != nil || e2 != nil || start.IsZero() || start.UTC().Format(time.RFC3339Nano) != action.StartedAt || end.UTC().Format(time.RFC3339Nano) != action.FinishedAt || start.Before(created.Add(-5*time.Second)) || end.Before(start) || end.After(now.Add(5*time.Second)) {
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
