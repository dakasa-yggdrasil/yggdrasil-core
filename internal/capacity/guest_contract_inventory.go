package capacity

import (
	"fmt"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// GuestContractInventory retains one actual native return with the complete
// immutable contract against which it was read. It is an internal collection,
// not an adapter response, an atomic snapshot or a caller-selected authority.
type GuestContractInventory struct {
	ContractSHA256 string
	Inventory      model.CapacityVMFleetInventory
}

// GuestContractReconcileSnapshot validates every native return separately and
// derives a logical view only after the complete authorized set has answered.
// Repository callers must re-resolve contracts under the scope lock; these
// computational views never replace a stored Manifest.Spec or its checksum.
func GuestContractReconcileSnapshot(policy model.Manifest, p model.CapacityPolicySpec, contracts []model.CapacityPolicySpec, inventories []GuestContractInventory, now time.Time) (model.CapacitySnapshot, []int, error) {
	var empty model.CapacitySnapshot
	refuse := func() (model.CapacitySnapshot, []int, error) {
		return empty, nil, fmt.Errorf("complete original Guest contract inventories required")
	}
	if ValidateGuestNotifyReconcileBinding(p) != nil || p.GuestNotifyReconcileBinding == nil || len(contracts) == 0 || len(contracts) != len(inventories) || len(contracts) > p.Ceiling+1 {
		return refuse()
	}
	current := p.MutationBindings[0]
	currentContract := GuestProductionProfileContractSHA256(p, *p.GuestRetirementBinding, p.Profiles[0].Provider)
	if !ValidDigest(currentContract) || inventories[0].ContractSHA256 != currentContract {
		return refuse()
	}
	type contractIdentity struct {
		ContractSHA256, InstanceID, ScopeChecksum, AdmissionChecksum string
	}
	type nativeIdentity struct {
		Slot                               int
		ContractSHA256, ID, ResourceBornAt string
	}
	identities := make([]contractIdentity, 0, len(contracts))
	tuples := make([]nativeIdentity, 0, current.MaxSlots)
	seenContracts, seenInstances, seenIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenSlots := map[int]bool{}
	var oldest time.Time
	for i, view := range contracts {
		if ValidateGuestNotifyReconcileBinding(view) != nil || view.GuestNotifyReconcileBinding == nil || view.Owner != p.Owner || view.TargetIdentity != p.TargetIdentity || view.Environment != p.Environment || view.Domain != p.Domain || view.Profiles[0].Provider != p.Profiles[0].Provider || view.Profiles[0].Name != p.Profiles[0].Name {
			return refuse()
		}
		b := view.MutationBindings[0]
		hash := GuestProductionProfileContractSHA256(view, *view.GuestRetirementBinding, view.Profiles[0].Provider)
		if !ValidDigest(hash) || hash != inventories[i].ContractSHA256 || seenContracts[hash] || seenInstances[b.IntegrationInstanceID] || b.Name != current.Name || b.ProfileName != current.ProfileName || b.MaxSlots != current.MaxSlots || b.ProtectedSlots != current.ProtectedSlots {
			return refuse()
		}
		seenContracts[hash], seenInstances[b.IntegrationInstanceID] = true, true
		inv := inventories[i].Inventory
		snapshot, err := GuestReconcileSnapshot(policy, view, inv, now)
		if err != nil {
			return refuse()
		}
		if oldest.IsZero() || snapshot.ObservedAt.Before(oldest) {
			oldest = snapshot.ObservedAt
		}
		identities = append(identities, contractIdentity{hash, b.IntegrationInstanceID, b.ScopeChecksum, inv.AdmissionChecksum})
		for _, member := range inv.Members {
			// A missing slot in the current instance never masks a live member
			// from an earlier contract. Duplicate logical or physical ownership
			// refuses the whole assessment, including any floor repair.
			if seenSlots[member.Slot] || seenIDs[member.Server.ID] {
				return refuse()
			}
			seenSlots[member.Slot], seenIDs[member.Server.ID] = true, true
			tuples = append(tuples, nativeIdentity{member.Slot, hash, member.Server.ID, member.Server.CreatedAt})
		}
	}
	if !Fresh(oldest, now, p.MaxEvidenceAgeSeconds) {
		return refuse()
	}
	missing := make([]int, 0, current.MaxSlots-len(seenSlots))
	for slot := 1; slot <= current.MaxSlots; slot++ {
		if !seenSlots[slot] {
			missing = append(missing, slot)
		}
	}
	if len(contracts) == 1 {
		// Keep every legacy identity/fingerprint and decision byte unchanged.
		snapshot, err := GuestReconcileSnapshot(policy, p, inventories[0].Inventory, now)
		return snapshot, missing, err
	}
	sort.Slice(tuples, func(i, j int) bool { return tuples[i].Slot < tuples[j].Slot })
	setSHA := GuestRetirementSHA(identities)
	return model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, Owner: p.Owner, Profile: current.ProfileName, Units: len(tuples), ObservedAt: oldest,
		ResourceUID: "original-vm-contract-cohorts:" + setSHA, WorkloadUID: "original-guest-contract-cohorts:" + setSHA,
		ResourceVersion: GuestRetirementSHA(tuples), WorkloadResourceVersion: setSHA}, missing, nil
}
