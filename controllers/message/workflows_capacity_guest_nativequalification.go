//go:build linux && nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

var originalGuestNativeRealm *capacitynativeqemu.Realm
var originalGuestNativeInstall sync.Once

// Called once BEFORE the real Core API starts. This constructor is absent
// from production binaries and cannot be selected by a workflow input.
func InstallOriginalGuestNativeFixture(realm *capacitynativeqemu.Realm) error {
	installed := false
	originalGuestNativeInstall.Do(func() {
		if realm != nil {
			originalGuestNativeRealm = realm
			originalGuestSourceProvider = realm
			installed = true
		}
	})
	if !installed {
		return errOriginalGuestStep
	}
	return nil
}
func guestOriginalSourceLimit(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return ctx, func() {}, errOriginalGuestStep
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}, errOriginalGuestStep
	}
	if originalGuestNativeRealm.Request.OriginalContextDeadline.Before(deadline) {
		deadline = originalGuestNativeRealm.Request.OriginalContextDeadline
	}
	if !time.Now().UTC().Before(deadline) {
		return ctx, func() {}, errOriginalGuestStep
	}
	original, cancel := context.WithDeadline(ctx, deadline)
	return original, cancel, nil
}
func guestOriginalSourceEnrolled(ctx context.Context, g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration, r model.CapacityGuestOriginalProvisioningReceipt) error {
	if originalGuestNativeRealm == nil {
		return errOriginalGuestStep
	}
	return originalGuestNativeRealm.Enrolled(ctx, g, p, r)
}
func guestOriginalSourceWitnessed(ctx context.Context, g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration, w model.CapacityGuestOriginalCreateWitness) error {
	if originalGuestNativeRealm == nil {
		return errOriginalGuestStep
	}
	return originalGuestNativeRealm.Witnessed(ctx, g, p, w)
}

func sourceGuestQualificationStep(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey, operation string) (any, error) {
	if originalGuestNativeRealm == nil || p.GuestRetirementBinding == nil || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, "native-qemu") {
		return nil, errOriginalGuestStep
	}
	if operation == "capacity.finish_original_guest_retirement" {
		return sourceGuestNativeRetirementFinished(ctx, store, policy, p, input, key)
	}
	current, err := store.Observe(ctx, policy)
	if err != nil || current.LeaseExpiresAt == nil || current.Generation != input.Generation || current.FencingToken != input.FencingToken || current.Phase != "preparing" {
		return nil, errOriginalGuestStep
	}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return nil, errOriginalGuestStep
	}
	slots := originalGuestNativeRealm.OwnedSlots()
	if len(slots) != current.Decision.Units {
		return nil, errOriginalGuestStep
	}
	var probes []capacitynativeqemu.QualificationProbeReceipt
	for _, slot := range slots {
		member := model.CapacityGuestRetirementMemberBinding{}
		for _, m := range p.GuestRetirementBinding.Members {
			if m.Slot == slot {
				member = m
			}
		}
		if member.Name == "" {
			return nil, errOriginalGuestStep
		}
		client, err := sourceGuestClient(ctx, store.DB, member)
		if err != nil {
			return nil, err
		}
		probe, err := originalGuestNativeRealm.Probe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, slot, key, client, *current.LeaseExpiresAt)
		client.Close()
		if err != nil {
			return nil, err
		}
		probes = append(probes, probe)
		physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, slot, b)
		if err != nil {
			return nil, err
		}
		var projection *model.CapacityMutationSpecV1
		for _, approved := range b.Slots {
			if approved.Slot == slot {
				projection = approved.DesiredSpec
			}
		}
		if projection == nil {
			return nil, errOriginalGuestStep
		}
		wire, err := json.Marshal(projection)
		if err != nil {
			return nil, err
		}
		if err = store.RecordMutationSlot(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, physical); err != nil {
			return nil, err
		}
	}
	// Healthy is restricted to the ACTUAL admitted source echo profile. Each
	// same original writer just served its bounded challenge; native/count or
	// a signed census alone cannot produce this phase receipt.
	at := time.Now().UTC()
	assessment := capacitynativeqemu.QualificationAssessment(p, len(probes), 0.9, at)
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: at, ReceiptRef: "original-native-useful-echo:" + capacity.GuestRetirementSHA(probes), Healthy: len(probes) == len(slots) && len(probes) > 0, Inflight: &zero}
	for _, phase := range []string{"prepared", "canary", "promoted"} {
		if _, err = store.Advance(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, phase, proof); err != nil {
			return nil, err
		}
	}
	return struct {
		Scope                             string                                         `json:"scope"`
		UsefulEchoProbes                  []capacitynativeqemu.QualificationProbeReceipt `json:"useful_echo_probes"`
		ProductionUsefulCapacityQualified bool                                           `json:"production_useful_capacity_qualified"`
	}{"same_original_qualification_echo_profile_only", probes, false}, nil
}
