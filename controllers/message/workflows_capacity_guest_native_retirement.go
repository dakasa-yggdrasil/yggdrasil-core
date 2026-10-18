//go:build linux && nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"sync"
	"time"
)

func sourceNativeBaseline(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (q.QualificationProbeReceipt, error) {
	var probe q.QualificationProbeReceipt
	if err := store.ValidateNativeObservationLease(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner); err != nil {
		return probe, err
	}
	current, err := store.Observe(ctx, policy)
	if err != nil || current.LeaseExpiresAt == nil || current.Generation != input.Generation || current.FencingToken != input.FencingToken {
		return probe, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, m := range p.GuestRetirementBinding.Members {
		if m.Slot == 1 {
			member = m
		}
	}
	client, err := sourceGuestClient(ctx, store.DB, member)
	if err != nil {
		return probe, err
	}
	defer client.Close()
	probe, err = originalGuestNativeRealm.Probe(ctx, store, policy, input.Generation, input.FencingToken, input.LeaseOwner, 1, key, client, *current.LeaseExpiresAt)
	if err != nil {
		return probe, err
	}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return probe, err
	}
	physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, 1, b)
	if err != nil {
		return probe, err
	}
	var spec *model.CapacityMutationSpecV1
	for _, slot := range b.Slots {
		if slot.Slot == 1 {
			spec = slot.DesiredSpec
		}
	}
	if spec == nil {
		return probe, errOriginalGuestStep
	}
	wire, _ := json.Marshal(spec)
	err = store.RecordMutationSlot(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, physical)
	return probe, err
}

func guestOriginalSourceBeforeRetirement(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (func() error, error) {
	if originalGuestNativeRealm == nil || input.Slot != 2 || !q.RetirementCase(originalGuestNativeRealm.Request.NativeCase) {
		return nil, errOriginalGuestStep
	}
	if _, err := sourceNativeBaseline(ctx, store, policy, p, input, key); err != nil {
		return nil, err
	}
	if err := originalGuestNativeRealm.PinOriginalRetirement(ctx, 2); err != nil {
		return nil, err
	}
	original, cancel := context.WithCancel(ctx)
	returned := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-original.Done():
				returned <- nil
				return
			case <-ticker.C:
				if _, err := sourceNativeBaseline(original, store, policy, p, input, key); err != nil {
					if original.Err() != nil {
						returned <- nil
					} else {
						returned <- err
					}
					return
				}
			}
		}
	}()
	var once sync.Once
	var joined error
	join := func() error {
		once.Do(func() {
			cancel()
			// Cancellation requests the SAME keeper's stop; only its actual
			// return releases the workflow's DB/HTTP/native owners.
			joined = <-returned
		})
		return joined
	}
	return join, nil
}

func sourceGuestNativeRetirementFinished(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (any, error) {
	if input.Slot != 2 || input.RequestID == "" || input.PreregistrationID == "" || originalGuestNativeRealm == nil {
		return nil, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, m := range p.GuestRetirementBinding.Members {
		if m.Slot == 2 {
			member = m
		}
	}
	// Source records name the exact original request. No latest/replacement ID
	// or missing response can be turned into a second retirement POST.
	var intentSHA string
	if err := store.DB.QueryRowContext(ctx, `SELECT intent_sha256 FROM public.capacity_vm_retirement_intents WHERE id=$1 AND preregistration_id=$2`, input.RequestID, input.PreregistrationID).Scan(&intentSHA); err != nil {
		return nil, err
	}
	stored, err := store.GuestRetirementOriginal(ctx, member.ActorClientPrincipal, input.RequestID, intentSHA)
	if err != nil {
		return nil, err
	}
	original, cancel := context.WithDeadline(ctx, stored.Request.Intent.OriginalDeadline)
	defer cancel()
	offWire, pidfdWire, err := originalGuestNativeRealm.OriginalNativeOff(original)
	if err != nil {
		return nil, err
	}
	baseline, err := sourceNativeBaseline(original, store, policy, p, input, key)
	if err != nil {
		return nil, err
	}
	if err = store.RecordGuestNativeQEMUPoweroff(original, input.RequestID, offWire, pidfdWire); err != nil {
		return nil, err
	}
	// Actual enrolled, quiescent and powered-off original success remains
	// ineligible for failed-create compensation; never relabel it as failed.
	if err = store.AssertOriginalSuccessfulParentNotCompensable(original, policy, stored.Preregistration.OriginalCreateGrantID); err != nil {
		return nil, err
	}
	current, err := store.Observe(original, policy)
	if err != nil || current.Phase != "draining" || current.Decision.Units != 1 {
		return nil, errOriginalGuestStep
	}
	assessment := q.QualificationAssessment(p, 1, 0.1, baseline.OriginalNativeAfterReturnedAt)
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: baseline.OriginalNativeAfterReturnedAt, ReceiptRef: "original-baseline-useful-and-burst-quiescent:" + capacity.BusinessCreationSHA256(offWire), Healthy: true, Inflight: &zero}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return nil, err
	}
	var spec *model.CapacityMutationSpecV1
	for _, slot := range b.Slots {
		if slot.Slot == 2 && slot.DesiredSpec != nil {
			copy := *slot.DesiredSpec
			spec = &copy
		}
	}
	if spec == nil {
		return nil, errOriginalGuestStep
	}
	spec.Capability = b.DestroyCapability
	spec.ExpectedResourceID = stored.Request.Intent.Tuple.ResourceID
	spec.ExpectedResourceCreatedAt = stored.Request.Intent.Tuple.CreatedAt
	wire, _ := json.Marshal(spec)
	burstIssue := model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}
	// The unchanged real intent is still draining. No caller writes phase or
	// grants: the original method must reject a physical delete before drain.
	if _, err = store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return nil, errOriginalGuestStep
	}
	if _, err = store.Advance(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, "drained", proof); err != nil {
		return nil, err
	}
	baselineIssue, err := sourceNativeProtectedDestroyIssue(original, p, b)
	if err != nil {
		return nil, err
	}
	if _, err = store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, baselineIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return nil, errOriginalGuestStep
	}
	grant, err := store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue)
	if err != nil {
		return nil, err
	}
	if err = sourceNativePendingDeleteContract(original, store, policy, p, b, input, burstIssue, baselineIssue, grant); err != nil {
		return nil, err
	}
	observed, err := originalGuestNativeRealm.DestroyOriginal(original, grant)
	if err != nil {
		return nil, err
	}
	if err = store.RecordGuestNativeQEMUDeleteReadback(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, observed); err != nil {
		return nil, err
	}
	receipt, err := originalGuestNativeRealm.OriginalMutationReceipt(original, grant.GrantID)
	if err != nil {
		return nil, err
	}
	nativeProof, err := repository.GuestNativeQEMUDeleteProof(p, b, receipt, observed, time.Now().UTC(), "original-native-qemu-disk-delete:"+capacity.GuestRetirementSHA(observed))
	if err != nil {
		return nil, err
	}
	confirmed, err := store.ConfirmMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, nativeProof)
	if err != nil {
		return nil, err
	}
	if err = sourceNativeConfirmedDeleteContract(original, store, policy, p, b, input, nativeProof, confirmed); err != nil {
		return nil, err
	}
	baseline, err = sourceNativeBaseline(original, store, policy, p, input, key)
	if err != nil {
		return nil, err
	}
	proof.Assessment = q.QualificationAssessment(p, 1, 0.1, baseline.OriginalNativeAfterReturnedAt)
	proof.ObservedAt = baseline.OriginalNativeAfterReturnedAt
	proof.ReceiptRef = "original-post-delete-baseline-useful:" + capacity.GuestRetirementSHA(baseline)
	if _, err = store.Advance(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, "promoted", proof); err != nil {
		return nil, err
	}
	return struct {
		RequestID                  string                      `json:"request_id"`
		DestroyGrant               model.CapacityMutationGrant `json:"destroy_grant"`
		NativeOffSHA256            string                      `json:"native_off_sha256"`
		NativeDeleteReadbackSHA256 string                      `json:"native_delete_readback_sha256"`
		BaselineUsefulSHA256       string                      `json:"baseline_useful_sha256"`
		Scope                      string                      `json:"scope"`
	}{input.RequestID, confirmed, capacity.BusinessCreationSHA256(offWire), capacity.GuestRetirementSHA(observed), capacity.GuestRetirementSHA(baseline), "original_native_qemu_only_not_physical_provider_or_production20"}, nil
}

// The protected baseline identity comes from the real independent native read,
// never from a caller resource name or an invented desired expected tuple.
func sourceNativeProtectedDestroyIssue(ctx context.Context, p model.CapacityPolicySpec, b model.CapacityMutationBinding) (model.CapacityMutationIssue, error) {
	var issue model.CapacityMutationIssue
	physical, err := originalGuestNativeRealm.FreshNativeMember(ctx, 1, b)
	if err != nil || physical.Slot != 1 || physical.ResourceAbsent || physical.ResourceID == "" || physical.ResourceCreatedAt == "" {
		return issue, errOriginalGuestStep
	}
	for _, slot := range b.Slots {
		if slot.Slot == 1 && slot.DesiredSpec != nil {
			spec := *slot.DesiredSpec
			spec.Capability = b.DestroyCapability
			spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = physical.ResourceID, physical.ResourceCreatedAt
			wire, err := json.Marshal(spec)
			if err != nil {
				return issue, err
			}
			return model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire}, nil
		}
	}
	return issue, errOriginalGuestStep
}

func sourceNativePendingDeleteContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, burstIssue, baselineIssue model.CapacityMutationIssue, grant model.CapacityMutationGrant) error {
	current, err := store.Observe(ctx, policy)
	if err != nil || current.Phase != "drained" || current.Decision.Units != 1 || p.Floor != 1 || b.ProtectedSlots != 1 || b.MaxSlots != 2 || grant.Slot != 2 || grant.Capability != b.DestroyCapability {
		return errOriginalGuestStep
	}
	repeated, err := store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, burstIssue)
	if err != nil || capacity.GuestRetirementSHA(repeated) != capacity.GuestRetirementSHA(grant) {
		return errOriginalGuestStep
	}
	if _, err = store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, baselineIssue); !errors.Is(err, repository.ErrCapacityConflict) {
		return errOriginalGuestStep
	}
	var live, pending, creates int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&live); err != nil {
		return err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'capability'=$5),count(*) FILTER(WHERE state IN ('issued','redeemed','settled','compensating') AND grant_record->'grant'->>'capability'=$6) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.DestroyCapability, b.EnsureCapability).Scan(&pending, &creates); err != nil {
		return err
	}
	if live != 2 || pending != 1 || creates != 0 || live-pending != current.Decision.Units || live-pending != p.Floor || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	contract := struct {
		Schema string `json:"schema"`
		CoreSource string `json:"core_source"`
		GrantID string `json:"grant_id"`
		Live int `json:"live_members"`
		Pending int `json:"pending_deletes"`
		PendingCreates int `json:"pending_creates"`
		Floor int `json:"protected_floor"`
		Target int `json:"target_units"`
		UndrainedRefused bool `json:"undrained_delete_refused"`
		FloorRefused bool `json:"protected_delete_refused"`
		ReplaySame bool `json:"pending_replay_same_grant"`
	}{"original_guest_two_slot_delete_budget_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, live, pending, creates, p.Floor, current.Decision.Units, true, true, true}
	_, err = q.Publish(ctx, filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 2), "delete-budget-contract.json"), contract)
	return err
}

func sourceNativeConfirmedDeleteContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, input guestOriginalStepInput, proof model.CapacityMutationProof, confirmed model.CapacityMutationGrant) error {
	// Re-use exactly the authentic independent absence proof; no re-observation,
	// copied resource-presence assertion or timestamp refresh is manufactured.
	repeated, err := store.ConfirmMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, proof)
	if err != nil || capacity.GuestRetirementSHA(repeated) != capacity.GuestRetirementSHA(confirmed) || confirmed.State != "confirmed" {
		return errOriginalGuestStep
	}
	var tombstone bool
	var resource, created string
	if err = store.DB.QueryRowContext(ctx, `SELECT COALESCE((slot_record->>'tombstone')::boolean,false),resource_id,slot_record->>'resource_created_at' FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND integration_instance_id=$5 AND scope_checksum=$6 AND profile_name=$7 AND slot=2`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName).Scan(&tombstone, &resource, &created); err != nil {
		return err
	}
	var events int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE metadata->>'namespace'=$1 AND idempotency_key=$2`, policy.Metadata.Namespace, "capacity-mutation/"+confirmed.GrantID).Scan(&events); err != nil {
		return err
	}
	if !tombstone || resource != "" || created != proof.ResourceCreatedAt || events != 1 || ctx.Err() != nil {
		return errOriginalGuestStep
	}
	contract := struct {
		Schema string `json:"schema"`
		CoreSource string `json:"core_source"`
		GrantID string `json:"grant_id"`
		ResourceID string `json:"original_resource_id"`
		ResourceCreatedAt string `json:"original_resource_created_at"`
		ProofSHA256 string `json:"absence_proof_sha256"`
		CanonicalEvents int `json:"canonical_events"`
		Tombstone bool `json:"tombstone"`
		ResourceCleared bool `json:"resource_cleared"`
		SameProofReplay bool `json:"same_absence_proof_replay"`
	}{"original_guest_native_delete_tombstone_v1", capacity.CurrentGuestCoreSource(), confirmed.GrantID, proof.ResourceID, proof.ResourceCreatedAt, capacity.GuestRetirementSHA(proof), events, tombstone, resource == "", true}
	_, err = q.Publish(ctx, filepath.Join(q.SlotDirectory(originalGuestNativeRealm.PrivateDirectory, 2), "delete-tombstone-contract.json"), contract)
	return err
}
