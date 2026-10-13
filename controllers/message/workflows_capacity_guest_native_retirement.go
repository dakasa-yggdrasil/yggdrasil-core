//go:build linux && nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	current, err := store.Observe(original, policy)
	if err != nil || current.Phase != "draining" || current.Decision.Units != 1 {
		return nil, errOriginalGuestStep
	}
	assessment := q.QualificationAssessment(p, 1, 0.1, baseline.OriginalNativeAfterReturnedAt)
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: assessment, ObservedAt: baseline.OriginalNativeAfterReturnedAt, ReceiptRef: "original-baseline-useful-and-burst-quiescent:" + capacity.BusinessCreationSHA256(offWire), Healthy: true, Inflight: &zero}
	if _, err = store.Advance(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, "drained", proof); err != nil {
		return nil, err
	}
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
	grant, err := store.IssueMutation(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: wire})
	if err != nil {
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
