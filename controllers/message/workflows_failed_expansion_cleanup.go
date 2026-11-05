//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func planFailedExpansionCleanup(ctx context.Context, store repository.CapacityStore, policy, wf model.Manifest, step model.WorkflowStepSpec) (any, bool, error) {
	store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	selected, current, a, handled, err := store.TryClaimFailedExpansionCleanup(ctx, policy)
	if err != nil || !handled {
		return nil, handled, err
	}
	if current.Phase == "hold" && current.LeaseExpiresAt == nil {
		return map[string]any{"mode": "hold", "reason": "failed_expansion_cleaned_original_failure_preserved", "cleanup_id": a.ID, "original_guest_success": false, "clean_cycle_credit": false}, true, nil
	}
	deadline, err := selected.OriginalGuestReconcileLeaseDeadline(ctx, policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || captureOriginalGuestReconcileDeadline(ctx, deadline) != nil {
		return nil, true, errOriginalGuestStep
	}
	return originalGuestReconcilePlan{Mode: "retire", Reason: repository.FailedUnwitnessedExpansionCleanupMode, Slot: a.Slot, Generation: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, PreregistrationID: a.PreregistrationID}, true, nil
}

func failedExpansionResult(a repository.FailedUnwitnessedExpansionCleanup) map[string]any {
	return map[string]any{"request_id": a.ID, "cleanup_id": a.ID, "original_create_grant_id": a.GrantID, "cleanup_destroy_grant_id": a.ChildGrantID, "original_failure_preserved": true, "original_guest_success": false, "normal_guest_success": false, "clean_cycle_credit": false, "serving_or_business_or_savings_authority": false}
}

func refreshFailedExpansionSurvivors(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput) error {
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return err
	}
	supplier, err := productionRetirementSupplierV2(ctx, store, policy, p, b, input)
	if err != nil || supplier.provider != "aws" {
		return errOriginalGuestStep
	}
	var inv model.CapacityVMFleetInventory
	status, err := supplier.call(ctx, capacity.VMObserveInventory, map[string]any{"profile": b.ProfileName}, &inv)
	if err != nil || status != "observed" {
		return errOriginalGuestStep
	}
	return store.RefreshFailedExpansionSurvivors(ctx, policy, inv)
}

// Only the existing registered retire/finish steps select this typed lane.
// The unwitnessed target is never given a Guest command or enrollment credit.
func executeFailedExpansionCleanupStep(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input guestOriginalStepInput, key ed25519.PrivateKey, finish bool) (any, bool, error) {
	store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	selected, a, handled, err := store.BindFailedExpansionCleanup(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner)
	if err != nil || !handled {
		return nil, handled, err
	}
	if a.PreregistrationID != input.PreregistrationID || a.Slot != input.Slot || finish && input.RequestID != a.ID || !finish && input.RequestID != "" {
		return nil, true, errOriginalGuestStep
	}
	if !finish {
		if err = refreshFailedExpansionSurvivors(ctx, selected, policy, p, input); err != nil {
			return nil, true, err
		}
		if err = failedExpansionSurvivorCanaries(ctx, db, selected, policy, p, input, key, "before_retirement_floor"); err != nil {
			return nil, true, err
		}
		return failedExpansionResult(a), true, nil
	}
	original, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	b, err := capacity.VMObservationBinding(p, a.BindingName)
	if err != nil {
		return nil, true, err
	}
	supplier, err := productionRetirementSupplierV2(original, selected, policy, p, b, input)
	if err != nil || supplier.provider != "aws" || !productionRetirementCatalogV2("aws", supplier.resolved.typeSpec) {
		return nil, true, errOriginalGuestStep
	}
	receipt, found, err := selected.FailedExpansionDestroyReceipt(original, policy)
	if err != nil {
		return nil, true, err
	}
	sent := false
	if !found {
		if _, _, err = sourceFailedExpansionRead(original, selected, policy, p, input, a, supplier, "inventory"); err != nil {
			return nil, true, err
		}
		grant, err := selected.IssueFailedExpansionDestroy(original, policy)
		if err != nil {
			return nil, true, err
		}
		// This commit precedes the ONE native call. Unknown acknowledgement stops;
		// neither a failed return nor a later workflow can replay the grant/send.
		if err = selected.MarkFailedExpansionPossibleSend(original, policy); err != nil {
			return nil, true, err
		}
		sent = true
		var returned struct {
			Plan          model.CapacityVMFleetPlan `json:"plan"`
			ActionID      string                    `json:"action_id"`
			NextActionIDs []string                  `json:"next_action_ids"`
		}
		status, callErr := supplier.call(original, b.DestroyCapability, map[string]any{"profile": b.ProfileName, "slot": a.Slot, "grant_id": grant.GrantID, "dry_run": false, "expected_resource_id": a.ResourceID, "expected_resource_created_at": a.ResourceCreatedAt}, &returned)
		if callErr != nil || status != "accepted" || original.Err() != nil {
			return nil, true, errOriginalGuestStep
		}
		receipt, found, err = selected.FailedExpansionDestroyReceipt(original, policy)
		if err != nil || !found || !originalGuestReceiptActionJoin(receipt, returned.ActionID, returned.NextActionIDs) {
			return nil, true, errOriginalGuestStep
		}
	}
	if receipt.Grant.State != "settled" || receipt.Outcome != "accepted" || !receipt.TransportCompleted || !receipt.AuxiliaryInventoryComplete {
		return nil, true, errOriginalGuestStep
	}
	for {
		_, pending, readErr := sourceFailedExpansionRead(original, selected, policy, p, input, a, supplier, "absence")
		if readErr != nil {
			return nil, true, readErr
		}
		if !pending {
			break
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-original.Done():
			timer.Stop()
			return nil, true, errOriginalGuestStep
		case <-timer.C:
		}
	}
	if err = refreshFailedExpansionSurvivors(original, selected, policy, p, input); err != nil {
		return nil, true, err
	}
	if err = failedExpansionSurvivorCanaries(original, db, selected, policy, p, input, key, "after_retirement_floor"); err != nil {
		return nil, true, err
	}
	result := failedExpansionResult(a)
	result["native_destroy_sent"] = sent
	result["physical_capacity_released"] = true
	return result, true, nil
}

func sourceFailedExpansionRead(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, a repository.FailedUnwitnessedExpansionCleanup, supplier *originalProductionGuestSupplier, kind string) (model.CapacityMutationProof, bool, error) {
	var proof model.CapacityMutationProof
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := store.PrepareFailedExpansionRead(read, policy, kind)
	if err != nil {
		return proof, false, err
	}
	readWire, encodeReadErr := json.Marshal(c)
	if encodeReadErr != nil {
		return proof, false, encodeReadErr
	}
	r := repository.FailedExpansionReadReturn{ReadWire: readWire, Schema: "failed_unwitnessed_expansion_native_return_v1", Read: c, StartedAtCore: time.Now().UTC()}
	if kind == "inventory" {
		var plan model.CapacityVMFleetPlan
		r.Status, err = supplier.call(read, supplier.binding.DestroyCapability, map[string]any{"profile": supplier.binding.ProfileName, "slot": a.Slot, "dry_run": true, "expected_resource_id": a.ResourceID, "expected_resource_created_at": a.ResourceCreatedAt}, &plan)
		if err == nil {
			r.Plan = &plan
		}
	} else {
		receipt, found, receiptErr := store.FailedExpansionDestroyReceipt(read, policy)
		if receiptErr != nil || !found {
			err = errOriginalGuestStep
		} else {
			r.Receipt = &receipt
			r.ReceiptWire, _ = json.Marshal(receipt)
			challenge, encodeErr := json.Marshal(c)
			original, receiptEncodeErr := json.Marshal(receipt)
			if encodeErr != nil || receiptEncodeErr != nil {
				err = errOriginalGuestStep
			} else {
				var out repository.GuestRetirementReadonlyReturn
				out, r.OriginalObserverReturn, err = readRetirementReadonly(read, supplier, c.ReadID, challenge, original)
				if err == nil {
					r.Status = "observed"
					r.ObserverSourceCommit = out.ObserverSourceCommit
					r.Observation = &out.Observation
				}
			}
		}
	}
	r.ReturnedAtCore = time.Now().UTC()
	r.CallFailed = err != nil
	r.OriginalContextFailed = read.Err() != nil || !r.ReturnedAtCore.Before(c.OriginalDeadlineCore)
	retain, stop := context.WithTimeout(context.WithoutCancel(read), 5*time.Second)
	proof, pending, recordErr := store.RecordFailedExpansionRead(retain, policy, r)
	stop()
	if err != nil || r.OriginalContextFailed {
		return model.CapacityMutationProof{}, false, errOriginalGuestStep
	}
	return proof, pending, recordErr
}

func completeFailedExpansionCleanup(ctx context.Context, store repository.CapacityStore, policy, wf model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input originalGuestReconcileInput) (any, bool, error) {
	store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), input.Mode, input.RequestID, model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	selected, a, handled, err := store.BindFailedExpansionCleanup(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner)
	if err != nil || !handled {
		return nil, handled, err
	}
	if input.Mode != "retire" || input.RequestID != a.ID || input.Slot != a.Slot {
		return nil, true, errOriginalGuestStep
	}
	out, err := selected.CompleteFailedExpansionCleanup(ctx, policy)
	if err != nil {
		return nil, true, err
	}
	result := failedExpansionResult(a)
	result["stage"] = "terminal"
	result["phase"] = out.Phase
	result["survivor_units"] = a.SurvivorCount
	return result, true, nil
}

func failedExpansionSurvivorCanaries(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey, usage string) error {
	members, err := store.GuestNotifyFloorMembers(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.Slot)
	if err != nil {
		return err
	}
	for _, member := range members {
		delay, err := store.FailedExpansionPublicationDelay(ctx, policy, member.PreregistrationID)
		if err != nil {
			return err
		}
		if delay > 0 {
			deadline, ok := ctx.Deadline()
			if !ok || delay >= time.Until(deadline) {
				return errOriginalGuestStep
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errOriginalGuestStep
			case <-timer.C:
			}
		}
		probe := input
		probe.Slot = member.Slot
		probe.PreregistrationID = member.PreregistrationID
		probe.RequestID = ""
		if _, err = executeOriginalGuestNotifyProbeForUsage(ctx, db, store, policy, p, probe, key, usage); err != nil {
			return err
		}
	}
	return nil
}
