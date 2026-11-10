//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestRetirementForwardResult(r repository.GuestRetirementForward) map[string]any {
	return map[string]any{
		"request_id": r.RetirementRequestID, "retirement_forward_id": r.ID,
		"root_admission_id": r.RootAdmissionID, "stage": r.Stage,
		"original_failure_preserved": true, "normal_guest_success": false,
		"guest_command_replayed": false, "native_destroy_sent": false,
	}
}

func liveGuestRetirementForward(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput, id string) (any, error) {
	r, err := store.AdmitGuestRetirementForwardLive(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, id)
	if err != nil {
		return nil, err
	}
	return guestRetirementForwardResult(r), nil
}

func historicalGuestRetirementForward(ctx context.Context, store repository.CapacityStore, policy model.Manifest, input guestOriginalStepInput) (any, bool, error) {
	waiting, found, err := store.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !found {
		return nil, false, err
	}
	if waiting.PreregistrationID != input.PreregistrationID {
		return nil, true, errOriginalGuestStep
	}
	stored, r, handled, err := store.GuestRetirementForwardOriginal(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, waiting.RetirementRequestID)
	if err != nil || !handled || stored.Request.Intent.Slot != input.Slot || stored.Preregistration.PreregistrationID != input.PreregistrationID {
		return nil, true, errOriginalGuestStep
	}
	// This is a new claim on retained originals, never another Guest command.
	return guestRetirementForwardResult(r), true, nil
}

func planGuestRetirementForward(ctx context.Context, store repository.CapacityStore, policy, wf model.Manifest, step model.WorkflowStepSpec) (any, bool, error) {
	store = store.WithOriginalGuestReconcile(wf, step, capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	r, waiting, err := store.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !waiting {
		return nil, false, err
	}
	if r.Stage != "requested" {
		requested, requestErr := store.TryRequestGuestRetirementForwardContinuation(ctx, policy)
		if requestErr != nil {
			return nil, true, requestErr
		}
		if !requested {
			return map[string]any{"mode": "hold", "reason": "partial_poweroff_forward_requires_historical_claim", "retirement_forward_id": r.ID, "native_write_sent": false, "original_failure_preserved": true}, true, nil
		}
		r, waiting, err = store.GuestRetirementForwardWaiting(ctx, policy)
		if err != nil {
			return nil, true, err
		}
		if !waiting || r.Stage != "requested" || r.Mode != repository.GuestRetirementForwardContinuationMode {
			return nil, true, errOriginalGuestStep
		}
	}
	claimed, preID, retirementID, handled, err := store.TryClaimGuestRetirementForward(ctx, policy)
	if err != nil {
		return nil, true, err
	}
	if !handled || preID != r.PreregistrationID || retirementID != r.RetirementRequestID || claimed.Decision.Units < 1 || claimed.Decision.Units > 7 {
		return nil, true, errOriginalGuestStep
	}
	deadline, err := store.OriginalGuestReconcileLeaseDeadline(ctx, policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner)
	if err != nil || captureOriginalGuestReconcileDeadline(ctx, deadline) != nil {
		return nil, true, errOriginalGuestStep
	}
	reason := "partial_poweroff_forward"
	if r.Mode == repository.GuestRetirementForwardContinuationMode {
		reason = "settled_absence_continuation"
	}
	return originalGuestReconcilePlan{Mode: "retire", Reason: reason, Slot: claimed.Decision.Units + 1, Generation: claimed.Generation, FencingToken: claimed.FencingToken, LeaseOwner: claimed.LeaseOwner, PreregistrationID: preID}, true, nil
}

// Each read owns a new five-second challenge and its actual return. The
// provider's lifecycle clock is joined to its own plan, never used as Core's
// freshness authority. Only an authenticated pending return permits another GET.
func sourceGuestRetirementForwardRead(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, stored repository.GuestRetirementOriginalV2, kind string, receipt model.CapacityMutationReceipt) (repository.GuestRetirementForwardReadReturn, model.CapacityMutationProof, error) {
	return sourceGuestRetirementForwardReadWithCall(ctx, store, input, kind, receipt, func(read context.Context, out *repository.GuestRetirementForwardReadReturn) error {
		return callGuestRetirementForwardNative(read, store, policy, p, input, stored, kind, receipt, out)
	})
}

// Fixed production transport is supplied as an in-process dependency, never a
// package-global setter, workflow input, URL, caller fact or proof constructor.
func callGuestRetirementForwardNative(read context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, stored repository.GuestRetirementOriginalV2, kind string, receipt model.CapacityMutationReceipt, out *repository.GuestRetirementForwardReadReturn) error {
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err == nil && kind == "absence" && b.OriginalProviderSourceCommit == enrolledFailedAWSCreator && !retirementReadonlySourceReady() {
		return errOriginalGuestStep
	}
	if err == nil {
		var supplier *originalProductionGuestSupplier
		supplier, err = productionRetirementSupplierV2(read, store, policy, p, b, input)
		if err == nil && !productionRetirementCatalogV2(supplier.provider, supplier.resolved.typeSpec) {
			err = errOriginalGuestStep
		}
		if err == nil {
			fixed := map[string]any{"profile": b.ProfileName, "slot": input.Slot, "grant_id": stored.Preregistration.OriginalCreateGrantID, "expected_resource_id": stored.Request.Intent.Tuple.ResourceID, "expected_resource_created_at": stored.Request.Intent.Tuple.CreatedAt}
			if kind == "off" && supplier.provider == "aws" {
				var returned struct {
					Plan      model.CapacityVMFleetPlan          `json:"plan"`
					Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
				}
				out.Status, err = supplier.call(read, "observe_ec2_instance", fixed, &returned)
				if err == nil {
					original, receiptErr := store.NativeMutationReceipt(read, policy, b, stored.Preregistration.OriginalCreateGrantID)
					if receiptErr != nil || !originalAWSForwardNativeOffLifecycleJoin(returned.Plan, returned.Lifecycle, original.ActionID) {
						err = errOriginalGuestStep
					}
				}
				if err == nil {
					out.Plan = &returned.Plan
				}
			} else if kind == "off" {
				var plan model.CapacityVMFleetPlan
				out.Status, err = supplier.call(read, capacity.VMObserveServer, fixed, &plan)
				if err == nil {
					out.Plan = &plan
				}
			} else if kind == "absence" && supplier.provider == "aws" && b.OriginalProviderSourceCommit == enrolledFailedAWSCreator {
				err = callRetirementReadonly(read, supplier, out)
			} else if kind == "absence" {
				fixed["grant_id"] = receipt.Grant.GrantID
				fixed["expected_resource_id"], fixed["expected_resource_created_at"] = receipt.ResourceID, receipt.ResourceCreatedAt
				operation := capacity.VMObserveRetirement
				if supplier.provider == "aws" {
					operation, fixed["retirement"] = "observe_ec2_instance", true
				}
				var observed model.CapacityVMRetirementObservation
				out.Status, err = supplier.call(read, operation, fixed, &observed)
				out.OriginalDestroyReceipt = &receipt
				if err == nil {
					out.Observation = &observed
				}
			} else {
				err = errOriginalGuestStep
			}
		}
	}
	return err
}

func sourceGuestRetirementForwardReadWithCall(ctx context.Context, store repository.CapacityStore, input guestOriginalStepInput, kind string, receipt model.CapacityMutationReceipt, call func(context.Context, *repository.GuestRetirementForwardReadReturn) error) (repository.GuestRetirementForwardReadReturn, model.CapacityMutationProof, error) {
	var out repository.GuestRetirementForwardReadReturn
	var proof model.CapacityMutationProof
	if call == nil {
		return out, proof, errOriginalGuestStep
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	destroyID := ""
	if kind == "absence" {
		destroyID = receipt.Grant.GrantID
	}
	challenge, err := store.PrepareGuestRetirementForwardRead(read, input.RequestID, kind, destroyID)
	if err != nil {
		return out, proof, err
	}
	out.Schema, out.Read = repository.GuestRetirementForwardReadReturnSchema, challenge
	out.StartedAtCore = time.Now().UTC()
	err = call(read, &out)
	out.OriginalReturnedAtCore = time.Now().UTC()
	out.CallFailed = err != nil
	out.OriginalContextFailed = read.Err() != nil || !out.OriginalReturnedAtCore.Before(challenge.OriginalDeadlineCore)
	retain, stop := context.WithTimeout(context.WithoutCancel(read), 5*time.Second)
	proof, recordErr := store.RecordGuestRetirementForwardRead(retain, out)
	stop()
	if err != nil || out.OriginalContextFailed {
		return out, proof, errOriginalGuestStep
	}
	return out, proof, recordErr
}

func originalAWSForwardNativeOffLifecycleJoin(plan model.CapacityVMFleetPlan, lifecycle model.CapacityAWSInstanceLifecycle, actionID string) bool {
	if originalAWSNativeOffLifecycleJoin(plan, lifecycle, actionID) {
		return true
	}
	return actionID != "" && lifecycle.RequestID == actionID && lifecycle.Schema == "aws_original_request_and_instance_status_v1" && lifecycle.EC2State == "stopping" && plan.Server != nil && plan.Server.Status == "stopping" && !lifecycle.ObservedAt.IsZero() && lifecycle.ObservedAt.UTC().Format(time.RFC3339Nano) == plan.ObservedAt
}

// Refresh only exact native membership. OFF is a separate typed observation;
// this inventory cannot manufacture demand, reporting coverage or useful credit.
func refreshGuestRetirementForwardInventory(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput) error {
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return err
	}
	supplier, err := productionRetirementSupplierV2(read, store, policy, p, b, input)
	if err != nil || !capacityBoundCatalogOperation(supplier.resolved.typeSpec, capacity.VMObserveInventory) {
		return errOriginalGuestStep
	}
	var inv model.CapacityVMFleetInventory
	status := "observed"
	if supplier.provider == "aws" && b.OriginalProviderSourceCommit == enrolledFailedAWSCreator {
		inv, err = callForwardInventoryReadonly(read, supplier)
	} else {
		status, err = supplier.call(read, capacity.VMObserveInventory, map[string]any{"profile": b.ProfileName}, &inv)
	}
	if err != nil || status != "observed" || read.Err() != nil {
		return errOriginalGuestStep
	}
	return store.RefreshGuestRetirementForwardInventory(read, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.RequestID, inv)
}

func guestRetirementForwardFloor(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) error {
	members, err := store.GuestNotifyFloorMembers(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.Slot)
	if err != nil {
		return err
	}
	for _, member := range members {
		delay, err := store.GuestRetirementForwardPublicationDelay(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.RequestID, member.PreregistrationID)
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
		probe.Slot, probe.PreregistrationID, probe.RequestID = member.Slot, member.PreregistrationID, ""
		// Existing issuance independently rechecks the full120/hour and gap
		// admission after this wait. There is exactly one publication attempt.
		if _, err = executeOriginalGuestNotifyProbeForUsage(ctx, db, store, policy, p, probe, key, "after_retirement_floor"); err != nil {
			return err
		}
	}
	return nil
}

func finishGuestRetirementForward(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey, stored repository.GuestRetirementOriginalV2, r repository.GuestRetirementForward) (any, error) {
	return finishGuestRetirementForwardWithCalls(ctx, guestRetirementForwardFinishCalls{
		knownDestroyOnly: r.Mode == repository.GuestRetirementForwardContinuationMode,
		destroyGrantID:   r.DestroyGrantID,
		receipt: func(c context.Context) (model.CapacityMutationReceipt, bool, error) {
			return store.GuestRetirementForwardDestroyReceipt(c, input.RequestID)
		},
		off: func(c context.Context) error {
			_, _, err := sourceGuestRetirementForwardRead(c, store, policy, p, input, stored, "off", model.CapacityMutationReceipt{})
			return err
		},
		inventory: func(c context.Context) error {
			return refreshGuestRetirementForwardInventory(c, store, policy, p, input)
		},
		floor: func(c context.Context) error { return guestRetirementForwardFloor(c, db, store, policy, p, input, key) },
		complete: func(c context.Context, receipt model.CapacityMutationReceipt, found bool) (any, error) {
			return finishProductionGuestNativeDestroyV2Forward(c, store, policy, p, input, stored, repository.GuestNativePoweroffReturnV2{}, receipt, found, &r)
		},
	})
}

type guestRetirementForwardFinishCalls struct {
	knownDestroyOnly bool
	destroyGrantID   string
	receipt          func(context.Context) (model.CapacityMutationReceipt, bool, error)
	off              func(context.Context) error
	inventory        func(context.Context) error
	floor            func(context.Context) error
	complete         func(context.Context, model.CapacityMutationReceipt, bool) (any, error)
}

// This ordering seam has no exported setter or wire representation. The live
// controller above always supplies the fixed Source-owned operations; tests
// can check orchestration without claiming native provider qualification.
func finishGuestRetirementForwardWithCalls(ctx context.Context, calls guestRetirementForwardFinishCalls) (any, error) {
	if calls.receipt == nil || calls.off == nil || calls.inventory == nil || calls.floor == nil || calls.complete == nil {
		return nil, errOriginalGuestStep
	}
	existing, found, err := calls.receipt(ctx)
	if err != nil {
		return nil, err
	}
	// A continuation has only the already accepted DELETE's read/confirm
	// authority. Losing or changing its receipt must never enter the OFF or
	// fresh-mutation branch, even if a later caller changes the orchestration.
	if calls.knownDestroyOnly && (!found || calls.destroyGrantID == "" || existing.Grant.GrantID != calls.destroyGrantID) {
		return nil, errOriginalGuestStep
	}
	if found && ((existing.Grant.State != "settled" && existing.Grant.State != "confirmed") || existing.Outcome != "accepted" || !existing.TransportCompleted) {
		return nil, errOriginalGuestStep
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil {
		return nil, errOriginalGuestStep
	}
	// Preserve the existing complete sixty-second destroy/absence invocation.
	// OFF, inventory and survivor work must finish before that reserve begins;
	// otherwise this attempt holds with every original/admission intact. The
	// unchanged ninety-second finish graph is never extended or rearmed.
	prepareDeadline := deadline.Add(-60 * time.Second)
	if found && existing.Grant.State == "confirmed" {
		prepareDeadline = deadline
	}
	if !time.Now().Before(prepareDeadline) {
		return nil, errOriginalGuestStep
	}
	prepare, stop := context.WithDeadline(ctx, prepareDeadline)
	defer stop()
	if !found {
		// OFF is read-only. The new barrier needs one NEW survivor publication
		// after actual OFF and this admission, rather than two back-to-back
		// publications that violate the unchanged per-member five-second gap.
		poll, cancel := context.WithTimeout(prepare, 120*time.Second)
		defer cancel()
		for {
			err = calls.off(poll)
			if err == nil {
				break
			}
			if !errors.Is(err, repository.ErrGuestRetirementForwardNativePending) {
				return nil, err
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-poll.Done():
				timer.Stop()
				return nil, errOriginalGuestStep
			case <-timer.C:
			}
		}
	}
	// A known parent destroy can be adopted only for read/confirm. Its actual
	// reduced inventory and NEW child survivor canaries replace no old proof;
	// no OFF is requested from an absent target and no DELETE is resent.
	if err = calls.inventory(prepare); err != nil {
		return nil, err
	}
	if err = calls.floor(prepare); err != nil {
		return nil, err
	}
	if prepare.Err() != nil {
		return nil, errOriginalGuestStep
	}
	return calls.complete(ctx, existing, found)
}
