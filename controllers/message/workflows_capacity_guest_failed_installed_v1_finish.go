//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"time"
)

// This is a genuine V1 retirement followed by a separately owned provider GET.
// V2 clock/records/nonce and native DELETE authority are never manufactured.
func executeFailedInstalledGuestRetirementFinishedV1(ctx context.Context, _ *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, step model.WorkflowStepSpec, input guestOriginalStepInput, _ ed25519.PrivateKey) (any, error) {
	store = store.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
	current, err := store.Observe(ctx, policy)
	if err != nil || current.FailedInstalledDisposal == nil || current.FailedInstalledDisposal.PreregistrationID != input.PreregistrationID {
		return nil, errOriginalGuestStep
	}
	if err = sourceFailedInstalledGuestLegacyNativeOff(ctx, store, input.RequestID, input.PreregistrationID, current.FailedInstalledDisposal.ID); err != nil {
		return nil, err
	}
	r, err := store.PrepareFailedInstalledGuestLegacyCleanup(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.RequestID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"request_id": r.RetirementRequestID, "admission_id": r.ID, "stage": r.Stage, "retirement_mode": r.RetirementMode, "native_poweroff_sha256": r.NativePoweroffSHA256, "explicit_operator_native_cleanup_required": true, "native_destroy_sent": false, "useful_capacity_credit": 0, "original_business_effects_preserved": true}, nil
}

func sourceFailedInstalledGuestLegacyNativeOff(ctx context.Context, store repository.CapacityStore, id, preID, admissionID string) error {
	original, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	owned, err := store.PrepareFailedInstalledGuestLegacyNativeRead(original, id, preID, admissionID)
	if err != nil {
		return err
	}
	stored, p, policy := owned.Original(), owned.Spec(), owned.Policy()
	i := stored.Request.Intent
	input := guestOriginalStepInput{BindingName: stored.Binding.MutationBindingName, Slot: i.Slot, Generation: int64(i.Generation), FencingToken: int64(i.Fence), LeaseOwner: i.LeaseOwner, PreregistrationID: preID, RequestID: id}
	b, err := capacity.VMObservationBinding(p, input.BindingName)
	if err != nil {
		return err
	}
	supplier, err := productionRetirementSupplierV2(original, store, policy, p, b, input)
	returned := repository.FailedInstalledLegacyNativeReturn{Schema: "failed_installed_guest548_v1_native_off_return_v1", Read: owned.Read(), StartedAt: time.Now().UTC()}
	if err == nil {
		fixed := map[string]any{"profile": b.ProfileName, "slot": input.Slot, "grant_id": stored.Preregistration.OriginalCreateGrantID, "expected_resource_id": i.Tuple.ResourceID, "expected_resource_created_at": i.Tuple.CreatedAt}
		if supplier.provider == "aws" {
			var output struct {
				Plan      model.CapacityVMFleetPlan          `json:"plan"`
				Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
			}
			returned.Status, err = failedInstalledLegacyReadonlyCall(original, supplier, "observe_ec2_instance", fixed, &output)
			if err == nil {
				receipt, e := store.NativeMutationReceipt(original, policy, b, stored.Preregistration.OriginalCreateGrantID)
				if e != nil || !originalAWSNativeOffLifecycleJoin(output.Plan, output.Lifecycle, receipt.ActionID) {
					err = errOriginalGuestStep
				} else {
					returned.Plan = &output.Plan
				}
			}
		} else {
			var plan model.CapacityVMFleetPlan
			returned.Status, err = failedInstalledLegacyReadonlyCall(original, supplier, capacity.VMObserveServer, fixed, &plan)
			if err == nil {
				returned.Plan = &plan
			}
		}
	}
	returned.ReturnedAt = time.Now().UTC()
	returned.CallFailed = err != nil
	returned.ContextFailed = original.Err() != nil
	if err != nil || returned.ContextFailed {
		return errOriginalGuestStep
	}
	return store.RecordFailedInstalledGuestLegacyNativeRead(original, owned, returned)
}

// A separately admitted, acknowledged V1 retirement may outlive its old lease.
// This fixed GET-only transport rechecks catalog identity; the private owner
// rederives the complete claim/quiescence before accepting the actual return.
func failedInstalledLegacyReadonlyCall(ctx context.Context, s *originalProductionGuestSupplier, op string, fixed map[string]any, out any) (string, error) {
	if s == nil || ctx.Err() != nil || (op != "observe_ec2_instance" && op != capacity.VMObserveServer) {
		return "", errOriginalGuestStep
	}
	a := s.resolved
	r, err := executeIntegrationThroughResolvedWithPolicy(ctx, s.conn, model.ExecuteIntegrationRequest{Operation: op, Capability: op, Input: fixed}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 5*time.Second, integrationExecutionPolicy{detailFreeErrors: true, safeError: errOriginalGuestStep, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
	if err != nil || ctx.Err() != nil || capacity.DecodeVMObservation(r.Output, out) != nil {
		return "", errOriginalGuestStep
	}
	after, err := resolveOriginalGuestSupplier(ctx, s.conn, s.store, model.CapacityObservationAdapterBinding{IntegrationInstanceID: s.binding.IntegrationInstanceID, InstanceChecksum: s.binding.IntegrationChecksum, IntegrationTypeID: s.binding.IntegrationTypeID, TypeChecksum: s.binding.IntegrationTypeChecksum}, s.binding.OriginalProviderSourceCommit, s.provider)
	if err != nil || after.instance.ID != a.instance.ID || after.instance.Checksum != a.instance.Checksum || after.typ.ID != a.typ.ID || after.typ.Checksum != a.typ.Checksum {
		return "", errOriginalGuestStep
	}
	return r.Status, nil
}
