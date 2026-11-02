//go:build !nativequalification

package message

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// QuiesceFailedInstalledV2RefusedNativeOff (ADR-0092) makes exactly one
// bounded native observe GET of the expired V2 retirement's own tuple through
// the existing V2 supplier transport. It never sends a Guest request, a
// poweroff or a DELETE. Only a timely exact OFF read quiesces the disposal; any
// other read is retained and the call may be repeated as a fresh GET.
func QuiesceFailedInstalledV2RefusedNativeOff(parent context.Context, db *sql.DB, conn *amqp.Connection, pre, admissionID, retID, issuer string) (repository.FailedInstalledV2RefusedNativeOff, repository.FailedInstalledGuestDisposal, error) {
	var empty repository.FailedInstalledV2RefusedNativeOff
	var disposal repository.FailedInstalledGuestDisposal
	if parent == nil || db == nil || conn == nil || issuer == "" {
		return empty, disposal, errOriginalCreateDisposition
	}
	original, stop := context.WithTimeout(parent, 5*time.Second)
	defer stop()
	store := repository.CapacityStore{DB: db, ExecutionEnabled: capacityExecutionEnabled()}
	owned, err := store.PrepareFailedInstalledV2RefusedNativeOffRead(original, pre, admissionID, retID, issuer)
	if err != nil {
		return empty, disposal, err
	}
	challenge := owned.Challenge()
	stored, p, policy := owned.Original(), owned.Spec(), owned.Policy()
	i := stored.Request.Intent
	store.WorkflowID = uuid.MustParse(i.WorkflowID)
	store.ExecutorID = stored.ExecutorID
	original = context.WithValue(original, originalGuestTransportKey{}, originalGuestTransport{conn: conn})
	input := guestOriginalStepInput{BindingName: stored.Binding.MutationBindingName, Slot: i.Slot, Generation: int64(i.Generation), FencingToken: int64(i.Fence), LeaseOwner: i.LeaseOwner, PreregistrationID: pre, RequestID: i.RequestID}
	returned := repository.GuestNativePoweroffReturnV2{Schema: "original_core_guest_native_poweroff_read_return_v2", Challenge: challenge, StartedAtCore: time.Now().UTC()}
	binding, err := capacity.VMObservationBinding(p, input.BindingName)
	if err == nil {
		var supplier *originalProductionGuestSupplier
		supplier, err = productionRetirementSupplierV2(original, store, policy, p, binding, input)
		if err == nil {
			fixed := map[string]any{"profile": binding.ProfileName, "slot": input.Slot, "grant_id": stored.Preregistration.OriginalCreateGrantID, "expected_resource_id": i.Tuple.ResourceID, "expected_resource_created_at": i.Tuple.CreatedAt}
			if supplier.provider == "aws" {
				var v struct {
					Plan      model.CapacityVMFleetPlan          `json:"plan"`
					Lifecycle model.CapacityAWSInstanceLifecycle `json:"lifecycle"`
				}
				returned.Status, err = failedInstalledLegacyReadonlyCall(original, supplier, "observe_ec2_instance", fixed, &v)
				if err == nil {
					receipt, e := store.NativeMutationReceipt(original, policy, binding, stored.Preregistration.OriginalCreateGrantID)
					if e != nil || !originalAWSNativeOffLifecycleJoin(v.Plan, v.Lifecycle, receipt.ActionID) {
						err = errOriginalGuestStep
					} else {
						returned.Plan = &v.Plan
					}
				}
			} else {
				var v model.CapacityVMFleetPlan
				returned.Status, err = failedInstalledLegacyReadonlyCall(original, supplier, capacity.VMObserveServer, fixed, &v)
				if err == nil {
					returned.Plan = &v
				}
			}
		}
	}
	returned.OriginalReturnedAtCore = time.Now().UTC()
	returned.CallFailed = err != nil
	returned.OriginalContextFailed = original.Err() != nil || !returned.OriginalReturnedAtCore.Before(challenge.OriginalDeadlineCore)
	retention, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	return store.RecordFailedInstalledV2RefusedNativeOffRead(retention, owned, returned)
}
