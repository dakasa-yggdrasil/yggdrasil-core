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

type PartialNativeOffObservationResult struct {
	ReadID                     string `json:"read_id"`
	Ordinal                    int    `json:"ordinal"`
	ReconciliationID           string `json:"reconciliation_id"`
	QuiescentQualified         bool   `json:"quiescent_qualified"`
	GuestRequestOrPoweroffSent bool   `json:"Guest_request_or_poweroff_sent"`
}

// One original GET only. A failed read can be followed by a separately selected
// read under the same unique admission; no Guest POST, stop or delete is sent.
func ObserveFailedInstalledPartialNativeOff(parent context.Context, db *sql.DB, conn *amqp.Connection, pre, id, previous string) (PartialNativeOffObservationResult, error) {
	var out PartialNativeOffObservationResult
	if parent == nil || db == nil || conn == nil {
		return out, errOriginalCreateDisposition
	}
	original, stop := context.WithTimeout(parent, 5*time.Second)
	defer stop()
	store := repository.CapacityStore{DB: db, ExecutionEnabled: capacityExecutionEnabled()}
	owned, err := store.PrepareFailedInstalledPartialNativeOffRead(original, pre, id, previous)
	if err != nil {
		return out, err
	}
	read := owned.Read()
	out = PartialNativeOffObservationResult{ReadID: read.ReadID, Ordinal: read.Ordinal, ReconciliationID: id}
	stored, p, policy := owned.Original(), owned.Spec(), owned.Policy()
	i := stored.Request.Intent
	store.WorkflowID = uuid.MustParse(i.WorkflowID)
	store.ExecutorID = stored.ExecutorID
	original = context.WithValue(original, originalGuestTransportKey{}, originalGuestTransport{conn: conn})
	input := guestOriginalStepInput{BindingName: stored.Binding.MutationBindingName, Slot: i.Slot, Generation: int64(i.Generation), FencingToken: int64(i.Fence), LeaseOwner: i.LeaseOwner, PreregistrationID: pre, RequestID: i.RequestID}
	binding, err := capacity.VMObservationBinding(p, input.BindingName)
	returned := repository.PartialNativeOffReturn{Schema: "partial_guest548_native_off_return_v1", Read: read, StartedAt: time.Now().UTC()}
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
	returned.ReturnedAt = time.Now().UTC()
	returned.CallFailed = err != nil
	returned.ContextFailed = original.Err() != nil
	retention, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	out.QuiescentQualified, err = store.RecordFailedInstalledPartialNativeOffRead(retention, owned, returned)
	return out, err
}
