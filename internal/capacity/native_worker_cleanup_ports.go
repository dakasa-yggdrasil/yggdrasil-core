package capacity

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const ObserveNativeWorkerCleanup = "observe_native_worker_cleanup"
const ObserveNativeWorkerAbortInventory = "observe_native_worker_abort_inventory"

// Protected Source composition installs these readers. They accept only
// selectors from the committed Attempt/initial footprint and perform no writes.
type NativeWorkerCleanupReadFunc func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerCleanupRequest) (model.CapacityNativeWorkerCleanupObservation, error)
type NativeWorkerAbortInventoryReadFunc func(context.Context, model.CapacityNativeWorkerPhaseReadBinding, model.CapacityNativeWorkerAbortInventoryRequest) (model.CapacityNativeWorkerAbortInventoryObservation, error)
