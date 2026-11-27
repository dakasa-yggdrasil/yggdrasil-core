package message

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

// A private process-composition port, never a registered workflow or HTTP
// operation. Catalog identity is checked before credential hydration, and all
// selector values come from the archived attempt plus its original acceptance.
func NewNativeWorkerPhysicalReadFunc(db *sql.DB, conn *amqp.Connection) capacity.NativeWorkerPhysicalReadFunc {
	return func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		var out model.CapacityNativeWorkerPhysicalObservation
		if db == nil || ctx == nil || ctx.Err() != nil || capacityDispatchFence(ctx) != nil || b.Capability != capacity.ObserveNativeWorkerPhysical || request.BindingName != b.BindingName {
			return out, errCapacityBoundAssessment
		}
		resolved, err := resolveCapacityObservationAdapterWithResolver(ctx, conn, db, marketObservationAdapter(b.Adapter), []string{capacity.ObserveNativeWorkerPhysical}, resolveIntegrationInstance)
		if err != nil || resolved.instance.Version != b.Adapter.Version || !capacityNativeCatalogOperation(resolved.typeSpec, capacity.ObserveNativeWorkerPhysical) {
			return out, errCapacityBoundAssessment
		}
		for _, action := range resolved.typeSpec.ActionCatalog {
			if action.Name == capacity.ObserveNativeWorkerPhysical && !action.Idempotent {
				return out, errCapacityBoundAssessment
			}
		}
		child, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		fixed := map[string]any{"binding_name": b.BindingName, "attempt_id": request.AttemptID, "resource_id": request.ResourceID, "launch_sha256": request.LaunchSHA256}
		result, err := executeIntegrationThroughResolvedWithPolicy(child, conn, model.ExecuteIntegrationRequest{Operation: capacity.ObserveNativeWorkerPhysical, Capability: capacity.ObserveNativeWorkerPhysical, Input: fixed}, resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec, 20*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		if err != nil || capacityDispatchFence(ctx) != nil {
			return model.CapacityNativeWorkerPhysicalObservation{}, errCapacityBoundAssessment
		}
		return nativePhysicalReadReply(b, request, result.Status, result.Output)
	}
}

func nativePhysicalReadReply(b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest, status string, raw any) (model.CapacityNativeWorkerPhysicalObservation, error) {
	var out model.CapacityNativeWorkerPhysicalObservation
	if status != "observed" || capacity.DecodeNativeCapacity(raw, &out) != nil || out.Adapter != b.Adapter || out.SourceCommit != b.SourceCommit || out.BindingName != b.BindingName || out.BindingScopeSHA256 != b.ScopeSHA256 || out.Requested != request {
		return out, errCapacityBoundAssessment
	}
	return out, nil
}
