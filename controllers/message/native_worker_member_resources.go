package message

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// These ports use real protected RPC clients and the existing resolver. Clients
// and broker/database stay borrowed; constructing a port never installs a grant.
func NewNativeWorkerMemberSDKPorts(db *sql.DB, broker func() *amqp.Connection, writer, reader, fence *capacity.NativeWorkerRPCClient) (repository.NativeWorkerMemberSDKPorts, error) {
	var empty repository.NativeWorkerMemberSDKPorts
	if db == nil || broker == nil || writer == nil || reader == nil || fence == nil || writer.SharesState(reader) || writer.SharesState(fence) || reader.SharesState(fence) {
		return empty, errCapacityBoundAssessment
	}
	call := func(ctx context.Context, e model.CapacityNativeWorkerMemberEndpoint, in model.CapacityNativeWorkerMemberSelectors, client *capacity.NativeWorkerRPCClient) (model.ExecuteIntegrationResponse, error) {
		var zero model.ExecuteIntegrationResponse
		if ctx == nil || ctx.Err() != nil || capacityDispatchFence(ctx) != nil || in.BindingName != e.BindingName || !client.Matches(e.Adapter, e.BindingName, e.BindingName, e.SourceCommit, e.ScopeSHA256, e.Capability) {
			return zero, errCapacityBoundAssessment
		}
		bound, err := WithNativeWorkerRPCClient(ctx, client, e.Adapter)
		if err != nil {
			return zero, err
		}
		b := model.CapacityNativeWorkerProbeResourceBinding{Name: e.BindingName, Adapter: e.Adapter, SourceCommit: e.SourceCommit, ScopeSHA256: e.ScopeSHA256}
		conn := broker()
		resolved, err := resolveNativeClosedResourceAdapter(bound, conn, db, b, e.Capability, nativeMemberCatalogOperation)
		if err != nil {
			return zero, errCapacityBoundAssessment
		}
		child, cancel := context.WithTimeout(bound, 25*time.Second)
		defer cancel()
		fixed := map[string]any{"binding_name": in.BindingName, "permit_id": in.PermitID}
		out, err := executeIntegrationThroughResolvedWithPolicy(child, conn, model.ExecuteIntegrationRequest{Operation: e.Capability, Capability: e.Capability, Input: fixed}, resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec, 25*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		if err != nil || capacityDispatchFence(ctx) != nil {
			return zero, errCapacityBoundAssessment
		}
		return out, nil
	}
	return repository.NativeWorkerMemberSDKPorts{
		Read: func(ctx context.Context, e model.CapacityNativeWorkerMemberEndpoint, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberObservation, error) {
			var out model.CapacityNativeWorkerMemberObservation
			if e.Capability != "observe_native_worker_pool_member" && e.Capability != "observe_native_worker_pod_placement" {
				return out, errCapacityBoundAssessment
			}
			response, err := call(ctx, e, in, reader)
			if err != nil || response.Status != "observed" || capacity.DecodeNativeCapacity(response.Output, &out) != nil || out.Schema != model.CapacityNativeWorkerMemberObservationSchema || out.BindingName != e.BindingName || out.PermitID != in.PermitID || out.Adapter != e.Adapter || out.SourceCommit != e.SourceCommit || out.ScopeSHA256 != e.ScopeSHA256 || !out.Complete || out.MutationAuthorized {
				return model.CapacityNativeWorkerMemberObservation{}, errCapacityBoundAssessment
			}
			return out, nil
		},
		Fence: func(ctx context.Context, e model.CapacityNativeWorkerMemberEndpoint, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceObservation, error) {
			var out model.CapacityNativeWorkerAllocatorFenceObservation
			if e.Capability != "observe_native_worker_allocator_fence" {
				return out, errCapacityBoundAssessment
			}
			response, err := call(ctx, e, in, fence)
			if err != nil || response.Status != "observed" || capacity.DecodeNativeCapacity(response.Output, &out) != nil || out.Schema != model.CapacityNativeWorkerAllocatorFenceObservationSchema || out.BindingName != e.BindingName || out.CreatorPermitID != in.PermitID || out.Adapter != e.Adapter || out.SourceCommit != e.SourceCommit || out.ScopeSHA256 != e.ScopeSHA256 || !out.Complete || out.MutationAuthorized {
				return model.CapacityNativeWorkerAllocatorFenceObservation{}, errCapacityBoundAssessment
			}
			return out, nil
		},
		Mutate: func(ctx context.Context, e model.CapacityNativeWorkerMemberEndpoint, in model.CapacityNativeWorkerMemberSelectors) error {
			_, readonly, ok := nativeMemberResource(e.Capability)
			if !ok || readonly {
				return errCapacityBoundAssessment
			}
			// No event/custody inference from an SDK safe response. Core reconciles its
			// own original and independent read before committing any observed result.
			_, err := call(ctx, e, in, writer)
			return err
		},
	}, nil
}

func nativeMemberResource(operation string) (string, bool, bool) {
	switch operation {
	case "ensure_native_worker_pool_member", "destroy_native_worker_pool_member":
		return "native_worker_pool_member", false, true
	case "ensure_native_worker_pod_placement", "destroy_native_worker_pod_placement":
		return "native_worker_pod_placement", false, true
	case "observe_native_worker_pool_member":
		return "native_worker_pool_member", true, true
	case "observe_native_worker_pod_placement":
		return "native_worker_pod_placement", true, true
	case "observe_native_worker_allocator_fence":
		return "native_worker_allocator_fence", true, true
	}
	return "", false, false
}
func nativeMemberCatalogOperation(ts model.IntegrationTypeManifestSpec, op string) bool {
	resource, readonly, ok := nativeMemberResource(op)
	if !ok || !slices.Contains(ts.Capabilities, "execute") {
		return false
	}
	count := 0
	for _, a := range ts.ActionCatalog {
		if a.Name == op {
			count++
			if a.Idempotent != readonly || a.Category != "" && a.Category != "capability" || len(a.ResourceTypes) != 1 || a.ResourceTypes[0] != resource {
				return false
			}
		}
	}
	if count != 1 {
		return false
	}
	count = 0
	for _, r := range ts.ResourceTypes {
		if r.Name == resource && slices.Contains(r.DefaultActions, op) {
			count++
		}
	}
	return count == 1
}
