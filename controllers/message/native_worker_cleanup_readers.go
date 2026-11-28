package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Only installed Source composition supplies these separate mTLS handles.
// A workflow cannot supply readers, URLs, callbacks, credentials or closure.
func NewProtectedNativeWorkerConcreteAbortRuntime(db *sql.DB, conn *amqp.Connection, policy model.Manifest, network *repository.NativeWorkerConcreteNetworkRuntime, inventoryClient *capacity.NativeWorkerRPCClient, cleanupClients map[string]*capacity.NativeWorkerRPCClient) (*repository.NativeWorkerConcreteAbortRuntime, error) {
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.AbortInventoryObserver == nil || len(cleanupClients) != len(p.NativeWorkerLifecycleBinding.PhysicalObservers) {
		return nil, errCapacityBoundAssessment
	}
	b := p.NativeWorkerLifecycleBinding.AbortInventoryObserver
	if !inventoryClient.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory) {
		return nil, errCapacityBoundAssessment
	}
	readers := make(map[string]*capacity.NativeWorkerRPCClient, len(cleanupClients))
	clients := []*capacity.NativeWorkerRPCClient{inventoryClient}
	for _, provider := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		client := cleanupClients[provider.Profile]
		if !client.Matches(provider.Adapter, provider.Profile, provider.BindingName, provider.SourceCommit, provider.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
			return nil, errCapacityBoundAssessment
		}
		readers[provider.Profile] = client
		clients = append(clients, client)
	}
	read := func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerCleanupRequest) (model.CapacityNativeWorkerCleanupObservation, error) {
		return NewProtectedNativeWorkerCleanupReadFunc(db, conn, readers[b.Profile])(ctx, b, request)
	}
	return repository.NewNativeWorkerConcreteAbortRuntime(repository.NativeWorkerConcreteAbortRuntimeConfig{DB: db, Policy: policy, Network: network, CleanupRead: read, InventoryRead: NewProtectedNativeWorkerAbortInventoryReadFunc(db, conn, inventoryClient), RPCClients: clients})
}

// Match the protected Source role before the original resolver may describe or
// hydrate any credential. A workflow cannot supply a client or a binding here.
func NewProtectedNativeWorkerCleanupReadFunc(db *sql.DB, conn *amqp.Connection, client *capacity.NativeWorkerRPCClient) capacity.NativeWorkerCleanupReadFunc {
	return func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerCleanupRequest) (model.CapacityNativeWorkerCleanupObservation, error) {
		var zero model.CapacityNativeWorkerCleanupObservation
		if db == nil || ctx == nil || ctx.Err() != nil || capacityDispatchFence(ctx) != nil || request.BindingName != b.BindingName ||
			!client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
			return zero, errCapacityBoundAssessment
		}
		bound, err := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
		if err != nil {
			return zero, err
		}
		resolved, err := resolveCapacityObservationAdapterWithResolver(bound, conn, db, marketObservationAdapter(b.Adapter), []string{capacity.ObserveNativeWorkerCleanup}, resolveIntegrationInstance)
		if err != nil || resolved.instance.Version != b.Adapter.Version || !capacityNativeCatalogOperation(resolved.typeSpec, capacity.ObserveNativeWorkerCleanup) {
			return zero, errCapacityBoundAssessment
		}
		for _, action := range resolved.typeSpec.ActionCatalog {
			if action.Name == capacity.ObserveNativeWorkerCleanup && !action.Idempotent {
				return zero, errCapacityBoundAssessment
			}
		}
		child, cancel := context.WithTimeout(bound, 30*time.Second)
		defer cancel()
		fixed := map[string]any{"binding_name": b.BindingName, "attempt_id": request.AttemptID, "resource_id": request.ResourceID, "launch_sha256": request.LaunchSHA256, "footprint": request.Footprint}
		result, err := executeIntegrationThroughResolvedWithPolicy(child, conn, model.ExecuteIntegrationRequest{Operation: capacity.ObserveNativeWorkerCleanup, Capability: capacity.ObserveNativeWorkerCleanup, Input: fixed}, resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec, 30*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		if err != nil || capacityDispatchFence(ctx) != nil {
			return zero, errCapacityBoundAssessment
		}
		return nativeCleanupReadReply(b, request, result.Status, result.Output)
	}
}

func nativeCleanupReadReply(b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerCleanupRequest, status string, raw any) (model.CapacityNativeWorkerCleanupObservation, error) {
	var out model.CapacityNativeWorkerCleanupObservation
	want := model.CapacityNativeWorkerObservationRequest{BindingName: request.BindingName, AttemptID: request.AttemptID, ResourceID: request.ResourceID, LaunchSHA256: request.LaunchSHA256}
	mode := "snapshot"
	if request.Footprint != nil {
		mode = "closure"
	}
	if status != "observed" || capacity.DecodeNativeCapacity(raw, &out) != nil || out.Schema != "native_worker_cleanup_observation_v1" || out.Provider != b.Provider || out.Mode != mode ||
		out.Adapter != b.Adapter || out.SourceCommit != b.SourceCommit || out.BindingName != b.BindingName || out.BindingScopeSHA256 != b.ScopeSHA256 || out.Requested != want || out.Footprint == nil {
		return model.CapacityNativeWorkerCleanupObservation{}, errCapacityBoundAssessment
	}
	if request.Footprint != nil {
		requested, _ := json.Marshal(request.Footprint)
		returned, _ := json.Marshal(out.Footprint)
		if string(requested) != string(returned) {
			return model.CapacityNativeWorkerCleanupObservation{}, errCapacityBoundAssessment
		}
	}
	return out, nil
}

func NewProtectedNativeWorkerAbortInventoryReadFunc(db *sql.DB, conn *amqp.Connection, client *capacity.NativeWorkerRPCClient) capacity.NativeWorkerAbortInventoryReadFunc {
	return func(ctx context.Context, b model.CapacityNativeWorkerPhaseReadBinding, request model.CapacityNativeWorkerAbortInventoryRequest) (model.CapacityNativeWorkerAbortInventoryObservation, error) {
		var out model.CapacityNativeWorkerAbortInventoryObservation
		if db == nil || ctx == nil || ctx.Err() != nil || capacityDispatchFence(ctx) != nil || request.BindingName != b.Name ||
			!client.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory) {
			return out, errCapacityBoundAssessment
		}
		bound, err := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
		if err != nil {
			return out, err
		}
		resolved, err := resolveCapacityObservationAdapterWithResolver(bound, conn, db, marketObservationAdapter(b.Adapter), []string{capacity.ObserveNativeWorkerAbortInventory}, resolveIntegrationInstance)
		if err != nil || resolved.instance.Version != b.Adapter.Version || !capacityNativeCatalogOperation(resolved.typeSpec, capacity.ObserveNativeWorkerAbortInventory) {
			return out, errCapacityBoundAssessment
		}
		for _, action := range resolved.typeSpec.ActionCatalog {
			if action.Name == capacity.ObserveNativeWorkerAbortInventory && !action.Idempotent {
				return out, errCapacityBoundAssessment
			}
		}
		child, cancel := context.WithTimeout(bound, 30*time.Second)
		defer cancel()
		fixed := map[string]any{"binding_name": b.Name, "provider_id": request.ProviderID, "creation_proof_sha256": request.CreationProofSHA256, "node_name": request.NodeName}
		result, err := executeIntegrationThroughResolvedWithPolicy(child, conn, model.ExecuteIntegrationRequest{Operation: capacity.ObserveNativeWorkerAbortInventory, Capability: capacity.ObserveNativeWorkerAbortInventory, Input: fixed}, resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec, 30*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		if err != nil || capacityDispatchFence(ctx) != nil || result.Status != "observed" || capacity.DecodeNativeCapacity(result.Output, &out) != nil ||
			out.Schema != "native_worker_abort_inventory_v1" || out.SourceCommit != b.SourceCommit || out.BindingScopeSHA256 != b.ScopeSHA256 || out.Adapter != b.Adapter || out.BindingName != b.Name || out.Requested != request {
			return model.CapacityNativeWorkerAbortInventoryObservation{}, errCapacityBoundAssessment
		}
		return out, nil
	}
}
