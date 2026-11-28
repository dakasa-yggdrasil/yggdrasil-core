package message

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// NewNativeWorkerReadinessSDKPorts uses dedicated writer/reader clients, exact
// catalogue pins and the original resolver. broker is the current connection
// getter, not a Workers owner getter; this port is called under WorkersRLock.
func NewNativeWorkerReadinessSDKPorts(db *sql.DB, broker func() *amqp.Connection, profile string, writer, reader *capacity.NativeWorkerRPCClient, phase capacity.NativeWorkerPhaseReadFunc) (repository.NativeWorkerReadinessPorts, error) {
	var zero repository.NativeWorkerReadinessPorts
	if db == nil || broker == nil || profile == "" || writer == nil || reader == nil || writer.SharesState(reader) || phase == nil {
		return zero, errCapacityBoundAssessment
	}
	call := func(ctx context.Context, b model.CapacityNativeWorkerProbeResourceBinding, operation string, in model.NativeWorkerProbeResourceInput, client *capacity.NativeWorkerRPCClient, readOnly bool) (model.ExecuteIntegrationResponse, error) {
		var empty model.ExecuteIntegrationResponse
		if ctx == nil || ctx.Err() != nil || capacityDispatchFence(ctx) != nil || in.BindingName != b.Name || !client.Matches(b.Adapter, profile, b.Name, b.SourceCommit, b.ScopeSHA256, operation) {
			return empty, errCapacityBoundAssessment
		}
		bound, err := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
		if err != nil {
			return empty, err
		}
		conn := broker()
		resolved, err := resolveNativeProbeAdapter(bound, conn, db, b, operation)
		if err != nil {
			return empty, errCapacityBoundAssessment
		}
		found := 0
		for _, action := range resolved.typeSpec.ActionCatalog {
			if action.Name == operation {
				found++
				if readOnly && !action.Idempotent {
					return empty, errCapacityBoundAssessment
				}
			}
		}
		if found != 1 {
			return empty, errCapacityBoundAssessment
		}
		child, cancel := context.WithTimeout(bound, 25*time.Second)
		defer cancel()
		fixed := map[string]any{"binding_name": in.BindingName, "run_id": in.RunID, "slot": in.Slot}
		result, err := executeIntegrationThroughResolvedWithPolicy(child, conn, model.ExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: fixed}, resolved.instance, resolved.instanceSpec, resolved.typ, resolved.typeSpec, 25*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: ctx}})
		if err != nil || capacityDispatchFence(ctx) != nil {
			return empty, errCapacityBoundAssessment
		}
		return result, nil
	}
	return repository.NativeWorkerReadinessPorts{
		Phase: phase,
		Mutate: func(ctx context.Context, b model.CapacityNativeWorkerProbeResourceBinding, operation string, in model.NativeWorkerProbeResourceInput) error {
			if operation != capacity.EnsureNativeWorkerProbeResource && operation != capacity.DestroyNativeWorkerProbeResource {
				return errCapacityBoundAssessment
			}
			// An SDK result is not private custody or independent absence. The
			// producer always rereads its own original journal after this call.
			_, err := call(ctx, b, operation, in, writer, false)
			return err
		},
		Read: func(ctx context.Context, b model.CapacityNativeWorkerProbeResourceBinding, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceObservation, error) {
			var out model.NativeWorkerProbeResourceObservation
			result, err := call(ctx, b, capacity.ObserveNativeWorkerProbeResource, in, reader, true)
			if err != nil || result.Status != "observed" || capacity.DecodeNativeCapacity(result.Output, &out) != nil || out.Schema != model.NativeWorkerProbeResourceObservationSchema || out.SourceCommit != b.SourceCommit || out.BindingScopeSHA256 != b.ScopeSHA256 || out.Adapter != b.Adapter || out.BindingName != b.Name || out.RunID != in.RunID || out.Slot != in.Slot || !out.ReadComplete || out.MutationAuthorized || out.ReadinessQualified || out.AbsenceProven {
				return model.NativeWorkerProbeResourceObservation{}, errCapacityBoundAssessment
			}
			return out, nil
		},
	}, nil
}

// Deliberately separate from legacy observation dispatch. The only mutation
// pair is the protected diagnostic resource; no other ensure/destroy gains a
// new route or hydrates credentials before its original public pins are read.
func resolveNativeProbeAdapter(ctx context.Context, conn *amqp.Connection, db *sql.DB, b model.CapacityNativeWorkerProbeResourceBinding, op string) (capacityResolvedObservationAdapter, error) {
	return resolveNativeClosedResourceAdapter(ctx, conn, db, b, op, nativeProbeCatalogOperation)
}

func resolveNativeClosedResourceAdapter(ctx context.Context, conn *amqp.Connection, db *sql.DB, b model.CapacityNativeWorkerProbeResourceBinding, op string, catalog func(model.IntegrationTypeManifestSpec, string) bool) (capacityResolvedObservationAdapter, error) {
	var zero capacityResolvedObservationAdapter
	im, err := resolveManifestForKind(ctx, db, "integration_instance", b.Adapter.ManifestID, "", "", nil)
	if err != nil || !im.Metadata.Active || im.Kind != "integration_instance" || im.ID.String() != b.Adapter.ManifestID || im.Version != b.Adapter.Version || im.Checksum != b.Adapter.Checksum {
		return zero, errCapacityBoundAssessment
	}
	is, err := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if err != nil {
		return zero, errCapacityBoundAssessment
	}
	tm, err := resolveManifestForKind(ctx, db, "integration_type", is.TypeRef.ManifestID, is.TypeRef.Namespace, is.TypeRef.Name, is.TypeRef.Version)
	if err != nil || tm.Kind != "integration_type" || !tm.Metadata.Active || tm.ID.String() != b.Adapter.IntegrationTypeID || tm.Checksum != b.Adapter.TypeChecksum {
		return zero, errCapacityBoundAssessment
	}
	ts, err := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if err != nil || manifest.ValidateIntegrationTypeSpec(ts) != nil || !catalog(ts, op) || validateNativeWorkerRPCScope(ctx, im, is, tm, ts) != nil {
		return zero, errCapacityBoundAssessment
	}
	im, is, tm, ts, err = resolveIntegrationInstance(ctx, conn, db, model.ManifestSelector{ManifestID: b.Adapter.ManifestID})
	if err != nil || im.Version != b.Adapter.Version || im.ID.String() != b.Adapter.ManifestID || im.Checksum != b.Adapter.Checksum || tm.ID.String() != b.Adapter.IntegrationTypeID || tm.Checksum != b.Adapter.TypeChecksum || !im.Metadata.Active || !tm.Metadata.Active || manifest.ValidateIntegrationTypeSpec(ts) != nil || !catalog(ts, op) || validateNativeWorkerRPCScope(ctx, im, is, tm, ts) != nil {
		return zero, errCapacityBoundAssessment
	}
	return capacityResolvedObservationAdapter{im, is, tm, ts}, nil
}

func nativeProbeCatalogOperation(ts model.IntegrationTypeManifestSpec, op string) bool {
	if op != capacity.EnsureNativeWorkerProbeResource && op != capacity.DestroyNativeWorkerProbeResource && op != capacity.ObserveNativeWorkerProbeResource || !slices.Contains(ts.Capabilities, "execute") {
		return false
	}
	count := 0
	for _, action := range ts.ActionCatalog {
		if action.Name != op {
			continue
		}
		count++
		if action.Idempotent != (op == capacity.ObserveNativeWorkerProbeResource) || action.Category != "" && action.Category != "capability" || len(action.ResourceTypes) != 1 || action.ResourceTypes[0] != "native_worker_probe_resource" {
			return false
		}
	}
	if count != 1 {
		return false
	}
	count = 0
	for _, r := range ts.ResourceTypes {
		if r.Name == "native_worker_probe_resource" && slices.Contains(r.DefaultActions, op) {
			count++
		}
	}
	return count == 1
}
