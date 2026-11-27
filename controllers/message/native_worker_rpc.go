package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

type nativeWorkerRPCKey struct{}
type nativeWorkerRPCScope struct {
	client  *capacity.NativeWorkerRPCClient
	adapter model.CapacityMarketAdapterBinding
}

func nativeWorkerRPC(ctx context.Context) *nativeWorkerRPCScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(nativeWorkerRPCKey{}).(*nativeWorkerRPCScope)
	return scope
}

// Only protected Go composition has this handle. Neither a manifest nor a
// workflow request can install a certificate or select a private client file.
func WithNativeWorkerRPCClient(ctx context.Context, client *capacity.NativeWorkerRPCClient, adapter model.CapacityMarketAdapterBinding) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, errCapacityBoundAssessment
	}
	return context.WithValue(ctx, nativeWorkerRPCKey{}, &nativeWorkerRPCScope{client, adapter}), nil
}

func validateNativeWorkerRPCScope(ctx context.Context, instance model.Manifest, instanceSpec model.IntegrationInstanceManifestSpec, typ model.Manifest, typeSpec model.IntegrationTypeManifestSpec) error {
	scope := nativeWorkerRPC(ctx)
	if scope == nil {
		return nil
	}
	b := scope.adapter
	base, e := adapterBaseURL(instanceSpec)
	if e != nil || instance.Kind != "integration_instance" || !instance.Metadata.Active || instance.ID.String() != b.ManifestID || instance.Version != b.Version || instance.Checksum != b.Checksum ||
		typ.Kind != "integration_type" || !typ.Metadata.Active || typ.ID.String() != b.IntegrationTypeID || typ.Checksum != b.TypeChecksum || !scope.client.ScopeValid(b, base) ||
		typeSpec.Adapter.Transport != "http_json" || typeSpec.Adapter.Endpoints.Describe != "/rpc/describe" || typeSpec.Adapter.Endpoints.Execute != "/rpc/execute" {
		return errCapacityBoundAssessment
	}
	return nil
}

// Original public row/type pins are checked before the resolver touches any
// credential reference. The ordinary resolver still owns all later steps.
func nativeWorkerRPCBeforeHydration(ctx context.Context, db *sql.DB, instance model.Manifest, spec model.IntegrationInstanceManifestSpec) error {
	if nativeWorkerRPC(ctx) == nil {
		return nil
	}
	typ, e := resolveManifestForKind(ctx, db, "integration_type", spec.TypeRef.ManifestID, spec.TypeRef.Namespace, spec.TypeRef.Name, spec.TypeRef.Version)
	if e != nil {
		return errCapacityBoundAssessment
	}
	typeSpec, e := manifest.ParseIntegrationTypeSpec(typ.Spec)
	if e != nil {
		return errCapacityBoundAssessment
	}
	return validateNativeWorkerRPCScope(ctx, instance, spec, typ, typeSpec)
}

func (c *adapterTransportClient) callProtectedNativeWorkerRPC(ctx context.Context, target string, request, response any, policy adapterCallPolicy) error {
	scope, n := nativeWorkerRPC(ctx), policy.native
	fail := func(e error) error { return &opaqueAdapterError{public: errAdapterCallFailed, cause: e} }
	if scope == nil || n == nil || n.get || n.guest != nil || n.readToken != "" || n.exactURL != "" || n.originalAWSReadUnavailable || policy.contextError(ctx) != nil {
		return fail(errCapacityBoundAssessment)
	}
	raw, e := json.Marshal(request)
	if e != nil {
		return fail(e)
	}
	returned, e := scope.client.Call(ctx, target, raw, n.limit)
	e = errors.Join(e, policy.contextError(ctx))
	if n.originalReturn != nil {
		n.originalReturn(e == nil)
	}
	if e != nil {
		return fail(e)
	}
	inner, e := unwrapSDKHTTPEnvelope(returned)
	if e == nil {
		e = decodeRPCBodyWithPolicy(inner, response, policy)
	}
	if e = errors.Join(e, policy.contextError(ctx)); e != nil {
		return fail(e)
	}
	return nil
}

// Mandatory mTLS counterpart of the existing independently pinned physical
// observer. Binding selection precedes the original resolver and Describe.
func NewProtectedNativeWorkerPhysicalReadFunc(db *sql.DB, conn *amqp.Connection, client *capacity.NativeWorkerRPCClient) capacity.NativeWorkerPhysicalReadFunc {
	read := NewNativeWorkerPhysicalReadFunc(db, conn)
	return func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		if !client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerPhysical) {
			return model.CapacityNativeWorkerPhysicalObservation{}, errCapacityBoundAssessment
		}
		bound, e := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
		if e != nil {
			return model.CapacityNativeWorkerPhysicalObservation{}, e
		}
		bounded, cancel := context.WithTimeout(bound, 30*time.Second)
		defer cancel()
		return read(bounded, b, request)
	}
}
