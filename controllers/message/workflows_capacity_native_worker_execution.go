package message

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errNativeWorkerReceiving = errors.New("native worker remains in protected receiving or HOLD")

func nativeWorkerExecutionCatalog(ts model.IntegrationTypeManifestSpec, operation string) bool {
	if operation != "ensure_native_worker" && operation != "ensure_native_worker_pool" || !slices.Contains(ts.Capabilities, "execute") {
		return false
	}
	for _, action := range ts.ActionCatalog {
		if action.Name != operation || action.Idempotent || (action.Category != "" && action.Category != "capability") {
			continue
		}
		for _, resource := range ts.ResourceTypes {
			if slices.Contains(action.ResourceTypes, resource.Name) && slices.Contains(resource.DefaultActions, operation) {
				return true
			}
		}
	}
	return false
}

// Resolve and authenticate the exact original catalog BEFORE claiming a
// dispatch. The returned closure is invoked synchronously at most once after
// the SQL barrier commits; no generic retry or caller-selected capability exists.
func prepareNativeWorkerExecutionRPC(ctx context.Context, conn *amqp.Connection, db *sql.DB, client *capacity.NativeWorkerRPCClient, b model.CapacityMarketAdapterBinding, profile, binding, source, scope, operation string, input map[string]any) (func() error, error) {
	if client == nil || !client.Matches(b, profile, binding, source, scope, operation) || capacityDispatchFence(ctx) != nil {
		return nil, errCapacityBoundAssessment
	}
	bound, err := WithNativeWorkerRPCClient(ctx, client, b)
	if err != nil {
		return nil, err
	}
	// Resolve original public rows before any private hydration/health/Describe.
	im, err := resolveManifestForKind(bound, db, "integration_instance", b.ManifestID, "", "", nil)
	if err != nil || !im.Metadata.Active || im.Version != b.Version || im.Checksum != b.Checksum {
		return nil, errCapacityBoundAssessment
	}
	is, err := manifest.ParseIntegrationInstanceSpec(im.Spec)
	if err != nil {
		return nil, errCapacityBoundAssessment
	}
	tm, err := resolveManifestForKind(bound, db, "integration_type", is.TypeRef.ManifestID, is.TypeRef.Namespace, is.TypeRef.Name, is.TypeRef.Version)
	if err != nil || !tm.Metadata.Active || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum {
		return nil, errCapacityBoundAssessment
	}
	ts, err := manifest.ParseIntegrationTypeSpec(tm.Spec)
	if err != nil || manifest.ValidateIntegrationTypeSpec(ts) != nil || !nativeWorkerExecutionCatalog(ts, operation) {
		return nil, errCapacityBoundAssessment
	}
	im, is, tm, ts, err = resolveIntegrationInstance(bound, conn, db, model.ManifestSelector{ManifestID: b.ManifestID})
	if err != nil || im.ID.String() != b.ManifestID || im.Version != b.Version || im.Checksum != b.Checksum || tm.ID.String() != b.IntegrationTypeID || tm.Checksum != b.TypeChecksum || !im.Metadata.Active || !tm.Metadata.Active || !nativeWorkerExecutionCatalog(ts, operation) {
		return nil, errCapacityBoundAssessment
	}
	used := false
	return func() error {
		if used || capacityDispatchFence(bound) != nil || bound.Err() != nil {
			return errCapacityBoundAssessment
		}
		used = true
		_, err := executeIntegrationThroughResolvedWithPolicy(bound, conn, model.ExecuteIntegrationRequest{Operation: operation, Capability: operation, Input: input}, im, is, tm, ts, 60*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: bound}})
		return err
	}, nil
}

func nativeWorkerPoolExecutionRead(ctx context.Context, conn *amqp.Connection, db *sql.DB, p model.CapacityPolicySpec, client *capacity.NativeWorkerRPCClient, scopeSHA string) (*model.CapacityNativeWorkerPoolObservation, error) {
	b := p.NativeWorkerPoolBinding
	if b == nil || client == nil || !client.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, scopeSHA, capacity.ObserveNativeWorkerPool) {
		return nil, errCapacityBoundAssessment
	}
	bound, err := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
	if err != nil {
		return nil, err
	}
	a, err := resolveCapacityObservationAdapterWithResolver(bound, conn, db, marketObservationAdapter(b.Adapter), []string{capacity.ObserveNativeWorkerPool}, resolveIntegrationInstance)
	if err != nil || a.instance.Version != b.Adapter.Version {
		return nil, errCapacityBoundAssessment
	}
	response, err := executeIntegrationThroughResolvedWithPolicy(bound, conn, model.ExecuteIntegrationRequest{Operation: capacity.ObserveNativeWorkerPool, Capability: capacity.ObserveNativeWorkerPool, Input: map[string]any{"binding_name": b.Name}}, a.instance, a.instanceSpec, a.typ, a.typeSpec, 20*time.Second, integrationExecutionPolicy{detailFreeErrors: true, exactJSONNumbers: true, safeError: errCapacityBoundAssessment, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 2 << 20, parent: bound}})
	var pool model.CapacityNativeWorkerPoolObservation
	if err != nil || response.Status != "observed" || capacity.DecodeNativeCapacity(response.Output, &pool) != nil || pool.Adapter != b.Adapter || capacityDispatchFence(bound) != nil {
		return nil, errCapacityBoundAssessment
	}
	if _, err = capacity.NativeWorkerPoolSnapshot(p, &pool, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &pool, nil
}

// No workflow input reaches this function except the already resolved policy.
// A single owner borrow covers the whole operation, including all callbacks.
func executeCapacityNativeWorkerExecution(ctx context.Context, conn *amqp.Connection, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, workflow model.Manifest, result model.WorkflowRunStepResult, read func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error), fail func(...error) model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	if !p.ExecutionEnabled || os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "true" || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Network == nil || p.NativeWorkerLifecycleBinding.RegistryWriter == nil || capacityDispatchFence(ctx) != nil {
		return fail()
	}
	admissionOnly := result.Operation == "capacity.admit_bound"
	err := withNativeWorkerExecutionScope(ctx, db, policy, func(callCtx context.Context, scope NativeWorkerExecutionScope) error {
		if scope.Workers == nil || scope.Network == nil || scope.PoolReader == nil || scope.RegistryWriter == nil || scope.Workers.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit {
			return errCapacityBoundAssessment
		}
		observer := func(c context.Context, actual model.Manifest) (*model.CapacityMarketAssessment, *model.CapacityNativeWorkerPoolObservation, error) {
			if actual.ID != policy.ID || actual.Checksum != policy.Checksum || c.Err() != nil || capacityDispatchFence(c) != nil {
				return nil, nil, errCapacityBoundAssessment
			}
			pool, err := nativeWorkerPoolExecutionRead(c, conn, db, p, scope.PoolReader, scope.PoolReaderScopeSHA256)
			if err != nil {
				return nil, nil, err
			}
			// Price collectors remain the existing protected, exact Source bindings.
			marketRead := func(b model.CapacityObservationAdapterBinding, op string, in map[string]any, out any) (string, error) {
				if op == capacity.ObserveNativeWorkerPool {
					dst, ok := out.(*model.CapacityNativeWorkerPoolObservation)
					if !ok {
						return "", errCapacityBoundAssessment
					}
					*dst = *pool
					return "observed", nil
				}
				return read(b, op, in, out)
			}
			_, market, err := observeCapacityWorkerMarket(p, marketRead, time.Now().UTC())
			return market, pool, err
		}
		executor, _ := callCtx.Value(capacityInvocationKey{}).(string)
		store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: workflow.ID, ExecutorID: executor, MarketObserver: observer}
		workers, err := repository.NativeWorkerRecordingStore(repository.CapacityNativeWorkerStore{Capacity: store, Runtime: scope.Workers, Enabled: true}, scope.Workers)
		if err != nil {
			return err
		}
		parent, err := store.Observe(callCtx, policy)
		if err != nil {
			return err
		}
		if parent.Phase == "proposed" {
			if admissionOnly || parent.Decision.Action != "expand" || parent.Decision.Profile != parent.Assessment.Snapshot.Profile {
				return errNativeWorkerReceiving
			}
			a := model.CapacityAssessment{}
			for _, b := range p.NativeWorkerPoolBinding.Signals {
				var metric model.CapacityMetricRangeObservation
				status, err := read(b.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": b.BindingName}, &metric)
				if err != nil || status != "succeeded" {
					return errCapacityBoundAssessment
				}
				e, err := capacity.BoundMetricEvidence(p, b, metric, time.Now().UTC())
				if err != nil {
					return err
				}
				a.Evidence = append(a.Evidence, e)
			}
			parent, err = store.Claim(callCtx, policy, parent.Generation, a)
			if err != nil {
				return err
			}
		}
		session, err := workers.OpenNativeExecution(callCtx, policy, workflow.ID)
		if err != nil {
			// Expiry never adopts a claim or launches again. Historical ACK
			// custody remains useful; separately authorized abort is not invoked.
			_ = workers.ReceiveNativeExecution(callCtx, policy)
			return errNativeWorkerReceiving
		}
		if err = session.Renew(callCtx); err != nil {
			return errNativeWorkerReceiving
		}
		var a model.CapacityNativeWorkerAttempt
		if admissionOnly {
			a, err = session.Pending(callCtx)
		} else {
			a, err = session.Next(callCtx)
		}
		if errors.Is(err, sql.ErrNoRows) {
			completed, e := session.Complete(callCtx)
			if e != nil {
				return e
			}
			result.Metadata = map[string]any{"mode": "native_worker_pool_v1", "intent": completed, "provider_execution_enabled": true}
			return nil
		}
		if err != nil {
			return err
		}
		result.Metadata = map[string]any{"mode": "native_worker_pool_v1", "attempt_id": a.ID.String(), "state": a.State, "receiving": true, "provider_execution_enabled": true}
		if a.State == "reserved" {
			if admissionOnly {
				return errNativeWorkerReceiving
			}
			b := a.Execution
			send, err := prepareNativeWorkerExecutionRPC(callCtx, conn, db, scope.ProviderMutations[a.Profile], b.Adapter, a.Profile, b.BindingName, b.SDKSourceCommit, b.ScopeSHA256, b.EnsureCapability, map[string]any{"binding_name": b.BindingName, "attempt_id": a.ID.String()})
			if err != nil {
				return err
			}
			won, err := session.ClaimDispatch(callCtx, a.ID, "provider_create", a.ID)
			if err != nil {
				return err
			}
			if !won {
				return errNativeWorkerReceiving
			}
			// Original SDK callback/custody is authoritative even if RPC fails.
			_ = send()
			_ = workers.ReceiveNativeExecution(callCtx, policy)
			return errNativeWorkerReceiving
		}
		if a.State == "send_started" || a.State == "unknown" {
			_, _ = session.Record(callCtx, a.ID)
			return errNativeWorkerReceiving
		}
		if a.State != "acknowledged" && a.State != "registered" {
			return errNativeWorkerReceiving
		}
		if a.State == "acknowledged" {
			g, err := session.Network(callCtx, scope.Network, a.ID)
			if err != nil {
				return err
			}
			networkPermitID, parseErr := uuid.Parse(g.PermitID)
			if parseErr != nil || networkPermitID == uuid.Nil || networkPermitID.String() != g.PermitID {
				return errNativeWorkerReceiving
			}
			if g.State != "observed" {
				if g.State == "issued" {
					won, err := session.ClaimDispatch(callCtx, a.ID, "network_install", networkPermitID)
					if err != nil {
						return err
					}
					if won {
						_, _ = scope.Network.RequestNetworkMutation(callCtx, policy, "install", networkPermitID)
					}
				}
				g, err = session.ReconcileNetwork(callCtx, scope.Network, networkPermitID)
				if err != nil || g.State != "observed" {
					return errNativeWorkerReceiving
				}
			}
			if err = nativeWorkerExecutionPhase(callCtx, conn, db, policy, p, scope, session, a, "register"); err != nil {
				return err
			}
			_, err = session.Record(callCtx, a.ID)
			if err != nil {
				return err
			}
			return errNativeWorkerReceiving
		}
		if os.Getenv("YGGDRASIL_CAPACITY_ADMISSION_ENABLED") != "true" {
			return errNativeWorkerReceiving
		}
		if err = nativeWorkerExecutionPhase(callCtx, conn, db, policy, p, scope, session, a, "admit_registry"); err != nil {
			return err
		}
		if err = nativeWorkerExecutionPhase(callCtx, conn, db, policy, p, scope, session, a, "release_quarantine"); err != nil {
			return err
		}
		_, err = session.Record(callCtx, a.ID)
		if err != nil {
			return err
		}
		return errNativeWorkerReceiving
	})
	if err != nil {
		safe := fail(err)
		safe.Metadata = result.Metadata
		return safe
	}
	if capacityDispatchFence(ctx) != nil {
		return fail()
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	return result
}

func nativeWorkerExecutionPhase(ctx context.Context, conn *amqp.Connection, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, scope NativeWorkerExecutionScope, session *repository.NativeWorkerExecutionSession, a model.CapacityNativeWorkerAttempt, action string) error {
	c, err := session.Phase(ctx, scope.Workers, a.ID, action)
	if err != nil {
		return err
	}
	if c.PhaseState == "observed" {
		return nil
	}
	if c.PhaseState == "issued" {
		b := p.NativeWorkerLifecycleBinding.RegistryWriter
		send, err := prepareNativeWorkerExecutionRPC(ctx, conn, db, scope.RegistryWriter, b.Adapter, b.BindingName, b.BindingName, b.SourceCommit, b.ScopeSHA256, b.Capability, map[string]any{"binding_name": b.BindingName, "permit_id": c.PermitID.String()})
		if err != nil {
			return err
		}
		won, err := session.ClaimDispatch(ctx, a.ID, "registry_phase", c.PermitID)
		if err != nil {
			return err
		}
		if won {
			_ = send()
		}
	}
	c, err = session.ReconcilePhase(ctx, scope.Workers, c.PermitID)
	if err != nil || c.PhaseState != "observed" {
		return errNativeWorkerReceiving
	}
	return nil
}
