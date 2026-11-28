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

// A Kubernetes reader has no market performance profile. Its private client
// Profile and BindingName are both the exact Source-owned reader binding name.
func NewProtectedNativeWorkerPhaseReadFunc(db *sql.DB, conn *amqp.Connection, client *capacity.NativeWorkerRPCClient) capacity.NativeWorkerPhaseReadFunc {
	read := NewNativeWorkerPhaseReadFunc(db, conn)
	return func(ctx context.Context, b model.CapacityNativeWorkerPhaseReadBinding, providerID, birthSHA string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		if !client.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerPhase) {
			return model.CapacityNativeWorkerPhaseReadObservation{}, errCapacityBoundAssessment
		}
		bound, err := WithNativeWorkerRPCClient(ctx, client, b.Adapter)
		if err != nil {
			return model.CapacityNativeWorkerPhaseReadObservation{}, err
		}
		bounded, cancel := context.WithTimeout(bound, 30*time.Second)
		defer cancel()
		return read(bounded, b, providerID, birthSHA)
	}
}

// The concrete composition always builds the existing real catalog/RPC reader
// around private mTLS handles. A request can supply neither a callback nor any
// client configuration. Ownership transfers only if the repository constructor
// succeeds; failed composition leaves every caller-owned handle untouched.
func NewProtectedNativeWorkerConcreteRuntime(db *sql.DB, conn *amqp.Connection, policy model.Manifest,
	factories map[string]*capacity.NativeWorkerPrivateFactory, phaseClient *capacity.NativeWorkerRPCClient,
	physicalClients map[string]*capacity.NativeWorkerRPCClient,
) (*repository.NativeWorkerConcreteRuntime, error) {
	return newProtectedNativeWorkerConcreteRuntime(db, func() *amqp.Connection { return conn }, policy, factories, phaseClient, physicalClients, nil, false)
}

// The main owner supplies the CURRENT broker snapshot once per operation. A
// reconnect never retries that operation or adopts a replacement mid-flight.
// The optional independent witness producer is protected Go composition; nil
// keeps readiness on HOLD even when the guest's own witness is available.
func NewProtectedNativeWorkerConcreteRuntimeWithBroker(db *sql.DB, broker func() *amqp.Connection, policy model.Manifest,
	factories map[string]*capacity.NativeWorkerPrivateFactory, phaseClient *capacity.NativeWorkerRPCClient,
	physicalClients map[string]*capacity.NativeWorkerRPCClient, proof capacity.NativeWorkerGuestWitnessProofFunc,
) (*repository.NativeWorkerConcreteRuntime, error) {
	return newProtectedNativeWorkerConcreteRuntime(db, broker, policy, factories, phaseClient, physicalClients, proof, true)
}

func newProtectedNativeWorkerConcreteRuntime(db *sql.DB, broker func() *amqp.Connection, policy model.Manifest,
	factories map[string]*capacity.NativeWorkerPrivateFactory, phaseClient *capacity.NativeWorkerRPCClient,
	physicalClients map[string]*capacity.NativeWorkerRPCClient, proof capacity.NativeWorkerGuestWitnessProofFunc, requireCurrentBroker bool,
) (*repository.NativeWorkerConcreteRuntime, error) {
	var p model.CapacityPolicySpec
	if broker == nil || json.Unmarshal(policy.Spec, &p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil ||
		len(physicalClients) != len(p.NativeWorkerLifecycleBinding.PhysicalObservers) {
		return nil, errCapacityBoundAssessment
	}
	phase := p.NativeWorkerLifecycleBinding.PhaseObserver
	if !phaseClient.Matches(phase.Adapter, phase.Name, phase.Name, phase.SourceCommit, phase.ScopeSHA256, capacity.ObserveNativeWorkerPhase) {
		return nil, errCapacityBoundAssessment
	}
	readers := make(map[string]*capacity.NativeWorkerRPCClient, len(physicalClients))
	clients := []*capacity.NativeWorkerRPCClient{phaseClient}
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		client := physicalClients[b.Profile]
		if !client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerPhysical) {
			return nil, errCapacityBoundAssessment
		}
		readers[b.Profile] = client
		clients = append(clients, client)
	}
	physical := func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, requested model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		conn := broker()
		if requireCurrentBroker && (conn == nil || conn.IsClosed()) {
			return model.CapacityNativeWorkerPhysicalObservation{}, errCapacityBoundAssessment
		}
		return NewProtectedNativeWorkerPhysicalReadFunc(db, conn, readers[b.Profile])(ctx, b, requested)
	}
	phaseRead := func(ctx context.Context, b model.CapacityNativeWorkerPhaseReadBinding, providerID, birthSHA string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		conn := broker()
		if requireCurrentBroker && (conn == nil || conn.IsClosed()) {
			return model.CapacityNativeWorkerPhaseReadObservation{}, errCapacityBoundAssessment
		}
		return NewProtectedNativeWorkerPhaseReadFunc(db, conn, phaseClient)(ctx, b, providerID, birthSHA)
	}
	return repository.NewNativeWorkerConcreteRuntime(repository.NativeWorkerConcreteRuntimeConfig{
		DB: db, Policy: policy, Factories: factories,
		PhaseRead: phaseRead, PhysicalRead: physical, RPCClients: clients, GuestWitnessProof: proof,
	})
}

// Abort borrows Network and Workers; only its distinct reader handles transfer
// on success. It also resolves a fresh broker at each original read boundary.
func NewProtectedNativeWorkerConcreteAbortRuntimeWithBroker(db *sql.DB, broker func() *amqp.Connection, policy model.Manifest,
	network *repository.NativeWorkerConcreteNetworkRuntime, inventory *capacity.NativeWorkerRPCClient, cleanup map[string]*capacity.NativeWorkerRPCClient,
) (*repository.NativeWorkerConcreteAbortRuntime, error) {
	var p model.CapacityPolicySpec
	if broker == nil || json.Unmarshal(policy.Spec, &p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.AbortInventoryObserver == nil || len(cleanup) != len(p.NativeWorkerLifecycleBinding.PhysicalObservers) {
		return nil, errCapacityBoundAssessment
	}
	b := p.NativeWorkerLifecycleBinding.AbortInventoryObserver
	if !inventory.Matches(b.Adapter, b.Name, b.Name, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory) {
		return nil, errCapacityBoundAssessment
	}
	readers := make(map[string]*capacity.NativeWorkerRPCClient, len(cleanup))
	clients := []*capacity.NativeWorkerRPCClient{inventory}
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		client := cleanup[b.Profile]
		if !client.Matches(b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup) {
			return nil, errCapacityBoundAssessment
		}
		readers[b.Profile] = client
		clients = append(clients, client)
	}
	read := func(ctx context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerCleanupRequest) (model.CapacityNativeWorkerCleanupObservation, error) {
		conn := broker()
		if conn == nil || conn.IsClosed() {
			return model.CapacityNativeWorkerCleanupObservation{}, errCapacityBoundAssessment
		}
		return NewProtectedNativeWorkerCleanupReadFunc(db, conn, readers[b.Profile])(ctx, b, request)
	}
	inventoryRead := func(ctx context.Context, b model.CapacityNativeWorkerPhaseReadBinding, request model.CapacityNativeWorkerAbortInventoryRequest) (model.CapacityNativeWorkerAbortInventoryObservation, error) {
		conn := broker()
		if conn == nil || conn.IsClosed() {
			return model.CapacityNativeWorkerAbortInventoryObservation{}, errCapacityBoundAssessment
		}
		return NewProtectedNativeWorkerAbortInventoryReadFunc(db, conn, inventory)(ctx, b, request)
	}
	return repository.NewNativeWorkerConcreteAbortRuntime(repository.NativeWorkerConcreteAbortRuntimeConfig{DB: db, Policy: policy, Network: network, CleanupRead: read, InventoryRead: inventoryRead, RPCClients: clients})
}
