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
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil ||
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
		return NewProtectedNativeWorkerPhysicalReadFunc(db, conn, readers[b.Profile])(ctx, b, requested)
	}
	return repository.NewNativeWorkerConcreteRuntime(repository.NativeWorkerConcreteRuntimeConfig{
		DB: db, Policy: policy, Factories: factories,
		PhaseRead: NewProtectedNativeWorkerPhaseReadFunc(db, conn, phaseClient), PhysicalRead: physical, RPCClients: clients,
	})
}
