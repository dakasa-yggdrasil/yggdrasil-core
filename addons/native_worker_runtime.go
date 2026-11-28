package addons

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

const nativeWorkerRuntimeResource = "native_worker_private_runtime_owner"

type nativeWorkerBorrowKey struct{}

// One opaque owner holds every successful composition. The database and the
// current broker remain borrowed; no workflow or public DTO can construct it.
type nativeWorkerRuntimeOwner struct{ *nativeWorkerRuntimeOwnerState }
type nativeWorkerRuntimeOwnerState struct {
	mu                         sync.RWMutex
	sealed                     atomic.Bool
	closed                     bool
	borrowMu                   sync.Mutex
	borrowers                  int
	borrowIdle                 chan struct{}
	db                         *sql.DB
	policy                     model.Manifest
	workers                    *repository.NativeWorkerConcreteRuntime
	network                    *repository.NativeWorkerConcreteNetworkRuntime
	abort                      *repository.NativeWorkerConcreteAbortRuntime
	poolReader, registryWriter *capacity.NativeWorkerRPCClient
	poolReaderScopeSHA256      string
	mutations                  map[string]*capacity.NativeWorkerRPCClient
	readiness                  *nativeWorkerReadinessOwner
	members                    *nativeWorkerMemberOwner
	closeErr                   error
	// Construction order is credentials/clients -> Workers -> Network -> Abort.
	// Transferred handles are removed, so rollback and final Close share LIFO.
	closers []func() error
}

func (nativeWorkerRuntimeOwner) String() string     { return "[private Native runtime owner]" }
func (o nativeWorkerRuntimeOwner) GoString() string { return o.String() }
func (nativeWorkerRuntimeOwner) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_runtime_owner":"redacted"}`), nil
}

func loadNativeWorkerRuntime(ctx context.Context, app *runtime.ServiceApp, db *sql.DB, role coreprocess.Role) (*nativeWorkerRuntimeOwner, error) {
	path, present := os.LookupEnv(nativeWorkerRuntimeFileEnv)
	if !present {
		return nil, nil
	}
	if role != coreprocess.Authority || ctx == nil || ctx.Err() != nil || db == nil || app == nil {
		return nil, errNativeWorkerInstallation
	}
	if current, exists := app.Resource(nativeWorkerRuntimeResource); exists && current != nil {
		return nil, errNativeWorkerInstallation
	}
	raw, err := nativeWorkerReadRuntimeFile(path)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	c, err := nativeWorkerConfigDecode(raw, capacity.CurrentGuestCoreSource())
	if err != nil {
		return nil, err
	}
	policy, err := repository.GetManifestByID(ctx, db, c.Policy.ID)
	if err != nil || !nativeWorkerPolicyMatches(c.Policy, policy) {
		return nil, errNativeWorkerInstallation
	}
	broker := func() *amqp.Connection { conn, _ := RabbitMQ(app); return conn }
	o, err := newNativeWorkerRuntimeOwner(ctx, db, policy, c, broker, nil)
	retainNativeWorkerRuntimeHold(app, o, err)
	return o, err
}

// A failed startup must retain the opaque owner behind ServiceApp's existing
// dependency barrier. Returning the error alone would let DB/broker close while
// an original callback still owns those borrowed resources.
func retainNativeWorkerRuntimeHold(app *runtime.ServiceApp, o *nativeWorkerRuntimeOwner, err error) {
	if app != nil && errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		app.RegisterCloser(func(context.Context) error { return errors.Join(err, o.Close()) })
	}
}

func rollbackNativeWorkerRuntimeInstallation(app *runtime.ServiceApp, o *nativeWorkerRuntimeOwner, err error) error {
	err = errors.Join(err, o.Close())
	retainNativeWorkerRuntimeHold(app, o, err)
	return err
}

func (o *nativeWorkerRuntimeOwner) rollbackConstruction(err error) (*nativeWorkerRuntimeOwner, error) {
	err = errors.Join(err, o.Close())
	if errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		return o, err
	}
	return nil, err
}

func newNativeWorkerRuntimeOwner(ctx context.Context, db *sql.DB, policy model.Manifest, c nativeWorkerRuntimeConfig, broker func() *amqp.Connection, proof capacity.NativeWorkerGuestWitnessProofFunc) (out *nativeWorkerRuntimeOwner, err error) {
	var p model.CapacityPolicySpec
	if ctx == nil || ctx.Err() != nil || db == nil || broker == nil || !nativeRuntimeSHA.MatchString(c.PoolReaderScopeSHA256) || !nativeWorkerPolicyMatches(c.Policy, policy) ||
		json.Unmarshal(policy.Spec, &p) != nil || p.NativeWorkerPoolBinding == nil || p.NativeWorkerLifecycleBinding == nil ||
		p.NativeWorkerLifecycleBinding.SourceCommit != c.CoreSourceCommit || c.CoreSourceCommit != capacity.CurrentGuestCoreSource() ||
		p.NativeWorkerLifecycleBinding.PhaseObserver == nil || p.NativeWorkerLifecycleBinding.RegistryWriter == nil ||
		p.NativeWorkerLifecycleBinding.Network == nil || p.NativeWorkerLifecycleBinding.PreAdmissionAbort == nil || p.NativeWorkerLifecycleBinding.AbortInventoryObserver == nil ||
		len(c.Profiles) != len(p.NativeWorkerLifecycleBinding.Profiles) || len(c.Profiles) != len(p.NativeWorkerLifecycleBinding.PhysicalObservers) {
		return nil, errNativeWorkerInstallation
	}
	if (p.NativeWorkerLifecycleBinding.ReadinessProducer == nil) != (c.Readiness == nil) || c.Readiness != nil && proof != nil {
		return nil, errNativeWorkerInstallation
	}
	if (p.NativeWorkerLifecycleBinding.Members == nil) != (c.Members == nil) {
		return nil, errNativeWorkerInstallation
	}
	// Copy the real JSONB bytes, rather than compacting them through Marshal.
	policy.Spec = append(json.RawMessage(nil), policy.Spec...)
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{db: db, policy: policy, mutations: map[string]*capacity.NativeWorkerRPCClient{}, poolReaderScopeSHA256: c.PoolReaderScopeSHA256}}
	ok := false
	defer func() {
		if !ok {
			out, err = o.rollbackConstruction(err)
		}
	}()
	own := func(close func() error) int { o.closers = append(o.closers, close); return len(o.closers) - 1 }
	transfer := func(indices []int) {
		for _, i := range indices {
			o.closers[i] = nil
		}
	}
	makeRPC := func(files nativeWorkerRPCFiles, adapter model.CapacityMarketAdapterBinding, profile, binding, source, scope string, caps ...string) (*capacity.NativeWorkerRPCClient, int, error) {
		client, e := capacity.NewNativeWorkerRPCClient(files.config(adapter, profile, binding, source, scope, caps...))
		if e != nil {
			return nil, 0, errNativeWorkerInstallation
		}
		return client, own(client.Close), nil
	}
	files := map[string]nativeWorkerProfileFiles{}
	for _, f := range c.Profiles {
		if _, duplicate := files[f.Profile]; duplicate {
			return nil, errNativeWorkerInstallation
		}
		files[f.Profile] = f
	}
	physicalBindings := map[string]model.CapacityNativeWorkerPhysicalReadBinding{}
	for _, b := range p.NativeWorkerLifecycleBinding.PhysicalObservers {
		if _, duplicate := physicalBindings[b.Profile]; duplicate {
			return nil, errNativeWorkerInstallation
		}
		physicalBindings[b.Profile] = b
	}
	factories := map[string]*capacity.NativeWorkerPrivateFactory{}
	physicalClients := map[string]*capacity.NativeWorkerRPCClient{}
	cleanupClients := map[string]*capacity.NativeWorkerRPCClient{}
	var workerTransfers, abortTransfers []int
	for _, execution := range p.NativeWorkerLifecycleBinding.Profiles {
		f, exists := files[execution.Profile]
		if !exists || factories[execution.Profile] != nil {
			return nil, errNativeWorkerInstallation
		}
		b, exists := physicalBindings[execution.Profile]
		if !exists {
			return nil, errNativeWorkerInstallation
		}
		provider, e := newNativeWorkerArtifactProvider(db, f.ArtifactCredentials, nativeArtifactScope(c, f))
		if e != nil {
			return nil, e
		}
		own(provider.Close)
		if _, e = provider.Retrieve(ctx); e != nil {
			return nil, errNativeWorkerInstallation
		}
		factoryConfig := capacity.NativeWorkerPrivateFactoryConfig{Execution: execution, TemplateFile: f.TemplateFile, TemplateSHA256: execution.LaunchTemplateSHA256,
			CLIFile: f.CLIFile, CLISHA256: f.CLISHA256, CLIBytes: f.CLIBytes, SystemBuildSource: execution.BootstrapSourceCommit,
			AgentTokenFile: f.AgentTokenFile, CAFile: f.CAFile, WireGuardMasterFile: f.WireGuardMasterFile,
			ArtifactBucket: f.ArtifactBucket, ArtifactKey: f.ArtifactKey, ArtifactVersionID: f.ArtifactVersionID}
		if f.GuestRead != nil {
			factoryConfig.GuestRead = f.GuestRead.config()
		}
		factory, e := capacity.NewNativeWorkerPrivateFactory(factoryConfig, provider)
		if e != nil {
			return nil, errNativeWorkerInstallation
		}
		factories[execution.Profile] = factory
		workerTransfers = append(workerTransfers, own(factory.Close))
		client, index, e := makeRPC(f.PhysicalReader, b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerPhysical)
		if e != nil {
			return nil, e
		}
		physicalClients[b.Profile] = client
		workerTransfers = append(workerTransfers, index)
		client, index, e = makeRPC(f.CleanupReader, b.Adapter, b.Profile, b.BindingName, b.SourceCommit, b.ScopeSHA256, capacity.ObserveNativeWorkerCleanup)
		if e != nil {
			return nil, e
		}
		cleanupClients[b.Profile] = client
		abortTransfers = append(abortTransfers, index)
		client, _, e = makeRPC(f.ProviderMutation, execution.Adapter, execution.Profile, execution.BindingName, execution.SDKSourceCommit, execution.ScopeSHA256, execution.EnsureCapability, execution.DestroyCapability)
		if e != nil {
			return nil, e
		}
		o.mutations[execution.Profile] = client
	}
	phase := p.NativeWorkerLifecycleBinding.PhaseObserver
	phaseClient, index, e := makeRPC(c.PhaseReader, phase.Adapter, phase.Name, phase.Name, phase.SourceCommit, phase.ScopeSHA256, capacity.ObserveNativeWorkerPhase)
	if e != nil {
		return nil, e
	}
	workerTransfers = append(workerTransfers, index)
	inventory := p.NativeWorkerLifecycleBinding.AbortInventoryObserver
	inventoryClient, index, e := makeRPC(c.InventoryReader, inventory.Adapter, inventory.Name, inventory.Name, inventory.SourceCommit, inventory.ScopeSHA256, capacity.ObserveNativeWorkerAbortInventory)
	if e != nil {
		return nil, e
	}
	abortTransfers = append(abortTransfers, index)
	pool := p.NativeWorkerPoolBinding
	o.poolReader, _, e = makeRPC(c.PoolReader, pool.Adapter, pool.Name, pool.Name, pool.SourceCommit, c.PoolReaderScopeSHA256, capacity.ObserveNativeWorkerPool)
	if e != nil {
		return nil, e
	}
	registry := p.NativeWorkerLifecycleBinding.RegistryWriter
	o.registryWriter, _, e = makeRPC(c.RegistryWriter, registry.Adapter, registry.BindingName, registry.BindingName, registry.SourceCommit, registry.ScopeSHA256, registry.Capability)
	if e != nil {
		return nil, e
	}
	readinessIndex := -1
	if c.Readiness != nil {
		o.readiness, e = newNativeWorkerReadinessOwner(ctx, db, policy, *c.Readiness, broker, phaseClient, factories)
		if o.readiness != nil {
			readinessIndex = own(o.readiness.Close)
		}
		if e != nil {
			return nil, errors.Join(errNativeWorkerInstallation, e)
		}
		proof = o.readiness.proof()
	}
	o.workers, e = message.NewProtectedNativeWorkerConcreteRuntimeWithBroker(db, broker, policy, factories, phaseClient, physicalClients, proof)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	transfer(workerTransfers)
	own(o.workers.Close)
	if readinessIndex >= 0 {
		transfer([]int{readinessIndex})
		own(o.readiness.Close)
	}
	network := *p.NativeWorkerLifecycleBinding.Network
	floorReader, e := capacity.NewNativeWorkerNetworkRPCClient(c.FloorReader.floorConfig(network, "reader"))
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	readerIndex := own(floorReader.Close)
	floorWriter, e := capacity.NewNativeWorkerNetworkRPCClient(c.FloorWriter.floorConfig(network, "writer"))
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	writerIndex := own(floorWriter.Close)
	o.network, e = repository.NewNativeWorkerConcreteNetworkRuntime(repository.NativeWorkerConcreteNetworkRuntimeConfig{DB: db, Policy: policy, Workers: o.workers, Reader: floorReader, Writer: floorWriter})
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	transfer([]int{readerIndex, writerIndex})
	own(o.network.Close)
	o.abort, e = message.NewProtectedNativeWorkerConcreteAbortRuntimeWithBroker(db, broker, policy, o.network, inventoryClient, cleanupClients)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	transfer(abortTransfers)
	own(o.abort.Close)
	if c.Members != nil {
		o.members, e = newNativeWorkerMemberOwner(ctx, db, policy, p, *c.Members, broker, phaseClient, o.workers, o.abort, o.network, o.mutations)
		if o.members != nil {
			own(o.members.Close)
		}
		if e != nil {
			return nil, errors.Join(errNativeWorkerInstallation, e)
		}
	}
	ok = true
	return o, nil
}

func (o *nativeWorkerRuntimeOwner) options() []httpapi.ServerOption {
	options := []httpapi.ServerOption{httpapi.WithConcreteNativeWorkerRuntime(o.workers), httpapi.WithNativeWorkerNetworkRuntime(o.network), httpapi.WithNativeWorkerAbortRuntime(o.abort)}
	if o.members != nil {
		options = append(options, httpapi.WithNativeWorkerMemberStore(o.members.store))
	}
	return options
}

func (o *nativeWorkerRuntimeOwner) Seal() {
	if o == nil || o.nativeWorkerRuntimeOwnerState == nil {
		return
	}
	// Serialize admission with the idle-channel snapshot used by Join.
	o.borrowMu.Lock()
	// Draining closes admission without joining an original borrower.
	o.sealed.Store(true)
	o.borrowMu.Unlock()
	if o.members != nil && o.members.store != nil {
		o.members.store.Seal()
	}
}

func (o *nativeWorkerRuntimeOwner) Join(ctx context.Context) error {
	if o == nil || o.nativeWorkerRuntimeOwnerState == nil {
		return nil
	}
	if ctx == nil {
		return errNativeWorkerInstallation
	}
	o.Seal()
	o.borrowMu.Lock()
	idle := o.borrowIdle
	o.borrowMu.Unlock()
	if idle == nil {
		return nil
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *nativeWorkerRuntimeOwner) Close() error {
	if o == nil || o.nativeWorkerRuntimeOwnerState == nil {
		return nil
	}
	o.Seal()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		if errors.Is(o.closeErr, runtime.ErrDependencyShutdownHeld) {
			return o.closeErr
		}
		return nil
	}
	o.closed = true
	var errs []error
	for i := len(o.closers) - 1; i >= 0; i-- {
		if o.closers[i] != nil {
			err := o.closers[i]()
			errs = append(errs, err)
			if errors.Is(err, runtime.ErrDependencyShutdownHeld) {
				o.closers = o.closers[:i+1]
				o.closeErr = errors.Join(errs...)
				return o.closeErr
			}
			o.closers[i] = nil
		}
	}
	o.closers = nil
	o.closeErr = errors.Join(errs...)
	return o.closeErr
}

func nativeWorkerExecutionResolver(app *runtime.ServiceApp) message.NativeWorkerExecutionResolver {
	return func(ctx context.Context, db *sql.DB, policy model.Manifest, use func(context.Context, message.NativeWorkerExecutionScope) error) error {
		if ctx == nil || ctx.Err() != nil || app == nil || use == nil || ctx.Value(nativeWorkerBorrowKey{}) != nil {
			return errNativeWorkerInstallation
		}
		current, exists := app.Resource(nativeWorkerRuntimeResource)
		o, ok := current.(*nativeWorkerRuntimeOwner)
		if !exists || !ok || o == nil || o.nativeWorkerRuntimeOwnerState == nil {
			return errNativeWorkerInstallation
		}
		o.mu.RLock()
		defer o.mu.RUnlock()
		current, _ = app.Resource(nativeWorkerRuntimeResource)
		if current != o || o.closed || o.sealed.Load() || !nativeRuntimeSHA.MatchString(o.poolReaderScopeSHA256) || db != o.db || policy.APIVersion != o.policy.APIVersion || !nativeWorkerPolicyMatches(nativeWorkerPolicyPin{ID: o.policy.ID, Namespace: o.policy.Metadata.Namespace, Name: o.policy.Metadata.Name, Version: o.policy.Version, Checksum: o.policy.Checksum}, policy) ||
			!bytes.Equal(o.policy.Spec, policy.Spec) {
			return errNativeWorkerInstallation
		}
		o.borrowMu.Lock()
		if o.sealed.Load() {
			o.borrowMu.Unlock()
			return errNativeWorkerInstallation
		}
		if o.borrowers == 0 {
			o.borrowIdle = make(chan struct{})
		}
		o.borrowers++
		o.borrowMu.Unlock()
		defer func() {
			o.borrowMu.Lock()
			defer o.borrowMu.Unlock()
			o.borrowers--
			if o.borrowers == 0 {
				close(o.borrowIdle)
				o.borrowIdle = nil
			}
		}()
		mutations := make(map[string]*capacity.NativeWorkerRPCClient, len(o.mutations))
		for k, v := range o.mutations {
			mutations[k] = v
		}
		// Reject recursive resolution before taking another read lock: a Close
		// waiting for this borrower must not deadlock behind a nested RLock.
		borrowed := context.WithValue(ctx, nativeWorkerBorrowKey{}, struct{}{})
		var members *repository.CapacityNativeWorkerMemberStore
		if o.members != nil {
			members = o.members.store
		}
		return use(borrowed, message.NativeWorkerExecutionScope{Workers: o.workers, Network: o.network, Abort: o.abort, PoolReader: o.poolReader, PoolReaderScopeSHA256: o.poolReaderScopeSHA256, RegistryWriter: o.registryWriter, ProviderMutations: mutations, Members: members})
	}
}

func nativeWorkerRuntimeHandler(app *runtime.ServiceApp, next http.Handler) http.Handler {
	resolver := nativeWorkerExecutionResolver(app)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(message.WithNativeWorkerExecutionResolver(r.Context(), resolver)))
	})
}

func shutdownNativeOwnedHTTPServers(ctx context.Context, originals *httpapi.OriginalWorkflowOwners, o *nativeWorkerRuntimeOwner, servers []*http.Server) error {
	if o == nil {
		return shutdownOwnedHTTPServers(ctx, originals, servers)
	}
	// Native borrowers may still need these listeners for private SDK custody.
	// A timed-out join leaves both callbacks and dependencies owned/unclosed;
	// the process may nevertheless exit and durable uncertainty remains held.
	if err := originals.Join(ctx); err != nil {
		return errors.Join(err, runtime.ErrDependencyShutdownHeld)
	}
	if err := o.Join(ctx); err != nil {
		return errors.Join(err, runtime.ErrDependencyShutdownHeld)
	}
	if err := shutdownOwnedHTTPServers(ctx, originals, servers); err != nil {
		return errors.Join(err, runtime.ErrDependencyShutdownHeld)
	}
	return o.Close()
}
