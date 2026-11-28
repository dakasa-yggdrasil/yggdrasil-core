package addons

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// The optional main file contains only this protected reference. The referenced
// member file has its own complete Source/policy/role/TLS/whole-file pin.
type nativeWorkerMemberFiles struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type nativeWorkerMemberOwner struct {
	mu        sync.Mutex
	store     *repository.CapacityNativeWorkerMemberStore
	runtime   *repository.NativeWorkerConcreteMemberRuntime
	listeners []*httpapi.NativeWorkerMemberListener
	clients   []*capacity.NativeWorkerRPCClient
	closed    bool
	closeErr  error
}

func (*nativeWorkerMemberOwner) String() string     { return "[private Native member installation]" }
func (o *nativeWorkerMemberOwner) GoString() string { return o.String() }
func (*nativeWorkerMemberOwner) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_member_installation":"redacted"}`), nil
}

func newNativeWorkerMemberOwner(ctx context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, files nativeWorkerMemberFiles, broker func() *amqp.Connection, phase *capacity.NativeWorkerRPCClient, workers *repository.NativeWorkerConcreteRuntime, abortRuntime *repository.NativeWorkerConcreteAbortRuntime, network *repository.NativeWorkerConcreteNetworkRuntime, mutations map[string]*capacity.NativeWorkerRPCClient) (out *nativeWorkerMemberOwner, err error) {
	if ctx == nil || ctx.Err() != nil || db == nil || broker == nil || phase == nil || workers == nil || abortRuntime == nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerLifecycleBinding.PreAdmissionAbort == nil {
		return nil, errNativeWorkerInstallation
	}
	o := &nativeWorkerMemberOwner{}
	ok := false
	defer func() {
		if !ok {
			out, err = o.rollbackConstruction(err)
		}
	}()
	wc, rc, fc, e := repository.NativeWorkerMemberRPCConfiguration(policy, files.File, files.SHA256)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	for _, config := range []capacity.NativeWorkerRPCConfig{wc, rc, fc} {
		client, e := capacity.NewNativeWorkerRPCClient(config)
		if e != nil {
			return nil, errNativeWorkerInstallation
		}
		o.clients = append(o.clients, client)
	}
	ports, e := message.NewNativeWorkerMemberSDKPorts(db, broker, o.clients[0], o.clients[1], o.clients[2])
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	readPhase := func(call context.Context, b model.CapacityNativeWorkerPhaseReadBinding, provider, birth string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		conn := broker()
		if conn == nil || conn.IsClosed() {
			return model.CapacityNativeWorkerPhaseReadObservation{}, errNativeWorkerInstallation
		}
		return message.NewProtectedNativeWorkerPhaseReadFunc(db, conn, phase)(call, b, provider, birth)
	}
	o.runtime, e = repository.NewNativeWorkerConcreteMemberRuntime(repository.NativeWorkerMemberRuntimeConfig{DB: db, Policy: policy, Workers: workers, PhaseRead: readPhase, Ports: ports})
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	w := p.NativeWorkerLifecycleBinding.PreAdmissionAbort.Workflow
	wf, e := repository.ResolveManifest(ctx, db, "workflow", w.Namespace, w.Name, nil, true)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	// This process identity is private. The public operation still checks the
	// exact active recovery workflow; stock Bind has its distinct TLS parent.
	base := repository.CapacityNativeWorkerStore{Capacity: repository.CapacityStore{DB: db, WorkflowID: wf.ID, ExecutorID: uuid.NewString(), ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}, Runtime: workers, Enabled: os.Getenv("YGGDRASIL_NATIVE_WORKER_LIFECYCLE_ENABLED") == "true"}
	abort := &repository.CapacityNativeWorkerAbortStore{Workers: base, Runtime: abortRuntime, RecoveryWorkflowID: wf.ID, Enabled: os.Getenv("YGGDRASIL_NATIVE_WORKER_ABORT_ENABLED") == "true"}
	o.store, e = repository.NewCapacityNativeWorkerMemberStoreFromProtectedFile(base, policy, o.runtime, abort, network, message.NewNativeWorkerMemberProviderAbortPort(db, broker, mutations), files.File, files.SHA256)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	abort.Members = o.store
	callbacks, e := repository.NativeWorkerMemberCallbacksConfiguration(policy, files.File, files.SHA256)
	if e != nil {
		return nil, errNativeWorkerInstallation
	}
	for _, cb := range callbacks {
		material, e := repository.NativeWorkerMemberCallbackMaterial(policy, files.File, files.SHA256, cb.Role)
		if e != nil {
			return nil, errNativeWorkerInstallation
		}
		f := material.Files
		transport := httpapi.NativeWorkerProbeResourceListenerConfig{ListenAddr: f.ListenAddr, ServerName: f.ServerName, CoreSourceCommit: material.CoreSourceCommit, BindingName: material.Binding.Name, ServerLeafSHA256: f.ServerLeafSHA256, ServerURI: f.ServerURI, ClientLeafSHA256: f.ClientLeafSHA256, ClientURI: f.ClientURI, ServerCertificate: material.Certificate, ClientCAs: material.ClientCAs}
		if cb.Role != repository.NativeMemberSchedulerRole {
			transport.SDKSourceCommit = material.Binding.SourceCommit
			transport.SDKScopeSHA256 = material.Binding.ScopeSHA256
			transport.BearerTokenSHA256 = f.BearerTokenSHA256
		}
		backend := nativeWorkerMemberBackend{store: o.store, caller: repository.NativeWorkerMemberCaller{Role: cb.Role, Binding: material.Binding}}
		listener, e := httpapi.NewNativeWorkerMemberListener(httpapi.NativeWorkerMemberListenerConfig{Role: cb.Role, Transport: transport, StockProfileSourceCommit: cb.StockProfileSourceCommit, StockProfileSHA256: cb.StockProfileSHA256}, backend)
		if key, yes := material.Certificate.PrivateKey.(ed25519.PrivateKey); yes {
			clear(key)
		}
		material.Certificate.PrivateKey = nil
		if e != nil {
			return nil, errNativeWorkerInstallation
		}
		o.listeners = append(o.listeners, listener)
		if e = listener.Start(ctx); e != nil {
			return nil, errNativeWorkerInstallation
		}
	}
	ok = true
	return o, nil
}

func (o *nativeWorkerMemberOwner) rollbackConstruction(err error) (*nativeWorkerMemberOwner, error) {
	err = errors.Join(err, o.Close())
	if errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		return o, err
	}
	return nil, err
}

func (o *nativeWorkerMemberOwner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || errors.Is(o.closeErr, runtime.ErrDependencyShutdownHeld) {
		return o.closeErr
	}
	if o.store != nil {
		o.store.Seal()
	}
	if o.runtime != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		e := o.runtime.Stop(ctx)
		cancel()
		if e != nil {
			o.closeErr = errors.Join(e, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	if o.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		e := o.store.ReceivingOriginalsJoined(ctx)
		cancel()
		if e != nil {
			o.closeErr = errors.Join(e, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	for i := len(o.listeners) - 1; i >= 0; i-- {
		if e := o.listeners[i].Close(); e != nil {
			o.closeErr = errors.Join(e, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	if o.runtime != nil {
		if e := o.runtime.Close(); e != nil {
			o.closeErr = errors.Join(e, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	var errs []error
	if o.store != nil {
		errs = append(errs, o.store.Close())
	}
	for i := len(o.clients) - 1; i >= 0; i-- {
		errs = append(errs, o.clients[i].Close())
	}
	o.closed = true
	o.closeErr = errors.Join(errs...)
	return o.closeErr
}

type nativeWorkerMemberBackend struct {
	store  *repository.CapacityNativeWorkerMemberStore
	caller repository.NativeWorkerMemberCaller
}

func (b nativeWorkerMemberBackend) Read(c context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	return b.store.Read(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) ReadAllocatorFence(c context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceRead, error) {
	return b.store.ReadAllocatorFence(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) Redeem(c context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberPermit, error) {
	return b.store.Redeem(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) Receive(c context.Context, in model.CapacityNativeWorkerMemberReceive) error {
	return b.store.Receive(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) ReceiveRead(c context.Context, in model.CapacityNativeWorkerMemberReadOriginal) error {
	return b.store.ReceiveRead(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) Reconcile(c context.Context, in model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	return b.store.Reconcile(c, in, b.caller)
}
func (b nativeWorkerMemberBackend) Bind(c context.Context, in httpapi.NativeWorkerSchedulerBinding) error {
	if b.caller.Role != repository.NativeMemberSchedulerRole {
		return errNativeWorkerInstallation
	}
	return b.store.Bind(c, repository.NativeWorkerMemberPlacementRequest{PodName: in.PodName, PodNamespace: in.PodNamespace, PodUID: in.PodUID, Node: in.Node})
}
