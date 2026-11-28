package addons

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

type nativeWorkerReadinessFiles struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Only the private installation owner constructs this lifetime. SDK clients,
// callback listener and producer keys are distinct from Workers' handles and
// remain live until their respective actual joins have returned successfully.
type nativeWorkerReadinessOwner struct {
	mu             sync.Mutex
	producer       *repository.NativeWorkerReadinessProducer
	listener       *httpapi.NativeWorkerProbeResourceListener
	writer, reader *capacity.NativeWorkerRPCClient
	closed         bool
	closeErr       error
}

func (*nativeWorkerReadinessOwner) String() string     { return "[private native readiness installation]" }
func (o *nativeWorkerReadinessOwner) GoString() string { return o.String() }
func (*nativeWorkerReadinessOwner) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_installation":"redacted"}`), nil
}

func newNativeWorkerReadinessOwner(ctx context.Context, db *sql.DB, policy model.Manifest, files nativeWorkerReadinessFiles, broker func() *amqp.Connection, phase *capacity.NativeWorkerRPCClient, factories map[string]*capacity.NativeWorkerPrivateFactory) (out *nativeWorkerReadinessOwner, err error) {
	if ctx == nil || ctx.Err() != nil || db == nil || broker == nil || phase == nil || !nativeWorkerPrivatePath(files.File) || !nativeRuntimeSHA.MatchString(files.SHA256) {
		return nil, errNativeWorkerInstallation
	}
	wc, rc, err := repository.NativeWorkerReadinessRPCConfiguration(policy, files.File, files.SHA256)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	o := &nativeWorkerReadinessOwner{}
	ok := false
	defer func() {
		if !ok {
			out, err = o.rollbackConstruction(err)
		}
	}()
	o.writer, err = capacity.NewNativeWorkerRPCClient(wc)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	o.reader, err = capacity.NewNativeWorkerRPCClient(rc)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	// This captures only the dedicated reader and current broker snapshot. It
	// does not reacquire the installation owner or Workers' enclosing RLock.
	readPhase := func(call context.Context, b model.CapacityNativeWorkerPhaseReadBinding, provider, birth string) (model.CapacityNativeWorkerPhaseReadObservation, error) {
		conn := broker()
		if conn == nil || conn.IsClosed() {
			return model.CapacityNativeWorkerPhaseReadObservation{}, errNativeWorkerInstallation
		}
		return message.NewProtectedNativeWorkerPhaseReadFunc(db, conn, phase)(call, b, provider, birth)
	}
	ports, err := message.NewNativeWorkerReadinessSDKPorts(db, broker, wc.Profile, o.writer, o.reader, readPhase)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	o.producer, err = repository.NewNativeWorkerReadinessProducer(repository.NativeWorkerReadinessProducerConfig{DB: db, Policy: policy, PrivateFile: files.File, PrivateFileSHA256: files.SHA256, Ports: ports, Factories: factories})
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	material, err := o.producer.CallbackMaterial()
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	// The listener clones its own private material before the temporary loader
	// handle is discarded. No key/cert is accepted from a manifest or URL.
	defer func() {
		if key, ok := material.Certificate.PrivateKey.(ed25519.PrivateKey); ok {
			clear(key)
		}
		material.Certificate.PrivateKey = nil
	}()
	f := material.Files
	o.listener, err = httpapi.NewNativeWorkerProbeResourceListener(httpapi.NativeWorkerProbeResourceListenerConfig{ListenAddr: f.ListenAddr, ServerName: f.ServerName, CoreSourceCommit: material.CoreSourceCommit, BindingName: material.Binding.Name, SDKSourceCommit: material.Binding.SourceCommit, SDKScopeSHA256: material.Binding.ScopeSHA256, ServerLeafSHA256: f.ServerLeafSHA256, ServerURI: f.ServerURI, ClientLeafSHA256: f.ClientLeafSHA256, ClientURI: f.ClientURI, BearerTokenSHA256: f.BearerTokenSHA256, ServerCertificate: material.Certificate, ClientCAs: material.ClientCAs}, o.producer)
	if err != nil {
		return nil, errNativeWorkerInstallation
	}
	if err = o.listener.Start(ctx); err != nil {
		return nil, errNativeWorkerInstallation
	}
	if err = o.producer.Start(ctx); err != nil {
		return nil, errNativeWorkerInstallation
	}
	ok = true
	return o, nil
}

func (o *nativeWorkerReadinessOwner) rollbackConstruction(err error) (*nativeWorkerReadinessOwner, error) {
	err = errors.Join(err, o.Close())
	if errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		return o, err
	}
	return nil, err
}

func (o *nativeWorkerReadinessOwner) proof() capacity.NativeWorkerGuestWitnessProofFunc {
	if o == nil || o.producer == nil {
		return nil
	}
	return o.producer.Proof
}

func (o *nativeWorkerReadinessOwner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || errors.Is(o.closeErr, runtime.ErrDependencyShutdownHeld) {
		return o.closeErr
	}
	if o.producer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		err := o.producer.Stop(ctx)
		cancel()
		if err != nil {
			o.closeErr = errors.Join(err, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	if o.listener != nil {
		if err := o.listener.Close(); err != nil {
			o.closeErr = errors.Join(err, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	if o.producer != nil {
		if err := o.producer.Close(); err != nil {
			o.closeErr = errors.Join(err, runtime.ErrDependencyShutdownHeld)
			return o.closeErr
		}
	}
	var errs []error
	if o.reader != nil {
		errs = append(errs, o.reader.Close())
	}
	if o.writer != nil {
		errs = append(errs, o.writer.Close())
	}
	o.closed = true
	o.closeErr = errors.Join(errs...)
	return o.closeErr
}
