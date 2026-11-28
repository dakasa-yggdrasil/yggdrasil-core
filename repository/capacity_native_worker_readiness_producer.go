package repository

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type NativeWorkerReadinessProducerConfig struct {
	DB                             *sql.DB
	Policy                         model.Manifest
	PrivateFile, PrivateFileSHA256 string
	Ports                          NativeWorkerReadinessPorts
	Factories                      map[string]*capacity.NativeWorkerPrivateFactory
}

type NativeWorkerReadinessProducer struct{ state *nativeReadinessProducerState }
type nativeReadinessProducerState struct {
	mu            sync.Mutex
	closed        bool
	active        int
	running       map[uuid.UUID]bool
	journal       *nativeReadinessRunJournal
	backend       nativeReadinessBackend
	spec          model.CapacityPolicySpec
	config        nativeReadinessPrivateConfig
	pins          nativeReadinessObservationPins
	ports         NativeWorkerReadinessPorts
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
	cleanupFailed bool
	cleanupCursor uuid.UUID
	factories     map[string]*capacity.NativeWorkerPrivateFactory
}

func (NativeWorkerReadinessProducer) String() string     { return "[private native readiness producer]" }
func (p NativeWorkerReadinessProducer) GoString() string { return p.String() }
func (NativeWorkerReadinessProducer) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_producer":"redacted"}`), nil
}
func (NativeWorkerReadinessProducerConfig) String() string {
	return "[private native readiness producer configuration]"
}
func (c NativeWorkerReadinessProducerConfig) GoString() string { return c.String() }
func (NativeWorkerReadinessProducerConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_producer_configuration":"redacted"}`), nil
}

// Installed protected composition uses these exact references to build two
// dedicated mTLS SDK clients. The producer reloads the same whole-file pin;
// changing a file between client construction and startup fails closed.
func NativeWorkerReadinessRPCConfiguration(policy model.Manifest, path, scope string) (capacity.NativeWorkerRPCConfig, capacity.NativeWorkerRPCConfig, error) {
	var zero capacity.NativeWorkerRPCConfig
	c, key, _, err := nativeReadinessLoadConfig(path, scope, policy, capacity.CurrentGuestCoreSource())
	clear(key)
	if err != nil {
		return zero, zero, err
	}
	return c.WriterRPC.Config(c.Binding.ResourceWriter, false), c.ReaderRPC.Config(c.Binding.ResourceReader, true), nil
}

func NewNativeWorkerReadinessProducer(c NativeWorkerReadinessProducerConfig) (*NativeWorkerReadinessProducer, error) {
	return newNativeWorkerReadinessProducer(c, capacity.CurrentGuestCoreSource())
}

func newNativeWorkerReadinessProducer(c NativeWorkerReadinessProducerConfig, source string) (*NativeWorkerReadinessProducer, error) {
	if c.DB == nil || c.Ports.Read == nil || c.Ports.Mutate == nil || c.Ports.Phase == nil {
		return nil, errNativeReadinessRun
	}
	loaded, key, pins, err := nativeReadinessLoadConfig(c.PrivateFile, c.PrivateFileSHA256, c.Policy, source)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	spec, err := parseCapacityPolicy(c.Policy)
	if err != nil {
		return nil, errNativeReadinessRun
	}
	if len(c.Factories) != len(spec.NativeWorkerLifecycleBinding.Profiles) {
		return nil, errNativeReadinessRun
	}
	factories := make(map[string]*capacity.NativeWorkerPrivateFactory, len(c.Factories))
	for _, profile := range spec.NativeWorkerLifecycleBinding.Profiles {
		f := c.Factories[profile.Profile]
		if f == nil || !f.MatchesExecution(profile) || !f.MatchesGuestNetwork(spec.NativeWorkerLifecycleBinding.Network.Template, spec.NativeWorkerLifecycleBinding.Network.TemplateSHA256) {
			return nil, errNativeReadinessRun
		}
		factories[profile.Profile] = f
	}
	template, err := nativeReadinessDigest(struct {
		Schema  string                                     `json:"schema"`
		Binding model.CapacityNativeWorkerReadinessBinding `json:"binding"`
		Scope   string                                     `json:"scope"`
	}{"native_worker_readiness_template_v1", loaded.Binding, c.PrivateFileSHA256})
	if err != nil {
		return nil, err
	}
	journal, err := newNativeReadinessRunJournal(c.DB, c.Policy, source, c.PrivateFileSHA256, template, key)
	if err != nil {
		return nil, err
	}
	state := &nativeReadinessProducerState{running: map[uuid.UUID]bool{}, journal: journal, backend: nativeReadinessBackend{journal, loaded.Binding.ResourceWriter}, spec: spec, config: loaded, pins: pins, ports: c.Ports, factories: factories}
	return &NativeWorkerReadinessProducer{state}, nil
}

// No lock spans WAN. In particular, a synchronous SDK call can enter the
// authenticated receiver while the proof callback is under Workers' read fence.
func (p *NativeWorkerReadinessProducer) enter(attempt uuid.UUID) (func(), error) {
	if p == nil || p.state == nil {
		return nil, errNativeReadinessRun
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || attempt != uuid.Nil && s.running[attempt] {
		return nil, errNativeReadinessRun
	}
	s.active++
	if attempt != uuid.Nil {
		s.running[attempt] = true
	}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.active--
		if attempt != uuid.Nil {
			delete(s.running, attempt)
		}
	}, nil
}

// Call only after Workers and the owned receiving listener have genuinely
// joined. A failed/unjoined listener Close must not be disguised as this join.
// Busy Close closes nothing: original receiving and borrowed DB remain alive.
func (p *NativeWorkerReadinessProducer) Close() error {
	if p == nil || p.state == nil {
		return nil
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.cleanupDone != nil {
		select {
		case <-s.cleanupDone:
		default:
			return errNativeReadinessRun
		}
	}
	if s.cleanupFailed {
		return errNativeReadinessRun
	}
	if s.active != 0 {
		return errNativeReadinessRun
	}
	s.closed = true
	s.journal.close()
	return nil
}

func (p *NativeWorkerReadinessProducer) Read(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceContext, error) {
	done, err := p.enter(uuid.Nil)
	if err != nil {
		return model.NativeWorkerProbeResourceContext{}, err
	}
	defer done()
	return p.state.backend.Read(ctx, in)
}
func (p *NativeWorkerReadinessProducer) Bootstrap(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceBootstrap, error) {
	done, err := p.enter(uuid.Nil)
	if err != nil {
		return model.NativeWorkerProbeResourceBootstrap{}, err
	}
	defer done()
	return p.state.backend.Bootstrap(ctx, in)
}
func (p *NativeWorkerReadinessProducer) Redeem(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourcePermit, error) {
	done, err := p.enter(uuid.Nil)
	if err != nil {
		return model.NativeWorkerProbeResourcePermit{}, err
	}
	defer done()
	return p.state.backend.Redeem(ctx, in)
}
func (p *NativeWorkerReadinessProducer) Receive(ctx context.Context, in model.NativeWorkerProbeResourceReceive) error {
	done, err := p.enter(uuid.Nil)
	if err != nil {
		return err
	}
	defer done()
	return p.state.backend.Receive(ctx, in)
}

// The protected addon owns the resulting listener and RPC client lifetimes.
// This explicit private Go carrier is never exposed through an HTTP/manifest.
type NativeWorkerReadinessCallbackMaterial struct {
	Files            NativeWorkerReadinessCallbackFiles
	CoreSourceCommit string
	Binding          model.CapacityNativeWorkerProbeResourceBinding
	Certificate      tls.Certificate
	ClientCAs        *x509.CertPool
}

func (NativeWorkerReadinessCallbackMaterial) String() string {
	return "[private native readiness listener material]"
}
func (m NativeWorkerReadinessCallbackMaterial) GoString() string { return m.String() }
func (NativeWorkerReadinessCallbackMaterial) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_listener_material":"redacted"}`), nil
}

func (p *NativeWorkerReadinessProducer) CallbackMaterial() (NativeWorkerReadinessCallbackMaterial, error) {
	var zero NativeWorkerReadinessCallbackMaterial
	done, err := p.enter(uuid.Nil)
	if err != nil {
		return zero, err
	}
	defer done()
	f := p.state.config.Callback
	cert, err := nativeReadinessReadFile(f.ServerCertificateFile, 64<<10, false)
	if err != nil {
		return zero, err
	}
	key, err := nativeReadinessReadFile(f.ServerKeyFile, 32<<10, true)
	defer clear(key)
	if err != nil {
		return zero, err
	}
	ca, err := nativeReadinessReadFile(f.ClientCAFile, 64<<10, false)
	if err != nil {
		return zero, err
	}
	sum := sha256.Sum256(ca)
	pair, pe := tls.X509KeyPair(cert, key)
	pool := x509.NewCertPool()
	if pe != nil || hex.EncodeToString(sum[:]) != f.ClientCASHA256 || !pool.AppendCertsFromPEM(ca) {
		return zero, errNativeReadinessRun
	}
	return NativeWorkerReadinessCallbackMaterial{Files: f, CoreSourceCommit: p.state.journal.source, Binding: p.state.config.Binding.ResourceWriter, Certificate: pair, ClientCAs: pool}, nil
}

// Proof is the real existing GuestWitnessProofFunc port. It is never a workflow
// proof argument, and nil/unconfigured composition continues to HOLD.
func (p *NativeWorkerReadinessProducer) Proof(ctx context.Context, a model.CapacityNativeWorkerAttempt, witness model.CapacityNativeWorkerGuestWitness) (*model.CapacityNativeWorkerReadinessProof, error) {
	done, err := p.enter(a.ID)
	if err != nil {
		return nil, err
	}
	defer done()
	if ctx == nil || ctx.Err() != nil || a.ID == uuid.Nil {
		return nil, errNativeReadinessRun
	}
	return p.state.produce(ctx, a, witness)
}

// The initial config is parsed into owned state; its private representations
// never serialize secret refs through a policy copy or generic JSON printer.
var _ capacity.NativeWorkerGuestWitnessProofFunc = (*NativeWorkerReadinessProducer)(nil).Proof
var _ json.Marshaler = NativeWorkerReadinessProducer{}
