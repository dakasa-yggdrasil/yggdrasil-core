package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type NativeWorkerMemberSDKPorts struct {
	Read   capacity.NativeWorkerMemberReadFunc
	Fence  capacity.NativeWorkerAllocatorFenceReadFunc
	Mutate capacity.NativeWorkerMemberWriteFunc
}
type NativeWorkerMemberRuntimeConfig struct {
	DB        *sql.DB
	Policy    model.Manifest
	Workers   *NativeWorkerConcreteRuntime
	PhaseRead capacity.NativeWorkerPhaseReadFunc
	Ports     NativeWorkerMemberSDKPorts
}

type NativeWorkerConcreteMemberRuntime struct{ state *nativeMemberRuntimeState }
type nativeMemberRuntimeState struct {
	mu              sync.Mutex
	closing, closed bool
	active          int
	idle            chan struct{}
	root            context.Context
	cancel          context.CancelFunc
	db              *sql.DB
	policy          model.Manifest
	spec            model.CapacityPolicySpec
	source          string
	workers         *NativeWorkerConcreteRuntime
	phase           capacity.NativeWorkerPhaseReadFunc
	ports           NativeWorkerMemberSDKPorts
}

func (NativeWorkerConcreteMemberRuntime) String() string               { return "[private native member runtime]" }
func (r NativeWorkerConcreteMemberRuntime) GoString() string           { return r.String() }
func (NativeWorkerConcreteMemberRuntime) MarshalJSON() ([]byte, error) { return nil, errNativeMember }
func (NativeWorkerMemberRuntimeConfig) String() string {
	return "[private native member runtime configuration]"
}
func (c NativeWorkerMemberRuntimeConfig) GoString() string           { return c.String() }
func (NativeWorkerMemberRuntimeConfig) MarshalJSON() ([]byte, error) { return nil, errNativeMember }

// All supplied handles remain borrowed, even after successful construction.
// The owner must stop/join this borrower before closing Workers or RPC clients.
func NewNativeWorkerConcreteMemberRuntime(c NativeWorkerMemberRuntimeConfig) (*NativeWorkerConcreteMemberRuntime, error) {
	p, e := parseCapacityPolicy(c.Policy)
	if c.DB == nil || c.Workers == nil || !c.Workers.BoundToDatabase(c.DB) || !c.Workers.policyMatches(c.Policy) || e != nil || capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil || p.NativeWorkerLifecycleBinding.SourceCommit != capacity.CurrentGuestCoreSource() || c.Workers.SourceCommit() != p.NativeWorkerLifecycleBinding.SourceCommit || c.PhaseRead == nil || c.Ports.Read == nil || c.Ports.Fence == nil || c.Ports.Mutate == nil {
		return nil, ErrCapacityDisabled
	}
	c.Workers.mu.RLock()
	for _, execution := range p.NativeWorkerLifecycleBinding.Profiles {
		f := c.Workers.factories[execution.Profile]
		if f == nil || !f.MatchesExecution(execution) || !f.MatchesPlacementBootstrapPolicy(p.NativeWorkerLifecycleBinding.Members.BootstrapPolicySHA256) {
			c.Workers.mu.RUnlock()
			return nil, ErrCapacityDisabled
		}
	}
	c.Workers.mu.RUnlock()
	raw, e := json.Marshal(c.Policy)
	var own model.Manifest
	if e != nil || json.Unmarshal(raw, &own) != nil {
		return nil, errNativeMember
	}
	own.Spec = append(json.RawMessage(nil), c.Policy.Spec...)
	idle := make(chan struct{})
	close(idle)
	root, cancel := context.WithCancel(context.Background())
	return &NativeWorkerConcreteMemberRuntime{state: &nativeMemberRuntimeState{db: c.DB, policy: own, spec: p, source: p.NativeWorkerLifecycleBinding.SourceCommit, workers: c.Workers, phase: c.PhaseRead, ports: c.Ports, idle: idle, root: root, cancel: cancel}}, nil
}

// Identity is immutable and intentionally does not acquire the operation lock:
// an SDK callback may resolve it while the original SDK RPC is still in flight.
func (r *NativeWorkerConcreteMemberRuntime) SourceCommit() string {
	if r == nil || r.state == nil {
		return ""
	}
	return r.state.source
}
func (r *NativeWorkerConcreteMemberRuntime) enter(ctx context.Context) (*nativeMemberRuntimeState, context.Context, func(), error) {
	if r == nil || r.state == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, nil, errNativeMember
	}
	s := r.state
	s.mu.Lock()
	if s.closing || s.closed {
		s.mu.Unlock()
		return nil, nil, nil, errNativeMember
	}
	if s.active == 0 {
		s.idle = make(chan struct{})
	}
	s.active++
	s.mu.Unlock()
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.root, cancel)
	done := func() {
		stop()
		cancel()
		s.mu.Lock()
		s.active--
		if s.active == 0 {
			close(s.idle)
		}
		s.mu.Unlock()
	}
	return s, child, done, nil
}
func (r *NativeWorkerConcreteMemberRuntime) Stop(ctx context.Context) error {
	if r == nil || r.state == nil {
		return nil
	}
	s := r.state
	s.mu.Lock()
	s.closing = true
	s.cancel()
	idle := s.idle
	s.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return errNativeMember
	}
}
func (r *NativeWorkerConcreteMemberRuntime) Close() error {
	if r == nil || r.state == nil {
		return nil
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.closing || s.active != 0 {
		return errNativeMember
	}
	s.closed = true
	return nil
}

func (r *NativeWorkerConcreteMemberRuntime) Target(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhaseReadObservation, error) {
	var zero model.CapacityNativeWorkerPhaseReadObservation
	s, child, done, e := r.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer done()
	if a.Physical == nil || a.PolicyID != s.policy.ID || a.PolicyChecksum != s.policy.Checksum || a.SourceCommit != s.source {
		return zero, errNativeMember
	}
	return s.phase(child, *s.spec.NativeWorkerLifecycleBinding.PhaseObserver, a.Physical.ProviderID, a.BirthSHA256)
}
func (r *NativeWorkerConcreteMemberRuntime) Observe(ctx context.Context, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext) (model.CapacityNativeWorkerMemberObservation, error) {
	var zero model.CapacityNativeWorkerMemberObservation
	s, child, done, e := r.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer done()
	if capacity.NativeWorkerMemberContextValid(s.spec, a, c, time.Now().UTC(), c.PlacementFenceSHA256 == "") != nil {
		return zero, errNativeMember
	}
	return s.ports.Read(child, c.Observer, model.CapacityNativeWorkerMemberSelectors{BindingName: c.Observer.BindingName, PermitID: c.PermitID})
}
func (r *NativeWorkerConcreteMemberRuntime) Send(ctx context.Context, c model.CapacityNativeWorkerMemberContext) error {
	s, child, done, e := r.enter(ctx)
	if e != nil {
		return e
	}
	defer done()
	if c.CoreSourceCommit != s.source || c.PolicyID != s.policy.ID.String() || c.PolicyChecksum != s.policy.Checksum || !c.NotAfter.After(time.Now().UTC()) {
		return errNativeMember
	}
	bounded, cancel := context.WithDeadline(child, c.NotAfter)
	defer cancel()
	return s.ports.Mutate(bounded, c.Actor, model.CapacityNativeWorkerMemberSelectors{BindingName: c.Actor.BindingName, PermitID: c.PermitID})
}
func (r *NativeWorkerConcreteMemberRuntime) Facts(ctx context.Context, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerMemberContext) (capacity.NativeWorkerMemberFacts, error) {
	var zero capacity.NativeWorkerMemberFacts
	s, child, done, e := r.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer done()
	if capacity.NativeWorkerMemberContextValid(s.spec, a, c, time.Now().UTC(), c.PlacementFenceSHA256 == "") != nil {
		return zero, errNativeMember
	}
	observation, e := s.ports.Read(child, c.Observer, model.CapacityNativeWorkerMemberSelectors{BindingName: c.Observer.BindingName, PermitID: c.PermitID})
	if e != nil {
		return zero, e
	}
	b := s.spec.NativeWorkerLifecycleBinding.Members.AllocatorFenceReader
	fenceEndpoint := capacity.NativeWorkerMemberEndpoint(b, "observe_native_worker_allocator_fence")
	fence, e := s.ports.Fence(child, fenceEndpoint, model.CapacityNativeWorkerMemberSelectors{BindingName: b.Name, PermitID: a.ID.String()})
	if e != nil {
		return zero, e
	}
	// Borrow the actual sealed qualifier and factory. No owner getter, new birth,
	// replacement acceptance ID or injected production witness is used here.
	w := s.workers
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed || !w.attemptProfileBound(a) || w.physical == nil {
		return zero, errNativeMember
	}
	original, e := w.loadOriginal(child, a)
	if e != nil {
		return zero, e
	}
	defer clear(original.Wire)
	launch, e := w.launchAndOriginal(child, a, original)
	if e != nil {
		return zero, e
	}
	physical, e := w.physical.ReadLifecycleACK(child, a, launch, original)
	if e != nil {
		return zero, e
	}
	f := w.factories[a.Profile]
	if f == nil {
		return zero, errNativeMember
	}
	bootstrap, e := f.ReadPlacementBootstrap(child, a, launch, s.spec.NativeWorkerLifecycleBinding.Members.BootstrapPolicySHA256)
	if e != nil || child.Err() != nil {
		return zero, errNativeMember
	}
	out := capacity.NativeWorkerMemberFacts{Observation: observation, Bootstrap: bootstrap, Fence: fence, Physical: &capacity.NativeWorkerMemberPhysicalFact{Physical: physical.Physical, Adapter: physical.Adapter, SourceCommit: physical.SourceCommit, ScopeSHA256: physical.ScopeSHA256, EvidenceSHA256: physical.EvidenceSHA256, ObservedAt: physical.ObservedAt}}
	out.ValidUntil = capacity.NativeWorkerMemberFactsValidUntil(s.spec, a, out)
	return out, nil
}

func (r *NativeWorkerConcreteMemberRuntime) AllocatorFence(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAllocatorFenceContext, model.CapacityNativeWorkerAllocatorFenceObservation, error) {
	var c model.CapacityNativeWorkerAllocatorFenceContext
	var o model.CapacityNativeWorkerAllocatorFenceObservation
	s, child, done, e := r.enter(ctx)
	if e != nil {
		return c, o, e
	}
	defer done()
	c, e = nativeMemberFenceContext(child, s.db, s.policy, s.spec, a)
	if e != nil {
		return c, o, e
	}
	o, e = s.ports.Fence(child, c.Observer, model.CapacityNativeWorkerMemberSelectors{BindingName: c.Observer.BindingName, PermitID: a.ID.String()})
	return c, o, e
}
