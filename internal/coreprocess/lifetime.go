package coreprocess

import (
	"context"
	"errors"
	"net/http"
	"sync"

	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
)

const LifetimeResource = "core_api_worker_lifetime"

// WorkerLanes is the complete process-local roster for the closed api_worker
// addon set. The authority's other lanes are not represented or certified here.
func WorkerLanes() []string {
	return []string{"broker_session", "dependencies", "listeners", "request_audits", "requests", "signal", "workflow_originals"}
}

type Lifetime struct {
	group                *lifecycle.Group
	guard                *lifecycle.NativeAdmissionGuard
	mu                   sync.Mutex
	requests             int
	requestsClosed       bool
	requestFailed        bool
	requestsReturned     chan struct{}
	dependenciesReturned chan struct{}
	dependenciesOnce     sync.Once
	failed               chan struct{}
	failOnce             sync.Once
}

// NewLifetime performs only local configuration validation. There is no network
// access, caller receipt, background admission or finalizer operation here.
func NewLifetime() (*Lifetime, error) {
	if err := ValidateWorkerEnvironment(); err != nil {
		return nil, err
	}
	g, err := lifecycle.NewGroup(WorkerLanes()...)
	if err != nil {
		return nil, err
	}
	guard, err := lifecycle.NewNativeAdmissionGuardFromEnvironment(g)
	if err != nil {
		return nil, err
	}
	l := &Lifetime{group: g, guard: guard, requestsReturned: make(chan struct{}), dependenciesReturned: make(chan struct{}), failed: make(chan struct{})}
	if err := g.Track("dependencies", l.dependenciesReturned); err != nil {
		return nil, err
	}
	if err := g.Start("requests", func() error {
		<-l.requestsReturned
		l.mu.Lock()
		failed := l.requestFailed
		l.mu.Unlock()
		if failed {
			return errors.New("API worker request panicked")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return l, nil
}

// Start and Track retain actual component return handles. Their callers must
// not close a handle on cancellation or on a guessed successful stop.
func (l *Lifetime) Start(lane string, run func() error) error { return l.group.Start(lane, run) }
func (l *Lifetime) Track(lane string, returned <-chan struct{}) error {
	return l.group.Track(lane, returned)
}
func (l *Lifetime) BeginDrain()                          { l.group.BeginDrain() }
func (l *Lifetime) Fail()                                { l.failOnce.Do(func() { l.group.BeginDrain(); close(l.failed) }) }
func (l *Lifetime) Failed() <-chan struct{}              { return l.failed }
func (l *Lifetime) NativeAdmissionHandler() http.Handler { return l.guard.Handler() }
func (l *Lifetime) RootsOpen() bool                      { return l.guard.RootsOpen() }

func (l *Lifetime) Open(ctx context.Context) error {
	if err := l.guard.WaitForProjection(ctx); err != nil {
		return err
	}
	return l.guard.OpenRootAdmission()
}

// Handler owns every HTTP return, including health and authenticated process
// observations. Only the exact admission route bypasses the external root gate.
// Role restrictions are enforced separately by the actual HTTP authorization
// owner; this guard does not grant any request a principal or capability.
func (l *Lifetime) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		if l.requestsClosed {
			l.mu.Unlock()
			http.Error(w, "API worker closing", http.StatusServiceUnavailable)
			return
		}
		l.requests++
		l.mu.Unlock()
		returned := false
		defer func() {
			l.mu.Lock()
			if !returned {
				l.requestFailed = true
			}
			l.requests--
			if l.requestsClosed && l.requests == 0 {
				close(l.requestsReturned)
			}
			l.mu.Unlock()
			if !returned {
				l.Fail()
			}
		}()
		if r.URL.Path == lifecycle.NativeAdmissionPath && r.URL.RawPath == "" && r.URL.RawQuery == "" && !r.URL.ForceQuery {
			l.guard.Handler().ServeHTTP(w, r)
		} else if !l.guard.RootsOpen() && (r.Method != http.MethodGet || r.URL.Path != "/healthz") {
			http.Error(w, "native admission unavailable", http.StatusServiceUnavailable)
		} else {
			next.ServeHTTP(w, r)
		}
		returned = true
	})
}

// HTTPShutdownReturned is called only after every original Server.Shutdown has
// returned nil. Closing this gate is not an alternative to those real joins.
func (l *Lifetime) HTTPShutdownReturned() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.requestsClosed {
		l.requestsClosed = true
		if l.requests == 0 {
			close(l.requestsReturned)
		}
	}
}

// DependenciesShutdownReturned follows the actual entire runtime closer pass.
// Any error leaves this handle open and forbids a successful process receipt.
func (l *Lifetime) DependenciesShutdownReturned() {
	l.dependenciesOnce.Do(func() { close(l.dependenciesReturned) })
}

func (l *Lifetime) WriteJoinedReceipt(ctx context.Context) error {
	if err := l.group.Wait(ctx); err != nil {
		return err
	}
	select {
	case <-l.failed:
		return errors.New("API worker failed during its original lifetime")
	default:
	}
	written, err := l.guard.WriteTerminationReceipt()
	if err != nil {
		return err
	}
	if !written {
		return errors.New("API worker native termination receipt unavailable")
	}
	return nil
}
