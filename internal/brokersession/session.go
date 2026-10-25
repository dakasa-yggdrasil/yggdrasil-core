// Package brokersession owns connection recovery, not message delivery retries.
package brokersession

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Session is returned only after all consumers have been registered. Close must
// stop admission, close the socket before cancelling handlers, and join its
// handlers and monitor before returning. It must not publish or replay work.
type Session struct {
	Connection *amqp.Connection
	Transport  rpc.Transport
	Closed     <-chan *amqp.Error
	Close      func()
	Live       func() bool
}

func (s *Session) live() bool {
	return s != nil && s.Connection != nil && s.Transport != nil &&
		s.Closed != nil && s.Close != nil && s.Live != nil && s.Live()
}

type Factory func(context.Context) (*Session, error)

// ErrDrainDeadline means a retired session has not finished stopping its
// consumers and monitor. It remains unavailable; no replacement starts until
// Close actually returns, even after this error has been reported.
var ErrDrainDeadline = errors.New("broker session drain exceeded deadline; replacement withheld")

const drainTimeout = 10 * time.Second

// Drain retires a complete or partially initialized session. A slow drain is
// reported after ten seconds, but this call waits until Close actually finishes
// so its caller cannot start a concurrent generation.
func Drain(session *Session, failed func(error)) { drain(session, drainTimeout, failed) }

// Manager serializes session replacement. It never accepts message bodies and
// never retries Request or Publish. The caller retains every ambiguous outcome.
type Manager struct {
	mu      sync.RWMutex
	current *Session
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	change  func(*Session)
}

// Start adopts an already initialized session, or starts degraded when initial
// is nil. Factory is invoked serially with cancellable backoff capped at 30s.
func Start(ctx context.Context, initial *Session, factory Factory, change func(*Session), failed func(error)) *Manager {
	return start(ctx, initial, factory, change, failed, wait)
}

func start(ctx context.Context, initial *Session, factory Factory, change func(*Session), failed func(error), pause func(context.Context, time.Duration) bool) *Manager {
	ctx, cancel := context.WithCancel(ctx)
	m := &Manager{ctx: ctx, cancel: cancel, done: make(chan struct{}), change: change}
	if initial != nil && ctx.Err() == nil {
		m.replace(initial)
	}
	go m.run(ctx, initial, factory, failed, pause)
	return m
}

func (m *Manager) replace(s *Session) {
	m.mu.Lock()
	m.current = s
	m.mu.Unlock()
	if m.change != nil {
		m.change(s)
	}
}

// Connection returns only a fully initialized, currently live session. A caller
// takes one snapshot for one operation; recovery never resends that operation.
func (m *Manager) Connection() *amqp.Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ctx.Err() != nil || !m.current.live() {
		return nil
	}
	return m.current.Connection
}

func (m *Manager) Transport() rpc.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ctx.Err() != nil || !m.current.live() {
		return nil
	}
	return m.current.Transport
}

func (m *Manager) run(ctx context.Context, session *Session, factory Factory, failed func(error), pause func(context.Context, time.Duration) bool) {
	defer close(m.done)
	defer m.replace(nil)
	backoff := time.Second
	for {
		if session != nil {
			select {
			case <-ctx.Done():
			case err := <-session.Closed:
				if failed != nil && err != nil {
					failed(err)
				}
			}
			// Stop exposing the old connection before closing subscriptions or
			// dialing. There is never an old and a new active session together.
			m.replace(nil)
			Drain(session, failed)
			session = nil
		}
		if !pause(ctx, backoff) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		candidate, err := factory(ctx)
		if err == nil && !candidate.live() {
			err = errors.New("broker session initialization did not produce a live transport")
		}
		if err != nil {
			if candidate != nil && candidate.Close != nil {
				Drain(candidate, failed)
			}
			if failed != nil {
				failed(err)
			}
			backoff = min(30*time.Second, backoff*2)
			continue
		}
		if ctx.Err() != nil {
			Drain(candidate, failed)
			return
		}
		session = candidate
		m.replace(session)
		backoff = time.Second
	}
}

func drain(session *Session, timeout time.Duration, failed func(error)) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		session.Close()
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		if failed != nil {
			failed(ErrDrainDeadline)
		}
	}
	// Returning on timeout would allow a second generation to start while old
	// handlers or probes still run. Shutdown itself has the caller's deadline.
	<-done
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.cancel()
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
