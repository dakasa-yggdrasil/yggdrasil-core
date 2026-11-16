// Package lifecycle tracks process-local ownership of explicitly declared lanes.
// It neither cancels providers nor certifies distributed mutation quiescence.
package lifecycle

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
)

const MaxLanes = 64

type State string

const (
	Pending  State = "pending"
	Running  State = "running"
	Done     State = "done"
	Inactive State = "inactive"
	Failed   State = "failed"
)

var (
	ErrAdmissionClosed = errors.New("lifecycle admission closed")
	ErrNotDraining     = errors.New("lifecycle group is not draining")
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Snapshot is local lifetime evidence only. Failed records a returned error,
// never a sanitized approximation of domain or provider state.
type Snapshot struct {
	Draining bool
	Drained  bool
	Lanes    map[string]State
}

type Group struct {
	mu       sync.Mutex
	names    []string
	lanes    map[string]State
	laneDone map[string]chan struct{}
	draining bool
	drained  bool
	done     chan struct{}
}

// NewGroup declares the complete lane roster before startup. An empty roster is
// explicit; a declared lane left pending prevents a completed drain.
func NewGroup(names ...string) (*Group, error) {
	if len(names) > MaxLanes {
		return nil, errors.New("lifecycle lane roster exceeds limit")
	}
	g := &Group{lanes: make(map[string]State, len(names)), laneDone: make(map[string]chan struct{}, len(names)), done: make(chan struct{})}
	for _, name := range names {
		if !namePattern.MatchString(name) {
			return nil, errors.New("invalid lifecycle lane name")
		}
		if _, exists := g.lanes[name]; exists {
			return nil, errors.New("duplicate lifecycle lane name")
		}
		g.names = append(g.names, name)
		g.lanes[name] = Pending
		g.laneDone[name] = make(chan struct{})
	}
	sort.Strings(g.names)
	return g, nil
}

// Start owns run until it returns. It never starts an undeclared, duplicate or
// post-drain lane. The caller owns cancellation and must retain dependencies
// until Wait succeeds. A panic is recorded as failure, then propagates normally.
func (g *Group) Start(name string, run func() error) error {
	if run == nil {
		return errors.New("nil lifecycle runner")
	}
	g.mu.Lock()
	if g.draining {
		g.mu.Unlock()
		return ErrAdmissionClosed
	}
	state, exists := g.lanes[name]
	if !exists || state != Pending {
		g.mu.Unlock()
		return errors.New("lifecycle lane is undeclared or already admitted")
	}
	g.lanes[name] = Running
	g.mu.Unlock()
	go func() {
		completed := false
		defer func() {
			if !completed {
				g.finish(name, Failed)
			}
		}()
		state := Done
		if err := run(); err != nil {
			state = Failed
		}
		g.finish(name, state)
		completed = true
	}()
	return nil
}

// Track owns a separately started component's actual join handle. Cancellation
// or a timeout must never close that handle; only actual component return does.
func (g *Group) Track(name string, done <-chan struct{}) error {
	if done == nil {
		return errors.New("nil lifecycle completion handle")
	}
	return g.Start(name, func() error {
		<-done
		return nil
	})
}

// MarkInactive explicitly records a configured inactive lane before drain.
// It does not stop or replace a running lane.
func (g *Group) MarkInactive(name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return ErrAdmissionClosed
	}
	state, exists := g.lanes[name]
	if !exists || state != Pending {
		return errors.New("lifecycle lane is undeclared or already admitted")
	}
	g.lanes[name] = Inactive
	close(g.laneDone[name])
	return nil
}

// BeginDrain closes local startup admission. Caller cancellation is separate.
func (g *Group) BeginDrain() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = true
	g.maybeDrainedLocked()
}

func (g *Group) finish(name string, state State) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lanes[name] != Running {
		return
	}
	g.lanes[name] = state
	close(g.laneDone[name])
	g.maybeDrainedLocked()
}

func (g *Group) maybeDrainedLocked() {
	if !g.draining || g.drained {
		return
	}
	for _, state := range g.lanes {
		if state == Pending || state == Running {
			return
		}
	}
	g.drained = true
	close(g.done)
}

// Wait joins actual admitted work. A context error changes no lane or receipt;
// a subsequent call may join after the work actually returns.
func (g *Group) Wait(ctx context.Context) error {
	g.mu.Lock()
	draining := g.draining
	g.mu.Unlock()
	if !draining {
		return ErrNotDraining
	}
	select {
	case <-g.done:
		return nil
	default:
	}
	select {
	case <-g.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitLanes joins selected actual local returns during staged shutdown. Names
// must be nonempty, distinct and declared in the immutable roster. Call it only
// after BeginDrain. It never marks global Drained, and returned/failed local work
// is not business success or remote quiescence. Context errors change no state.
// A caller may join every dependency user, then close/join that dependency lane,
// and finally use Wait to require the complete process roster.
func (g *Group) WaitLanes(ctx context.Context, names ...string) error {
	if len(names) == 0 || len(names) > MaxLanes {
		return errors.New("invalid selected lifecycle lane roster")
	}
	g.mu.Lock()
	if !g.draining {
		g.mu.Unlock()
		return ErrNotDraining
	}
	seen := make(map[string]bool, len(names))
	selected := make([]<-chan struct{}, 0, len(names))
	for _, name := range names {
		done, exists := g.laneDone[name]
		if !exists || seen[name] {
			g.mu.Unlock()
			return errors.New("selected lifecycle lane is undeclared or duplicate")
		}
		seen[name] = true
		selected = append(selected, done)
	}
	g.mu.Unlock()
	for _, done := range selected {
		select {
		case <-done:
			continue
		default:
		}
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (g *Group) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := Snapshot{Draining: g.draining, Drained: g.drained, Lanes: make(map[string]State, len(g.lanes))}
	for _, name := range g.names {
		s.Lanes[name] = g.lanes[name]
	}
	return s
}
