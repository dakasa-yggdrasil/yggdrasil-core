package runtime

import (
	"context"
	"sync"
)

// Closer shuts down a runtime resource.
type Closer func(context.Context) error

// ServiceApp stores the shared runtime state for the template service.
type ServiceApp struct {
	ServiceName string

	mu        sync.RWMutex
	resources map[string]any
	closers   []Closer
}

// New creates a new runtime container for the service.
func New(serviceName string) *ServiceApp {
	return &ServiceApp{
		ServiceName: serviceName,
		resources:   map[string]any{},
		closers:     []Closer{},
	}
}

// SetResource stores a runtime resource.
func (a *ServiceApp) SetResource(name string, value any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resources[name] = value
}

// Resource returns a previously registered runtime resource.
func (a *ServiceApp) Resource(name string) (any, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	value, ok := a.resources[name]
	return value, ok
}

// RegisterCloser registers a closer executed on shutdown.
func (a *ServiceApp) RegisterCloser(fn Closer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closers = append(a.closers, fn)
}

// Shutdown runs all registered closers in reverse order.
func (a *ServiceApp) Shutdown(ctx context.Context) error {
	a.mu.RLock()
	closers := make([]Closer, len(a.closers))
	copy(closers, a.closers)
	a.mu.RUnlock()

	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i](ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
