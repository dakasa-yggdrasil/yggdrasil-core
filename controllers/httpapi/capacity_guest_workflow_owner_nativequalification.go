//go:build linux && nativequalification

package httpapi

import (
	"context"
	"errors"
	"sync"
)

type NativeOriginalWorkflowOwners struct {
	ctx      context.Context
	mu       sync.Mutex
	active   int
	sealed   bool
	returned chan struct{}
}

func NewNativeOriginalWorkflowOwners(ctx context.Context) (*NativeOriginalWorkflowOwners, error) {
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return nil, errors.New("original native workflow deadline required")
	}
	return &NativeOriginalWorkflowOwners{ctx: ctx, returned: make(chan struct{})}, nil
}
func (o *NativeOriginalWorkflowOwners) Begin() (context.Context, func(), error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed || o.ctx.Err() != nil {
		return nil, nil, errors.New("original native workflow owner closed")
	}
	o.active++
	var once sync.Once
	finish := func() {
		once.Do(func() {
			o.mu.Lock()
			defer o.mu.Unlock()
			o.active--
			if o.sealed && o.active == 0 {
				close(o.returned)
			}
		})
	}
	return o.ctx, finish, nil
}
func (o *NativeOriginalWorkflowOwners) Join(ctx context.Context) error {
	o.mu.Lock()
	if !o.sealed {
		o.sealed = true
		if o.active == 0 {
			close(o.returned)
		}
	}
	o.mu.Unlock()
	select {
	case <-o.returned:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func WithNativeOriginalWorkflowOwners(o *NativeOriginalWorkflowOwners) ServerOption {
	return func(s *Server) { s.originalGuestAsyncWorkflowOwner = o }
}
