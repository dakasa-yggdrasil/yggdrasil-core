package httpapi

import (
	"context"
	"errors"
	"sync"
)

// OriginalWorkflowOwners joins the actual returns of work admitted by this
// process. Sealing admission neither cancels an original operation nor makes a
// timeout, a durable row or a replacement process its return.
type OriginalWorkflowOwners struct {
	ctx      context.Context
	mu       sync.Mutex
	active   int
	sealed   bool
	returned chan struct{}
}

func NewOriginalWorkflowOwners(ctx context.Context) (*OriginalWorkflowOwners, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("original workflow owner unavailable")
	}
	return &OriginalWorkflowOwners{ctx: ctx, returned: make(chan struct{})}, nil
}

func (o *OriginalWorkflowOwners) AdmissionOpen() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.sealed && o.ctx.Err() == nil
}

func (o *OriginalWorkflowOwners) Begin() (context.Context, func(), error) {
	if o == nil {
		return nil, nil, errors.New("original workflow owner unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed || o.ctx.Err() != nil {
		return nil, nil, errors.New("original workflow owner closed")
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

// Seal is the admission phase of drain. Original descendants, including the
// process-local authenticated callback listener, must remain available to the
// admitted work until Join returns. It grants no finalizer release or receipt.
func (o *OriginalWorkflowOwners) Seal() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.sealed {
		o.sealed = true
		if o.active == 0 {
			close(o.returned)
		}
	}
}

func (o *OriginalWorkflowOwners) Join(ctx context.Context) error {
	if o == nil {
		return errors.New("original workflow owner unavailable")
	}
	o.Seal()
	select {
	case <-o.returned:
		return nil
	default:
	}
	select {
	case <-o.returned:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Returned is observation only: only the original finish closures close it.
func (o *OriginalWorkflowOwners) Returned() <-chan struct{} { return o.returned }

func WithOriginalWorkflowOwners(o *OriginalWorkflowOwners) ServerOption {
	return func(s *Server) { s.originalGuestAsyncWorkflowOwner = o }
}

func (s *Server) originalWorkflowAdmissionOpen() bool {
	owner, tracked := s.originalGuestAsyncWorkflowOwner.(interface{ AdmissionOpen() bool })
	return !tracked || owner.AdmissionOpen()
}
