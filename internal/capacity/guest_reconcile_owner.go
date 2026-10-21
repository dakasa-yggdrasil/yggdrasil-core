package capacity

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// One in-process invocation owner. No wire field, absolute PG wall time,
// caller lease, expiry renewal or alternate operation can install a deadline.
// The source executor captures the conservative local monotonic result of its
// original PG lease transaction exactly once, before any provider write.
type OriginalGuestReconcileOwner struct {
	mu       sync.Mutex
	captured bool
	deadline time.Time
}

func (o *OriginalGuestReconcileOwner) Capture(ctx context.Context, deadline time.Time) error {
	refuse := fmt.Errorf("live original Guest reconciliation owner required")
	if o == nil || ctx == nil || ctx.Err() != nil || deadline.IsZero() {
		return refuse
	}
	parent, ok := ctx.Deadline()
	if !ok || !time.Now().Before(parent) || !time.Now().Before(deadline) {
		return refuse
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.captured || ctx.Err() != nil || !time.Now().Before(parent) || !time.Now().Before(deadline) {
		return refuse
	}
	o.captured, o.deadline = true, deadline
	return nil
}

func (o *OriginalGuestReconcileOwner) Context(ctx context.Context) (context.Context, context.CancelFunc) {
	if o == nil {
		return ctx, func() {}
	}
	o.mu.Lock()
	captured, deadline := o.captured, o.deadline
	o.mu.Unlock()
	if !captured {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}
