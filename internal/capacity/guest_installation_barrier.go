package capacity

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// AwaitGuestOriginalInstallation performs only authenticated state reads. The
// original context is never replaced and the caller cannot reserve a probe
// until this function returns a confirmed receipt. Tick delivery is a bounded
// wake-up for pending database state, not a retry of registration or a probe.
func AwaitGuestOriginalInstallation(ctx context.Context, ticks <-chan time.Time, read func(context.Context) (model.CapacityGuestOriginalProvisioningReceipt, bool, error)) (model.CapacityGuestOriginalProvisioningReceipt, error) {
	var zero model.CapacityGuestOriginalProvisioningReceipt
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		receipt, ready, err := read(ctx)
		if err != nil {
			return zero, err
		}
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		if ready {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case _, ok := <-ticks:
			if !ok {
				return zero, context.Canceled
			}
		}
	}
}
