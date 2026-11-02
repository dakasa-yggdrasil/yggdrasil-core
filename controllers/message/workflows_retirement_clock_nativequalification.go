//go:build linux && nativequalification

package message

import (
	"context"
	"time"
)

// The V1 source-only QEMU actor and Core have independently synchronized
// clocks. Give a freshly issued request time to cross their measured
// millisecond-scale offset without changing its timestamp or original deadline.
func guestQualificationBeforeRetirementPOST(ctx context.Context) error {
	if originalGuestNativeRealm == nil {
		return nil
	}
	return waitQualificationRetirementClock(ctx)
}

func waitQualificationRetirementClock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
