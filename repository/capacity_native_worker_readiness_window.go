package repository

import "time"

const (
	nativeReadinessMaximumRun = 300 * time.Second
	nativeReadinessMinimumRun = 180 * time.Second
)

// The diagnostic cap never extends its original command, parent or physical
// authority. The first-run minimum leaves room for one normal Secret remount,
// two finite packet batches and setup/startup/read headroom. It is not an IO SLA:
// original expiry/cancellation still holds, including after a slow VM boot.
func nativeReadinessRunEnd(now, command, parent, physical time.Time) time.Time {
	end := now.Add(nativeReadinessMaximumRun)
	for _, bound := range []time.Time{command, parent, physical} {
		if bound.Before(end) {
			end = bound
		}
	}
	return end
}

func nativeReadinessNewRunHasBudget(now, end time.Time) bool {
	return !now.IsZero() && end.Sub(now) >= nativeReadinessMinimumRun
}
