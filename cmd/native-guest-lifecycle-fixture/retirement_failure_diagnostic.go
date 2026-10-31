//go:build linux && nativequalification

package main

import (
	"context"
	"time"
)

// The disposable qualification database must contain exactly one original
// caller return. Export only the existing allowlisted projection, never a raw
// response or error. Failure to collect does not alter the workflow result.
func (f *fixture) retainFailedRetirementCallerDiagnostic(parent context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	var requestID string
	var count int
	if err := f.db.QueryRowContext(ctx, `SELECT COALESCE(min(intent_id::text), ''), count(*) FROM public.capacity_guest_original_caller_returns`).Scan(&requestID, &count); err != nil || count != 1 {
		return
	}
	_ = f.exportOriginalRetirementCallerProjection(ctx, requestID)
}
