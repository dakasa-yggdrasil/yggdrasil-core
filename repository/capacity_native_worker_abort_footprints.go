package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Keep the pre-send footprint in the SAME append-only transaction that exposes
// the one-use deletion right. Begin can legitimately have seen provider unknown.
// A later safe Redeem must retain its actual first snapshot before returning.
func nativeAbortRetainResourceFootprint(r *nativeWorkerAbortRecord, o model.CapacityNativeWorkerAbortObservation) error {
	if o.ResourceFootprint == nil {
		return nil // Original Source-only/legacy ports retain their existing wire.
	}
	if o.ProviderOutcome != "present" || r == nil ||
		r.Observation != nil && r.Observation.ResourceFootprint != nil && !capacity.NativeWorkerResourceFootprintStableEqual(r.Observation.ResourceFootprint, o.ResourceFootprint) {
		return ErrCapacityConflict
	}
	// Own every nested slice/pointer after the callback returns. No later Go
	// producer mutation may alter the resource set saved by the transaction.
	raw, e := json.Marshal(o)
	var owned model.CapacityNativeWorkerAbortObservation
	if e != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &owned) != nil {
		return ErrCapacityConflict
	}
	r.Observation = &owned
	return nil
}

// Only committed historical PRESENT snapshots can select closure GETs. Never
// recover authority from the mutable latest Observation, a response supplied by
// the workflow, or a footprint first recorded after a provider delete return.
// The first snapshot may be revision2 when Begin observed unknown.
func nativeAbortCommittedResourceFootprint(ctx context.Context, db *sql.DB, policy model.Manifest, a model.CapacityNativeWorkerAttempt, source string) (*model.CapacityNativeWorkerResourceFootprint, error) {
	if db == nil {
		return nil, ErrCapacityMutationAuthorization
	}
	return nativeAbortCommittedResourceFootprintFrom(ctx, db, policy, a, source)
}

type nativeAbortHistoryReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func nativeAbortCommittedResourceFootprintFrom(ctx context.Context, reader nativeAbortHistoryReader, policy model.Manifest, a model.CapacityNativeWorkerAttempt, source string) (*model.CapacityNativeWorkerResourceFootprint, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || policy.ID != a.PolicyID || policy.Checksum != a.PolicyChecksum || policy.Metadata.Namespace != a.Namespace || a.SourceCommit != source {
		return nil, ErrCapacityMutationAuthorization
	}
	var raw []byte
	var recordedAt time.Time
	e := reader.QueryRowContext(ctx, `SELECT e.record,e.recorded_at
FROM public.capacity_native_worker_abort_events e
JOIN public.capacity_native_worker_abort_permits p ON p.id=e.permit_id
WHERE p.attempt_id=$1 AND p.policy_id=$2 AND p.namespace=$3
  AND jsonb_typeof(e.record#>'{observation,resource_footprint}')='object'
  AND e.record#>>'{observation,ProviderOutcome}'='present'
  AND e.record#>>'{context,state}' IN ('issued','redeemed')
  AND NOT (e.record ? 'original')
ORDER BY e.recorded_at,e.permit_id,e.revision LIMIT 1`, a.ID, policy.ID, a.Namespace).Scan(&raw, &recordedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil // Snapshot mode only; it cannot infer provider absence.
	}
	var old nativeWorkerAbortRecord
	if e != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &old) != nil || old.Observation == nil || old.Observation.ResourceFootprint == nil || old.SourceCommit != source ||
		old.Attempt.ID != a.ID || old.Attempt.PolicyID != policy.ID || old.Attempt.PolicyChecksum != policy.Checksum || old.Attempt.Namespace != a.Namespace ||
		old.Attempt.BirthSHA256 != a.BirthSHA256 || old.Attempt.LaunchSHA256 != a.LaunchSHA256 || old.Attempt.Physical == nil || a.Physical == nil || *old.Attempt.Physical != *a.Physical ||
		old.Context.AttemptID != a.ID || old.Context.Physical != *a.Physical || old.Observation.ResourceFootprint.ObservedAt.After(recordedAt) || ctx.Err() != nil {
		return nil, ErrCapacityConflict
	}
	return old.Observation.ResourceFootprint, nil
}
