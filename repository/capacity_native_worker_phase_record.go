package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The base runtime remains ACK-only for provider callbacks. Only this protected
// executor store installs the phase-recording wrapper. Neither a public permit
// nor a workflow input can supply its reads, custody, readiness or Node claims.
type nativeWorkerRecordingRuntime struct{ *NativeWorkerConcreteRuntime }

func NativeWorkerRecordingStore(s CapacityNativeWorkerStore, r *NativeWorkerConcreteRuntime) (CapacityNativeWorkerStore, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || s.Runtime != r || s.Capacity.DB != r.db {
		return s, ErrCapacityDisabled
	}
	s.Runtime = &nativeWorkerRecordingRuntime{r}
	return s, nil
}

func (r *nativeWorkerRecordingRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	if r == nil || r.NativeWorkerConcreteRuntime == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return model.CapacityNativeWorkerObservation{}, ErrCapacityDisabled
	}
	if a.State == "send_started" || a.State == "unknown" {
		return r.NativeWorkerConcreteRuntime.Qualify(ctx, a, original)
	}
	var zero model.CapacityNativeWorkerObservation
	if r == nil || r.NativeWorkerConcreteRuntime == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrCapacityDisabled
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !r.attemptProfileBound(a) || (a.State != "acknowledged" && a.State != "registered") || r.phase == nil || r.physical == nil || r.spec.NativeWorkerLifecycleBinding.RegistryWriter == nil {
		return zero, ErrCapacityConflict
	}
	launch, err := r.launchAndOriginal(ctx, a, original)
	if err != nil {
		return zero, err
	}
	physical, err := r.physical.ReadLifecycleACK(ctx, a, launch, original)
	if err != nil {
		return zero, err
	}
	// Immutable observed records survive restarts. Select all live action slots,
	// including issued/unknown, so neither omission nor a new UUID can disguise
	// a consumed phase. No network or transaction is held while collecting.
	rows, err := r.db.QueryContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 AND policy_id=$2 AND namespace=$3 AND state<>'no_effect' ORDER BY id LIMIT 4`, a.ID, a.PolicyID, a.Namespace)
	if err != nil {
		return zero, err
	}
	records := map[string]capacity.NativeWorkerPhaseRecordEvidence{}
	for rows.Next() {
		var raw []byte
		var record nativeWorkerPhaseRecord
		if err = rows.Scan(&raw); err != nil {
			break
		}
		if json.Unmarshal(raw, &record) != nil || !nativePhaseWriterScopeMatches(record) || record.Context.AttemptID != a.ID || record.PolicyChecksum != a.PolicyChecksum || record.Original == nil || record.Context.PhaseState != "observed" || record.Writer != *r.spec.NativeWorkerLifecycleBinding.RegistryWriter {
			err = ErrCapacityConflict
			break
		}
		if _, exists := records[record.Context.Action]; exists {
			err = ErrCapacityConflict
			break
		}
		originalCopy := *record.Original
		originalCopy.OriginalReturn = append([]byte(nil), originalCopy.OriginalReturn...)
		records[record.Context.Action] = capacity.NativeWorkerPhaseRecordEvidence{Context: record.Context, Original: originalCopy, Redeemed: nativePhaseSHA.MatchString(record.SettlementTokenSHA256)}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return zero, err
	}
	if closeErr != nil {
		return zero, closeErr
	}
	register, ok := records["register"]
	if !ok || len(records) > 3 {
		return zero, ErrCapacityConflict
	}
	current, proof, err := r.phase.ReadLifecyclePhase(ctx, a)
	if err != nil || ctx.Err() != nil {
		return zero, ErrCapacityConflict
	}
	var admit, release *capacity.NativeWorkerPhaseRecordEvidence
	if v, exists := records["admit_registry"]; exists {
		copied := v
		admit = &copied
	}
	if v, exists := records["release_quarantine"]; exists {
		copied := v
		release = &copied
	}
	return capacity.ProjectNativeWorkerPhaseRecord(r.spec, a, physical, register, admit, release, current, proof, time.Now().UTC())
}
