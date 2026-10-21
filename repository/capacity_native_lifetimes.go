package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const maxNativeActiveLifetimes = 64
const maxNativeRetainedLifetimes = 512
const maxNativeRetainedCommands = 8192

// Hold and an applied reservation still require real lifetime reconciliation.
// The lease guards this invocation, not the immutable lifetime origin epoch.
func (s CapacityStore) AcquireNativeLifetimeExecution(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, assessment model.CapacityAssessment) (model.CapacityIntent, error) {
	if intent.Phase == "proposed" {
		return s.Claim(ctx, policy, intent.Generation, assessment)
	}
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !s.ExecutionEnabled || !p.ExecutionEnabled || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || !validCapacityExecutor(s.ExecutorID) || old == nil || old.Generation != intent.Generation || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.FencingToken >= maxCapacityGeneration || capacity.ValidateSnapshot(p, assessment, now) != nil || !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
			return model.CapacityIntent{}, "", ErrCapacityLease
		}
		next := *old
		if next.Generation == 0 {
			next.Generation = 1
		}
		next.FencingToken++
		next.RecoveryOnly = false
		next.LeaseOwner, next.LeaseExecutorID = uuid.NewString(), s.ExecutorID
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt, next.UpdatedAt = &expires, now
		if next.BaselineSnapshot.ResourceUID == "" {
			next.BaselineSnapshot = assessment.Snapshot
		}
		next.Phase = "native_pending"
		return next, "", nil
	})
}

func nativeLifetimeCheckpoint(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, uid string) (model.CapacityNativePodCheckpoint, error) {
	var raw []byte
	var checkpoint model.CapacityNativePodCheckpoint
	var err error
	if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
		err = tx.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5 FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension, uid).Scan(&raw)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND pod_uid=$6 FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, uid).Scan(&raw)
	}
	if err != nil {
		return checkpoint, err
	}
	if json.Unmarshal(raw, &checkpoint) != nil {
		return checkpoint, ErrCapacityConflict
	}
	if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode && (checkpoint.PolicyID != current.PolicyID || checkpoint.PolicyChecksum != current.PolicyChecksum || checkpoint.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(p) || checkpoint.IntentGeneration < 1 || !capacity.NativeProcessNonce(checkpoint.ProcessNonce)) {
		return checkpoint, ErrCapacityConflict
	}
	return checkpoint, nil
}

func updateNativeLifetimeCheckpoint(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, checkpoint model.CapacityNativePodCheckpoint, now time.Time) error {
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_lifetimes SET checkpoint_record=$6,updated_at=$7 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5`, current.Namespace, p.Environment, p.Domain, p.Dimension, checkpoint.PodUID, raw, now)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_pod_checkpoints SET checkpoint_record=$7,updated_at=$8 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND pod_uid=$6`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, checkpoint.PodUID, raw, now)
	}
	return err
}

// The fixed private invocation supplies freshly read native SDK/API facts. No
// public caller route accepts an origin, startup receipt, Pod or readiness flag.
func (s CapacityStore) RegisterNativeLifetime(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, response model.AdapterCapacityPodAdmissionResponse) (model.CapacityNativePodCheckpoint, error) {
	var checkpoint model.CapacityNativePodCheckpoint
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || capacity.NativeProcessAdmission(p, response, now) != nil || response.Admission.State != "waiting_projection" || response.Admission.Challenge != nil || current.Generation < 1 {
			return ErrCapacityConflict
		}
		var pending, retained, active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','uncertain')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE checkpoint_record->>'state'<>'released') FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&retained, &active); err != nil {
			return err
		}
		if pending != 0 || retained >= maxNativeRetainedLifetimes || active >= maxNativeActiveLifetimes {
			return ErrCapacityConflict
		}
		var archived int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5`, current.Namespace, p.Environment, p.Domain, p.Dimension, response.Observation.PodUID).Scan(&archived); err != nil || archived != 0 {
			return ErrCapacityConflict
		}
		if err := lockNativeBoundOwner(ctx, tx, policy, p, response.Observation.PodUID); err != nil {
			return err
		}
		pod := response.Observation
		challenge, err := capacity.NativeProcessChallenge(p, current, pod, response.Admission, now)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(challenge)
		if err != nil {
			return err
		}
		checkpoint = model.CapacityNativePodCheckpoint{Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, PodResourceVersion: pod.PodResourceVersion, PodGeneration: pod.PodGeneration, WorkloadUID: pod.WorkloadUID, ContainerName: pod.ContainerName, ContainerID: pod.ContainerID, ContainerStartedAt: *pod.StartedAt, ImageDigest: pod.ImageDigest, RestartCount: pod.RestartCount, IntentGeneration: current.Generation, DrainNonce: challenge.DrainNonce, Challenge: raw, State: "planned", PolicyID: current.PolicyID, PolicyChecksum: current.PolicyChecksum, BindingSHA256: capacity.NativeLifetimeBindingSHA256(p), ProcessNonce: response.Admission.ProcessNonce}
		checkpoint.OriginPolicy = append(json.RawMessage(nil), policy.Spec...)
		checkpoint.OriginPolicySHA256 = nativeCanonicalArchiveSHA(checkpoint.OriginPolicy)
		checkpoint.OriginChallengeBytes = append([]byte(nil), raw...)
		checkpoint.OriginChallengeSHA256 = nativeArchiveSHA(raw)
		raw, err = json.Marshal(checkpoint)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_lifetimes(namespace,environment,domain,dimension,pod_uid,origin_generation,checkpoint_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, checkpoint.PodUID, checkpoint.IntentGeneration, raw, now)
		return err
	})
	return checkpoint, err
}

func (s CapacityStore) AcknowledgeNativeProjection(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, uid string, response model.AdapterCapacityPodAdmissionResponse) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		checkpoint, err := nativeLifetimeCheckpoint(ctx, tx, p, current, uid)
		if err != nil || (checkpoint.State != "protected" && checkpoint.State != "admitted") || capacity.NativeProcessAdmissionCheckpoint(p, checkpoint, response, now) != nil || (response.Admission.State != "projection_observed" && response.Admission.State != "roots_open") {
			return ErrCapacityConflict
		}
		raw, err := json.Marshal(response)
		if err != nil || len(raw) > 32768 {
			return ErrCapacityConflict
		}
		checkpoint.ProjectionAcknowledgement = raw
		if response.Admission.State == "roots_open" {
			checkpoint.RootAcknowledgement = raw
		}
		checkpoint.PodResourceVersion = response.Observation.PodResourceVersion
		return updateNativeLifetimeCheckpoint(ctx, tx, p, current, checkpoint, now)
	})
}

// This phase closes a reservation decision only. Alive protected lifetimes
// retain their immutable origins; none is called joined, drained or released.
func (s CapacityStore) CompleteNativeReservationDecision(ctx context.Context, policy model.Manifest, intent model.CapacityIntent) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode {
			return ErrCapacityConflict
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','uncertain')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return ErrCapacityConflict
		}
		phase := "hold"
		if current.Decision.Action != "hold" {
			var confirmed int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND operation=$6 AND state='confirmed'`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, capacity.EnsureBoundHPAEnvelope).Scan(&confirmed); err != nil || confirmed != 1 {
				return ErrCapacityConflict
			}
			phase = "envelope_applied"
			current.Decision.Clock.LastActionAt = now
		}
		current.Phase = phase
		current.LeaseOwner, current.LeaseExecutorID, current.LeaseExpiresAt = "", "", nil
		current.UpdatedAt = now
		raw, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, phase, "native:reservation-only-lifetime-ledger-retained")
		return err
	})
}

func nativeLifetimeLedger(ctx context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, admissionOnly bool) ([]model.CapacityNativeCommand, []model.CapacityNativePodCheckpoint, error) {
	commands := []model.CapacityNativeCommand{}
	checkpoints := []model.CapacityNativePodCheckpoint{}
	rows, err := db.QueryContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY updated_at,id LIMIT 8193`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var raw []byte
		var record model.CapacityNativeCommand
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &record) != nil {
			rows.Close()
			return nil, nil, ErrCapacityConflict
		}
		commands = append(commands, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(commands) > maxNativeRetainedCommands {
		return nil, nil, fmt.Errorf("native command history exceeds retained bound or is unavailable")
	}
	rows, err = db.QueryContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY pod_uid LIMIT 513`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	active := 0
	for rows.Next() {
		var raw []byte
		var record model.CapacityNativePodCheckpoint
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &record) != nil {
			return nil, nil, ErrCapacityConflict
		}
		if record.PolicyID != policy.ID || record.PolicyChecksum != policy.Checksum || record.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(p) {
			if admissionOnly {
				continue
			}
			return nil, nil, ErrCapacityConflict
		}
		if record.State != "released" {
			active++
		}
		checkpoints = append(checkpoints, record)
	}
	if len(checkpoints) > maxNativeRetainedLifetimes || active > maxNativeActiveLifetimes {
		return nil, nil, ErrCapacityConflict
	}
	return commands, checkpoints, rows.Err()
}

// Every actual baseline lifetime is admitted before the reservation CAS. The
// native controller chooses retirement victims; no selected Pod DELETE exists.
func (s CapacityStore) PlanNativeReservationEnvelope(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, hpa model.CapacityHPAEnvelopeResponse, inventory model.AdapterCapacityPodInventoryResponse, acknowledgements map[string]model.AdapterCapacityPodAdmissionResponse) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || current.Decision.Action == "hold" || capacity.NativePodInventory(p, inventory, now) != nil || len(inventory.Pods) < p.Floor || len(acknowledgements) != len(inventory.Pods) || hpa.Observation.EnvelopeGeneration >= maxCapacityGeneration {
			return ErrCapacityConflict
		}
		snapshot, err := capacity.BoundHPASnapshot(p, hpa, now)
		if err != nil || snapshot.Units != current.BaselineSnapshot.Units {
			return ErrCapacityConflict
		}
		seen := map[string]bool{}
		baseline := []string{}
		for _, pod := range inventory.Pods {
			checkpoint, err := nativeLifetimeCheckpoint(ctx, tx, p, current, pod.PodUID)
			actual, ok := acknowledgements[pod.PodUID]
			if err != nil || !ok || checkpoint.State != "admitted" || seen[pod.PodUID] || capacity.NativeProcessAdmissionCheckpoint(p, checkpoint, actual, now) != nil || actual.Admission.State != "roots_open" || !actual.Observation.AdmissionReady || actual.Observation.PodResourceVersion != pod.PodResourceVersion {
				return ErrCapacityConflict
			}
			seen[pod.PodUID] = true
			baseline = append(baseline, pod.PodUID)
		}
		var unresolved int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND checkpoint_record->>'state' NOT IN ('admitted','released')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unresolved); err != nil || unresolved != 0 {
			return ErrCapacityConflict
		}
		current.NativePodBaseline = baseline
		current.NativeHPAGeneration = hpa.Observation.EnvelopeGeneration + 1
		if current.NativeHPAGeneration < current.Generation {
			current.NativeHPAGeneration = current.Generation
		}
		raw, err := json.Marshal(current)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now)
		return err
	})
}

func nativeCapacityWorkflow(p model.CapacityPolicySpec, admissionOnly bool) model.ManifestSelector {
	if admissionOnly && p.HPAExecutionBinding != nil {
		return p.HPAExecutionBinding.AdmissionWorkflow
	}
	return p.Workflow
}

// Bootstrap has no pressure samples or HPA send permission. The source-fixed
// admission workflow may adopt current candidates while old baseline stays
// explicitly unqualified/frozen under the separate execution gate.
func (s CapacityStore) AcquireNativeAdmissionExecution(ctx context.Context, policy model.Manifest, hpa model.CapacityHPAEnvelopeResponse) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !s.AdmissionOnly || !s.ExecutionEnabled || !p.ExecutionEnabled || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || !validCapacityExecutor(s.ExecutorID) {
			return model.CapacityIntent{}, "", ErrCapacityDisabled
		}
		snapshot, err := capacity.BoundHPASnapshot(p, hpa, now)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		generation, fence := int64(1), int64(0)
		if old != nil {
			if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
				return model.CapacityIntent{}, "", ErrCapacityLease
			}
			if old.Phase != "hold" && old.Phase != "envelope_applied" && old.Phase != "native_completed" && old.Phase != "admission_pending" {
				return model.CapacityIntent{}, "", ErrCapacityConflict
			}
			generation, fence = old.Generation, old.FencingToken
			if generation < 1 {
				generation = 1
			}
			if old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum {
				generation++
			}
		}
		if generation >= maxCapacityGeneration || fence >= maxCapacityGeneration {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: generation, FencingToken: fence + 1, Phase: "admission_pending", LeaseOwner: uuid.NewString(), LeaseExecutorID: s.ExecutorID, LeaseExpiresAt: &expires, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, Decision: model.CapacityDecision{Action: "hold", Reason: "native_candidate_admission_only", Units: snapshot.Units, Floor: p.Floor, Profile: snapshot.Profile}, UpdatedAt: now}
		if old != nil {
			next.Decision.Clock = old.Decision.Clock
		}
		return next, "native:candidate-bootstrap-without-pressure-permission", nil
	})
}
