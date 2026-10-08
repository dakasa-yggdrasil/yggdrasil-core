package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"time"
)

// A restarted fixed invocation may acquire only the same pending bound native
// generation after the old lease expires. Command uniqueness and unresolved
// command checks still forbid sending again or advancing past lost outcomes.
func (s CapacityStore) ResumeNativeExecution(ctx context.Context, policy model.Manifest, generation int64) (model.CapacityIntent, error) {
	return s.transaction(ctx, policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time) (model.CapacityIntent, string, error) {
		if !s.ExecutionEnabled || !p.ExecutionEnabled || p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || !validCapacityExecutor(s.ExecutorID) || old == nil || old.Generation != generation || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Phase == "proposed" || !pendingCapacityPhase(old.Phase) || old.FencingToken >= maxCapacityGeneration {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		if old.LeaseExpiresAt != nil && old.LeaseExpiresAt.After(now) {
			return model.CapacityIntent{}, "", ErrCapacityLease
		}
		next := *old
		next.FencingToken++
		next.RecoveryOnly = false
		next.LeaseOwner = uuid.NewString()
		next.LeaseExecutorID = s.ExecutorID
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		next.LeaseExpiresAt = &expires
		next.Phase = "native_pending"
		next.UpdatedAt = now
		return next, "", nil
	})
}
func (s CapacityStore) NativeLedger(ctx context.Context, policy model.Manifest, intent model.CapacityIntent) ([]model.CapacityNativeCommand, []model.CapacityNativePodCheckpoint, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.HPAExecutionBinding == nil || intent.PolicyID != policy.ID || intent.PolicyChecksum != policy.Checksum {
		return nil, nil, ErrCapacityConflict
	}
	if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
		return nativeLifetimeLedger(ctx, s.DB, policy, p, s.AdmissionOnly)
	}
	commands := []model.CapacityNativeCommand{}
	checkpoints := []model.CapacityNativePodCheckpoint{}
	rows, err := s.DB.QueryContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 ORDER BY updated_at,id`, intent.Namespace, p.Environment, p.Domain, p.Dimension, intent.Generation)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var raw []byte
		var c model.CapacityNativeCommand
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &c) != nil {
			rows.Close()
			return nil, nil, ErrCapacityConflict
		}
		commands = append(commands, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.DB.QueryContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 ORDER BY pod_uid`, intent.Namespace, p.Environment, p.Domain, p.Dimension, intent.Generation)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var c model.CapacityNativePodCheckpoint
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &c) != nil {
			return nil, nil, ErrCapacityConflict
		}
		checkpoints = append(checkpoints, c)
	}
	return commands, checkpoints, rows.Err()
}
func (s CapacityStore) ConfirmNativeCommand(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, commandID uuid.UUID, readback any) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, commandID).Scan(&raw); err != nil {
			return err
		}
		var command model.CapacityNativeCommand
		if json.Unmarshal(raw, &command) != nil || command.PolicyID != policy.ID || command.PolicyChecksum != policy.Checksum || (command.IntentGeneration != current.Generation && p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode) || command.Namespace != current.Namespace || command.Environment != p.Environment || command.Domain != p.Domain || command.Dimension != p.Dimension || command.Adapter != p.AssessmentBinding.Snapshot.Adapter || (command.State != "redeemed" && command.State != "uncertain") {
			return ErrCapacityConflict
		}
		if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(command.Adapter)); err != nil {
			return err
		}
		rawReadback, err := json.Marshal(readback)
		if err != nil || len(rawReadback) > 32768 {
			return ErrCapacityConflict
		}
		if command.Operation == capacity.EnsureBoundHPAEnvelope {
			var expected model.CapacityNativeHPARequest
			var observed model.CapacityHPAEnvelopeResponse
			if capacity.DecodeNativeCapacity(json.RawMessage(command.Request), &expected) != nil || capacity.DecodeNativeCapacity(readback, &observed) != nil {
				return ErrCapacityConflict
			}
			exact := current
			if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
				exact.NativeHPAGeneration, exact.Decision.Units = expected.Generation, expected.MinReplicas
			}
			if nativeEnvelopeMatches(p, exact, expected, observed, now) != nil {
				return ErrCapacityConflict
			}
		} else {
			var req model.AdapterEnsureCapacityPodDrainRequest
			var release model.AdapterDestroyCapacityPodDrainProtectionRequest
			subject := ""
			if command.Phase == "release" {
				if json.Unmarshal(command.Request, &release) != nil {
					return ErrCapacityConflict
				}
				subject = release.ExpectedPodUID
			} else {
				if json.Unmarshal(command.Request, &req) != nil {
					return ErrCapacityConflict
				}
				subject = req.ExpectedPodUID
			}
			checkpoint, err := nativeLifetimeCheckpoint(ctx, tx, p, current, subject)
			if err != nil {
				return err
			}
			var response model.AdapterCapacityPodTerminationResponse
			if command.Phase == "admit" {
				var admitted model.AdapterCapacityPodAdmissionResponse
				if capacity.DecodeNativeCapacity(readback, &admitted) != nil || capacity.NativeProcessAdmissionCheckpoint(p, checkpoint, admitted, now) != nil || admitted.Admission.State != "roots_open" || !admitted.Observation.AdmissionReady || len(checkpoint.ProjectionAcknowledgement) == 0 || len(checkpoint.RootAcknowledgement) == 0 {
					return ErrCapacityConflict
				}
				checkpoint.State, checkpoint.PodResourceVersion, checkpoint.RootAcknowledgement = "admitted", admitted.Observation.PodResourceVersion, rawReadback
				if err := updateNativeLifetimeCheckpoint(ctx, tx, p, current, checkpoint, now); err != nil {
					return err
				}
				command.State, command.NativeReadback, command.UpdatedAt = "confirmed", rawReadback, now
				raw, _ = json.Marshal(command)
				_, err := tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state='confirmed',command_record=$2,updated_at=$3 WHERE id=$1`, commandID, raw, now)
				return err
			}
			if capacity.DecodeNativeCapacity(readback, &response) != nil || response.Operation != capacity.ObserveNativePodTermination || response.Status != "observed" {
				return ErrCapacityConflict
			}
			observed := response.Observation
			if command.Phase == "release" {
				if checkpoint.State != "confirmed" || checkpoint.ConfirmedAt == nil || len(checkpoint.NativeTerminationReceipt) == 0 || capacity.NativePodReleaseTarget(p, checkpoint, observed, now) != nil {
					return ErrCapacityConflict
				}
				checkpoint.State = "released"
			} else {
				if capacity.NativePodMatchesCheckpoint(p, checkpoint, observed, now) != nil || !observed.Protected {
					return ErrCapacityConflict
				}
				switch command.Phase {
				case "protect":
					checkpoint.State = "protected"
				case "terminate":
					if observed.DeletionRequestedAt == nil {
						return ErrCapacityConflict
					}
					checkpoint.State = "terminating"
				default:
					return ErrCapacityConflict
				}
				checkpoint.PodResourceVersion = observed.PodResourceVersion
			}
			if err := updateNativeLifetimeCheckpoint(ctx, tx, p, current, checkpoint, now); err != nil {
				return err
			}
		}
		command.State, command.NativeReadback, command.UpdatedAt = "confirmed", rawReadback, now
		raw, _ = json.Marshal(command)
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state='confirmed',command_record=$2,updated_at=$3 WHERE id=$1`, commandID, raw, now)
		return err
	})
}
func nativeEnvelopeMatches(p model.CapacityPolicySpec, intent model.CapacityIntent, request model.CapacityNativeHPARequest, response model.CapacityHPAEnvelopeResponse, now time.Time) error {
	if response.Operation != capacity.ObserveHPAEnvelope || response.Status != "observed" {
		return ErrCapacityConflict
	}
	snapshot, err := capacity.BoundHPASnapshot(p, response, now)
	if err != nil {
		return err
	}
	o := response.Observation
	if snapshot.Units != intent.Decision.Units || o.EnvelopeGeneration != intent.NativeHPAGeneration || o.IdempotencyKey != request.IdempotencyKey || o.MinReplicas != request.MinReplicas || o.MaxReplicas != request.MaxReplicas || !o.BoundsMatchTracking || !o.TrackingMatchesScope {
		return ErrCapacityConflict
	}
	return nil
}
func (s CapacityStore) ConfirmNativePodWitness(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, uid string, response model.AdapterCapacityPodTerminationResponse) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		checkpoint, err := nativeLifetimeCheckpoint(ctx, tx, p, current, uid)
		if err != nil {
			return err
		}
		validState := checkpoint.State == "terminating" || checkpoint.State == "confirmed"
		if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
			validState = validState || checkpoint.State == "protected" || checkpoint.State == "admitted"
		}
		if !validState || response.Operation != capacity.ObserveNativePodTermination || response.Status != "observed" || capacity.NativePodWitness(p, checkpoint, response.Observation, now) != nil {
			return ErrCapacityConflict
		}
		if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(p.AssessmentBinding.Snapshot.Adapter)); err != nil {
			return err
		}
		checkpoint.State = "confirmed"
		checkpoint.ConfirmedAt = &now
		checkpoint.PodResourceVersion = response.Observation.PodResourceVersion
		checkpoint.NativeTerminationReceipt, _ = json.Marshal(response)
		return updateNativeLifetimeCheckpoint(ctx, tx, p, current, checkpoint, now)
	})
}
func (s CapacityStore) CompleteNativeExecution(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, inventory model.AdapterCapacityPodInventoryResponse) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if capacity.NativePodInventory(p, inventory, now) != nil {
			return ErrCapacityConflict
		}
		live := map[string]bool{}
		for _, pod := range inventory.Pods {
			live[pod.PodUID] = true
		}
		for _, uid := range current.NativePodBaseline {
			if !live[uid] {
				var witnessed int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND pod_uid=$6 AND checkpoint_record->>'state'='released' AND checkpoint_record->>'confirmed_at' IS NOT NULL`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, uid).Scan(&witnessed); err != nil || witnessed != 1 {
					return ErrCapacityConflict
				}
			}
		}
		var confirmed, unresolved, lifetimes int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state='confirmed'),count(*) FILTER(WHERE state NOT IN ('confirmed','refused_no_redemption')) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation).Scan(&confirmed, &unresolved); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation).Scan(&lifetimes); err != nil {
			return err
		}
		if confirmed != 1+3*lifetimes || unresolved != 0 {
			return ErrCapacityConflict
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND checkpoint_record->>'state'<>'released'`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved != 0 {
			return ErrCapacityConflict
		}
		current.Phase = "native_completed"
		current.LeaseOwner, current.LeaseExecutorID, current.LeaseExpiresAt = "", "", nil
		current.Decision.Clock.LastActionAt = now
		current.UpdatedAt = now
		raw, _ := json.Marshal(current)
		if _, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, current.Phase, "native:reserved-envelope-and-declared-local-lifetimes")
		return err
	})
}

func (s CapacityStore) SaveNativePodPlan(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, inventory model.AdapterCapacityPodInventoryResponse, hpa model.CapacityHPAEnvelopeResponse, checkpoints []model.CapacityNativePodCheckpoint) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if capacity.NativePodInventory(p, inventory, now) != nil || current.NativePodBaseline != nil {
			return ErrCapacityConflict
		}
		snapshot, err := capacity.BoundHPASnapshot(p, hpa, now)
		if err != nil || snapshot.Units != current.BaselineSnapshot.Units || hpa.Observation.EnvelopeGeneration >= maxCapacityGeneration {
			return ErrCapacityConflict
		}
		current.NativeHPAGeneration = hpa.Observation.EnvelopeGeneration + 1
		if current.NativeHPAGeneration < current.Generation {
			current.NativeHPAGeneration = current.Generation
		}
		expected := current.BaselineSnapshot.Units - current.Decision.Units
		if expected < 0 {
			expected = 0
		}
		if len(checkpoints) != expected {
			return ErrCapacityConflict
		}
		baseline := map[string]model.NativeTerminationObservation{}
		for _, pod := range inventory.Pods {
			baseline[pod.PodUID] = pod
			current.NativePodBaseline = append(current.NativePodBaseline, pod.PodUID)
		}
		if expected > 0 && expected > len(baseline)-p.AssessmentBinding.Snapshot.ProtectedFloor {
			return ErrCapacityConflict
		}
		seen := map[string]bool{}
		for _, checkpoint := range checkpoints {
			pod, ok := baseline[checkpoint.PodUID]
			var challenge model.NativePodTerminationChallenge
			if !ok || seen[checkpoint.PodUID] || checkpoint.State != "planned" || checkpoint.IntentGeneration != current.Generation || capacity.NativePodMatchesCheckpoint(p, checkpoint, pod, now) != nil || pod.State != "running" || pod.StartedAt == nil || !pod.StartedAt.Equal(checkpoint.ContainerStartedAt) || pod.DeletionRequestedAt != nil || json.Unmarshal(checkpoint.Challenge, &challenge) != nil || challenge.PodUID != pod.PodUID || challenge.PodName != pod.PodName || challenge.Namespace != pod.Namespace || challenge.WorkloadUID != pod.WorkloadUID || challenge.ContainerName != pod.ContainerName || challenge.ImageDigest != pod.ImageDigest || challenge.IntentGeneration != current.Generation || challenge.DrainNonce != checkpoint.DrainNonce || challenge.LaneRosterSHA256 != capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes) || challenge.IssuedAt.Before(*pod.StartedAt) || !capacity.Fresh(challenge.IssuedAt, now, p.MaxEvidenceAgeSeconds) {
				return ErrCapacityConflict
			}
			seen[checkpoint.PodUID] = true
			raw, _ := json.Marshal(checkpoint)
			if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_native_pod_checkpoints(namespace,environment,domain,dimension,generation,pod_uid,checkpoint_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, checkpoint.PodUID, raw, now); err != nil {
				return err
			}
		}
		if current.NativePodBaseline == nil {
			current.NativePodBaseline = []string{}
		}
		raw, _ := json.Marshal(current)
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now)
		return err
	})
}
func validateNativeCommandRequest(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, operation, phase, subject string, raw json.RawMessage) error {
	if operation == capacity.EnsureBoundHPAEnvelope {
		var req model.CapacityNativeHPARequest
		if capacity.DecodeNativeCapacity(raw, &req) != nil {
			return ErrCapacityMutationAuthorization
		}
		b := p.AssessmentBinding.Snapshot
		if subject != b.HPAUID || req.Namespace != b.Namespace || req.HPAName != b.HPAName || req.ExpectedUID != b.HPAUID || req.ExpectedWorkloadUID != b.WorkloadUID || req.Owner != b.Owner || req.Generation != current.NativeHPAGeneration || req.MinReplicas != current.Decision.Units || req.MaxReplicas < req.MinReplicas || req.MaxReplicas > b.MaximumReplicas || req.MinReplicas < b.ProtectedFloor || req.DryRun == nil || *req.DryRun || req.ExpectedResourceVersion == "" || req.ExpectedWorkloadResourceVersion == "" || req.IdempotencyKey == "" {
			return ErrCapacityMutationAuthorization
		}
		if p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode {
			if len(current.NativePodBaseline) < p.Floor {
				return ErrCapacityConflict
			}
			var unresolved int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND checkpoint_record->>'state' NOT IN ('admitted','released')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unresolved); err != nil || unresolved != 0 {
				return ErrCapacityConflict
			}
		}
		return nil
	}
	checkpoint, err := nativeLifetimeCheckpoint(ctx, tx, p, current, subject)
	if err != nil {
		return err
	}
	if checkpoint.PodUID != subject || (checkpoint.IntentGeneration != current.Generation && p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode) || checkpoint.Namespace != p.AssessmentBinding.Snapshot.Namespace || checkpoint.WorkloadUID != p.AssessmentBinding.Snapshot.WorkloadUID || checkpoint.ContainerName != p.HPAExecutionBinding.ContainerName || checkpoint.ImageDigest != p.HPAExecutionBinding.ImageDigest {
		return ErrCapacityConflict
	}
	var challenge model.NativePodTerminationChallenge
	if phase == "release" {
		var req model.AdapterDestroyCapacityPodDrainProtectionRequest
		if capacity.DecodeNativeCapacity(raw, &req) != nil || checkpoint.State != "confirmed" || req.PodName != checkpoint.PodName || req.ExpectedPodUID != subject || req.ExpectedPodGeneration != checkpoint.PodGeneration || req.ExpectedContainerID != checkpoint.ContainerID || !req.ExpectedContainerStartedAt.Equal(checkpoint.ContainerStartedAt) || req.ExpectedRestartCount != checkpoint.RestartCount || req.BindingName != p.HPAExecutionBinding.PodTerminationBinding || req.ExpectedPodResourceVersion != checkpoint.PodResourceVersion || req.DryRun == nil || *req.DryRun {
			return ErrCapacityConflict
		}
		challenge = req.Challenge
	} else {
		var req model.AdapterEnsureCapacityPodDrainRequest
		if capacity.DecodeNativeCapacity(raw, &req) != nil || req.Phase != phase || req.ExpectedPodUID != subject || req.PodName != checkpoint.PodName || req.ExpectedPodGeneration != checkpoint.PodGeneration || req.ExpectedContainerID != checkpoint.ContainerID || !req.ExpectedContainerStartedAt.Equal(checkpoint.ContainerStartedAt) || req.ExpectedRestartCount != checkpoint.RestartCount || req.BindingName != p.HPAExecutionBinding.PodTerminationBinding || req.ExpectedPodResourceVersion == "" || req.DryRun == nil || *req.DryRun || (phase == "protect" && checkpoint.State != "planned") || (phase == "terminate" && checkpoint.State != "protected") || (phase == "admit" && (checkpoint.State != "protected" || len(checkpoint.ProjectionAcknowledgement) == 0 || len(checkpoint.RootAcknowledgement) == 0)) || (p.HPAExecutionBinding.Mode == capacity.HPALifetimeExecutionMode && phase == "terminate") {
			return ErrCapacityConflict
		}
		challenge = req.Challenge
	}
	normalized, _ := json.Marshal(challenge)
	var retained model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &retained) != nil {
		return ErrCapacityConflict
	}
	expected, _ := json.Marshal(retained)
	if string(normalized) != string(expected) {
		return ErrCapacityConflict
	}
	return nil
}
