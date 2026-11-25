package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Fixed phase labels identify a refused original without projecting record data.
// The protected workflow's public error stays detail-free.
func migratedOriginRefusal(stage string) error {
	return fmt.Errorf("%w: migrated-origin %s", ErrCapacityConflict, stage)
}

func migratedOriginAdmissionTime(r model.AdapterCapacityPodAdmissionResponse) time.Time {
	at := r.Admission.ObservedAt
	if r.Observation.ObservedAt.After(at) {
		at = r.Observation.ObservedAt
	}
	return at
}

func migratedOriginPolicy(ctx context.Context, tx *sql.Tx, current model.Manifest, p model.CapacityPolicySpec, b model.CapacityMigratedNativeOriginBinding) (model.Manifest, model.CapacityPolicySpec, error) {
	id, err := uuid.Parse(b.OriginPolicyID)
	if err != nil {
		return model.Manifest{}, model.CapacityPolicySpec{}, ErrCapacityConflict
	}
	origin, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, id))
	if err != nil || origin.Checksum != b.OriginPolicyChecksum {
		return origin, model.CapacityPolicySpec{}, ErrCapacityConflict
	}
	op, err := parseCapacityPolicy(origin)
	if err != nil || !nativeAbortQuarantineSameLogicalScope(current, p, origin, op) || op.AssessmentBinding.Snapshot.WorkloadUID != b.WorkloadUID || op.HPAExecutionBinding.ContainerName != b.ContainerName || op.HPAExecutionBinding.ImageDigest != b.ImageDigest {
		return origin, op, ErrCapacityConflict
	}
	return origin, op, nil
}

// The declared Source absence is human administrative evidence. Historical
// ACKs are validated at their original timestamps, never refreshed to today.
func migratedOriginBodies(ctx context.Context, tx *sql.Tx, origin model.Manifest, op model.CapacityPolicySpec, b model.CapacityMigratedNativeOriginBinding) (json.RawMessage, []json.RawMessage, error) {
	var raw []byte
	var cp model.CapacityNativePodCheckpoint
	if tx.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5 FOR UPDATE`, origin.Metadata.Namespace, op.Environment, op.Domain, op.Dimension, b.PodUID).Scan(&raw) != nil || nativeCanonicalArchiveSHA(raw) != b.CheckpointSHA256 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &cp) != nil {
		return nil, nil, migratedOriginRefusal("checkpoint-record")
	}
	if cp.PolicyID != origin.ID || cp.PolicyChecksum != origin.Checksum || cp.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(op) || cp.PodUID != b.PodUID || cp.PodName != b.PodName || cp.WorkloadUID != b.WorkloadUID || cp.Namespace != op.AssessmentBinding.Snapshot.Namespace || cp.ContainerName != b.ContainerName || cp.ImageDigest != b.ImageDigest || cp.IntentGeneration != b.OriginGeneration || cp.State != "admitted" || cp.ConfirmedAt != nil || !nativeAbortRecoveryAbsent(cp.NativeTerminationReceipt) || nativeCanonicalArchiveSHA(cp.OriginPolicy) != cp.OriginPolicySHA256 || nativeCanonicalArchiveSHA(origin.Spec) != cp.OriginPolicySHA256 {
		return nil, nil, migratedOriginRefusal("checkpoint-origin")
	}
	for _, ack := range []json.RawMessage{cp.ProjectionAcknowledgement, cp.RootAcknowledgement} {
		var actual model.AdapterCapacityPodAdmissionResponse
		if capacity.DecodeNativeCapacity(ack, &actual) != nil || capacity.NativeProcessAdmissionCheckpoint(op, cp, actual, migratedOriginAdmissionTime(actual)) != nil {
			return nil, nil, migratedOriginRefusal("historical-admission-ack")
		}
	}
	var root model.AdapterCapacityPodAdmissionResponse
	if capacity.DecodeNativeCapacity(cp.RootAcknowledgement, &root) != nil || root.Admission.State != "roots_open" || !root.Observation.AdmissionReady {
		return nil, nil, migratedOriginRefusal("roots-open")
	}
	var lifetimes, legacy, archives, hot, identities, commandArchives int
	if tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1),
 (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),
 (SELECT count(*) FROM public.capacity_native_command_archive a JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1)`, b.PodUID).Scan(&lifetimes, &legacy, &archives, &hot, &identities, &commandArchives) != nil || lifetimes != 1 || legacy != 0 || archives != 0 || hot != 2 || identities != 2 || commandArchives != 0 {
		return nil, nil, migratedOriginRefusal("subject-history")
	}
	commands := []json.RawMessage{}
	for i, id := range []string{b.ProtectCommandID, b.AdmitCommandID} {
		var body []byte
		var c model.CapacityNativeCommand
		if tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 AND subject_uid=$2 FOR UPDATE`, id, b.PodUID).Scan(&body) != nil || capacity.DecodeNativeCapacity(json.RawMessage(body), &c) != nil {
			return nil, nil, migratedOriginRefusal("command-record")
		}
		wantSHA, phase := b.ProtectCommandSHA256, "protect"
		if i == 1 {
			wantSHA, phase = b.AdmitCommandSHA256, "admit"
		}
		canonical, _, canonicalErr := canonicalNativeCommandRequest(c.Operation, c.Request)
		if canonicalErr != nil {
			return nil, nil, migratedOriginRefusal("command-canonical")
		}
		var req model.AdapterEnsureCapacityPodDrainRequest
		var challenge model.NativePodTerminationChallenge
		if nativeCanonicalArchiveSHA(body) != wantSHA || c.CommandID.String() != id || c.State != "confirmed" || c.Operation != capacity.EnsureNativePodDrain || c.Phase != phase || c.IntentGeneration != cp.IntentGeneration || c.PolicyID != origin.ID || c.PolicyChecksum != origin.Checksum || c.Namespace != origin.Metadata.Namespace || c.Environment != op.Environment || c.Domain != op.Domain || c.Dimension != op.Dimension || c.Adapter != op.AssessmentBinding.Snapshot.Adapter || c.AdapterPrincipalID != op.HPAExecutionBinding.AdapterPrincipalID || c.AttemptID == uuid.Nil || c.RedeemedBy != c.AdapterPrincipalID || nativeArchiveSHA(canonical) != c.RequestSHA256 || capacity.DecodeNativeCapacity(c.Request, &req) != nil || capacity.DecodeNativeCapacity(cp.Challenge, &challenge) != nil || !reflect.DeepEqual(req.Challenge, challenge) || req.Phase != phase || req.BindingName != op.HPAExecutionBinding.PodTerminationBinding || req.ExpectedPodUID != cp.PodUID || req.PodName != cp.PodName || req.ExpectedPodGeneration != cp.PodGeneration || req.ExpectedContainerID != cp.ContainerID || !req.ExpectedContainerStartedAt.Equal(cp.ContainerStartedAt) || req.ExpectedRestartCount != cp.RestartCount || req.ExpectedPodResourceVersion == "" || req.DryRun == nil || *req.DryRun {
			return nil, nil, migratedOriginRefusal("command-binding")
		}
		var identityCount int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_command_identities WHERE id=$1 AND subject_uid=$2 AND namespace=$3 AND environment=$4 AND domain=$5 AND dimension=$6 AND generation=$7 AND operation=$8 AND phase=$9 AND sequence=$10 AND authority_token_sha256=$11 AND request_sha256=$12`, c.CommandID, b.PodUID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, c.Phase, c.Sequence, c.AuthorityTokenSHA256, c.RequestSHA256).Scan(&identityCount) != nil || identityCount != 1 {
			return nil, nil, migratedOriginRefusal("command-identity")
		}
		if i == 1 {
			// The checkpoint may contain a later same-process roots-open ACK.
			// Preserve and validate the original command ACK independently.
			var admitted model.AdapterCapacityPodAdmissionResponse
			if capacity.DecodeNativeCapacity(c.NativeReadback, &admitted) != nil || admitted.Admission.State != "roots_open" || !admitted.Observation.AdmissionReady || capacity.NativeProcessAdmissionCheckpoint(op, cp, admitted, migratedOriginAdmissionTime(admitted)) != nil {
				return nil, nil, migratedOriginRefusal("admit-ack")
			}
		}
		if i == 0 {
			var observed model.AdapterCapacityPodTerminationResponse
			if capacity.DecodeNativeCapacity(c.NativeReadback, &observed) != nil || observed.Operation != capacity.ObserveNativePodTermination || observed.Status != "observed" || capacity.NativePodMatchesCheckpoint(op, cp, observed.Observation, c.UpdatedAt) != nil {
				return nil, nil, migratedOriginRefusal("protect-ack")
			}
		}
		commands = append(commands, append(json.RawMessage(nil), body...))
	}
	return append(json.RawMessage(nil), raw...), commands, nil
}

func migratedOriginWorkflow(ctx context.Context, tx *sql.Tx, id uuid.UUID, b model.CapacityMigratedNativeOriginBinding, historical bool) error {
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='workflow' AND ($2 OR active) AND namespace=(SELECT namespace FROM public.manifests WHERE id=$3::uuid) FOR SHARE`, id, historical, b.PolicyID).Scan(&raw) != nil {
		return ErrCapacityMutationAuthorization
	}
	var wf struct {
		Trigger struct {
			Mode string `json:"mode"`
		} `json:"trigger"`
		DispatchMode  string          `json:"dispatch_mode"`
		Authorization json.RawMessage `json:"authorization"`
		Steps         []struct {
			ID      string                     `json:"id"`
			Use     map[string]string          `json:"use"`
			With    map[string]json.RawMessage `json:"with"`
			Retry   map[string]int             `json:"retry"`
			Timeout int                        `json:"timeout_seconds"`
		} `json:"steps"`
	}
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &wf) != nil || wf.Trigger.Mode != "manual" || wf.DispatchMode != "sync" || len(wf.Authorization) == 0 || bytes.Equal(wf.Authorization, []byte("null")) || len(wf.Steps) != 1 {
		return ErrCapacityMutationAuthorization
	}
	s := wf.Steps[0]
	var literal model.CapacityMigratedNativeOriginBinding
	var confirmation string
	if s.ID == "" || len(s.Use) != 2 || s.Use["kind"] != "yggdrasil" || s.Use["operation"] != capacity.RetireMigratedNativeOrigin || s.Timeout != 90 || len(s.Retry) != 1 || s.Retry["max_attempts"] != 1 || len(s.With) != 2 || bytes.Contains(s.With["binding"], []byte("{{")) || capacity.DecodeNativeCapacity(s.With["binding"], &literal) != nil || !reflect.DeepEqual(literal, b) || json.Unmarshal(s.With["confirmation"], &confirmation) != nil || confirmation != "{{ inputs.confirmation }}" {
		return ErrCapacityMutationAuthorization
	}
	return nil
}

// RetireMigratedNativeOrigin appends an administrative declaration only. It
// never updates the old checkpoint/commands/intent or fabricates a native ACK.
func (s CapacityStore) RetireMigratedNativeOrigin(ctx context.Context, policy model.Manifest, b model.CapacityMigratedNativeOriginBinding, e model.CapacityMigratedNativeTargetEvidence) error {
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil || !s.ExecutionEnabled || s.AdmissionOnly || !validCapacityExecutor(s.ExecutorID) || s.ExecutorPowerOperator != b.OperatorID || capacity.ValidateMigratedNativeOriginBinding(policy, p, b) != nil {
		return ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return err
	}
	var checksum string
	var active bool
	var currentSpec []byte
	if tx.QueryRowContext(ctx, `SELECT checksum,active,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active, &currentSpec) != nil || !active || checksum != policy.Checksum || nativeCanonicalArchiveSHA(currentSpec) != nativeCanonicalArchiveSHA(policy.Spec) {
		return migratedOriginRefusal("current-policy")
	}
	if err = migratedOriginWorkflow(ctx, tx, s.WorkflowID, b, false); err != nil {
		return err
	}
	if err = checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(p.AssessmentBinding.Snapshot.Adapter)); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	now = now.UTC()
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil || current.Generation != b.ExpectedIntentGeneration || current.FencingToken != b.ExpectedIntentFencingToken || current.RecoveryOnly || current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(now) || current.Phase != "hold" && current.Phase != "envelope_applied" && current.Phase != "native_completed" && current.Phase != "admission_pending" || failedServingQuarantineBlocks(&current) || current.OriginalNotifyWindow != nil && (current.OriginalNotifyWindow.State != "original_returns_observed" || current.OriginalNotifyWindow.OriginalReturnsObservedAt == nil) {
		return migratedOriginRefusal("current-intent")
	}
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	if err = lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
		return err
	}
	if capacity.ValidateMigratedSourceFence(b, p, now) != nil || capacity.ValidateMigratedNativeTarget(p, b, e, now) != nil {
		return migratedOriginRefusal("fresh-observations")
	}
	origin, op, err := migratedOriginPolicy(ctx, tx, policy, p, b)
	if err != nil {
		return err
	}
	cp, commands, err := migratedOriginBodies(ctx, tx, origin, op, b)
	if err != nil {
		return err
	}
	counts, err := nativeActiveUnsettledTx(ctx, tx, policy, p, "")
	if err != nil || counts.ActiveUnsettled != 0 {
		return migratedOriginRefusal("active-unsettled")
	}
	r := model.CapacityMigratedNativeOriginRetirement{Schema: capacity.MigratedNativeOriginSchema, Binding: b, WorkflowID: s.WorkflowID.String(), ExecutorID: s.ExecutorID, OperatorID: s.ExecutorPowerOperator, Checkpoint: cp, Commands: commands, Target: e, RecordedAt: now}
	raw, err := nativeAbortCanonical(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_migrated_origin_retirements(subject_uid,namespace,environment,domain,dimension,origin_policy_id,checkpoint_sha256,record_sha256,retirement_record,recorded_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, b.PodUID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, origin.ID, b.CheckpointSHA256, nativeCanonicalArchiveSHA(raw), raw, now); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tx.Commit()
}
