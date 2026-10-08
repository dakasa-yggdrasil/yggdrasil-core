package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeObservationMutationBinding(b model.CapacityObservationAdapterBinding) model.CapacityMutationBinding {
	return model.CapacityMutationBinding{IntegrationInstanceID: b.IntegrationInstanceID, IntegrationChecksum: b.InstanceChecksum, IntegrationTypeID: b.IntegrationTypeID, IntegrationTypeChecksum: b.TypeChecksum}
}

func nativeCapacityOperation(operation string) bool {
	return operation == capacity.EnsureBoundHPAEnvelope || operation == capacity.EnsureNativePodDrain || operation == capacity.DestroyNativePodProtection
}

const maxNativeCommandSequences = 4

// IssueNativeCommand creates a fresh one-use permission for a native phase.
// A new sequence requires every previous permission to be proven unredeemed.
// No network call occurs while the transaction holds dimension and row locks.
// The plaintext command token is returned only to the fixed private invocation.
func (s CapacityStore) IssueNativeCommand(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, operation, subject string, request json.RawMessage) (model.CapacityNativeCommand, string, error) {
	var command model.CapacityNativeCommand
	if !nativeCapacityOperation(operation) || len(request) == 0 || len(request) > 32768 || !json.Valid(request) || len(subject) > 128 {
		return command, "", ErrCapacityMutationAuthorization
	}
	canonical, phase, err := canonicalNativeCommandRequest(operation, request)
	if err != nil {
		return command, "", err
	}
	request = canonical
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return command, "", err
	}
	token := hex.EncodeToString(secret)
	tokenDigest, requestDigest := sha256.Sum256([]byte(token)), sha256.Sum256(request)
	err = s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || len(p.MutationBindings) != 0 || !p.ExecutionEnabled || !s.ExecutionEnabled {
			return ErrCapacityDisabled
		}
		if current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.RecoveryOnly || current.LeaseExecutorID != s.ExecutorID {
			return ErrCapacityConflict
		}
		if err := lockNativeBoundOwner(ctx, tx, policy, p, subject); err != nil {
			return err
		}
		if err := validateNativeCommandRequest(ctx, tx, p, current, operation, phase, subject, request); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN ('issued','redeemed','uncertain')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return ErrCapacityConflict
		}
		var previous, refused int
		if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='refused_no_redemption') FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND operation=$6 AND subject_uid=$7 AND phase=$8`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, operation, subject, phase).Scan(&previous, &refused); err != nil {
			return err
		}
		if previous != refused || previous >= maxNativeCommandSequences {
			return ErrCapacityConflict
		}
		binding := p.AssessmentBinding.Snapshot.Adapter
		if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(binding)); err != nil {
			return err
		}
		if operation == capacity.DestroyNativePodProtection {
			var checkpointRaw []byte
			if err := tx.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_pod_checkpoints WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND pod_uid=$6 FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, subject).Scan(&checkpointRaw); err != nil {
				return err
			}
			var checkpoint model.CapacityNativePodCheckpoint
			if json.Unmarshal(checkpointRaw, &checkpoint) != nil || checkpoint.PodUID != subject || checkpoint.IntentGeneration != current.Generation || checkpoint.State != "confirmed" || checkpoint.ConfirmedAt == nil || len(checkpoint.NativeTerminationReceipt) == 0 {
				return ErrCapacityConflict
			}
		}
		command = model.CapacityNativeCommand{
			CommandID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID,
			Namespace: current.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension,
			IntentGeneration: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: s.ExecutorID,
			Adapter: binding, AdapterPrincipalID: p.HPAExecutionBinding.AdapterPrincipalID, Operation: operation, Phase: phase,
			Sequence: previous + 1,
			Request:  request, RequestSHA256: hex.EncodeToString(requestDigest[:]), State: "issued", AuthorityTokenSHA256: hex.EncodeToString(tokenDigest[:]),
			CreatedAt: now, ExpiresAt: *current.LeaseExpiresAt, UpdatedAt: now,
		}
		raw, err := json.Marshal(command)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_native_commands (id,namespace,environment,domain,dimension,generation,operation,subject_uid,state,authority_token_sha256,command_record,updated_at,phase,sequence) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence) DO NOTHING`, command.CommandID, command.Namespace, command.Environment, command.Domain, command.Dimension, command.IntentGeneration, command.Operation, subject, command.State, command.AuthorityTokenSHA256, raw, now, phase, command.Sequence)
		if err != nil {
			return err
		}
		inserted, err := result.RowsAffected()
		if err != nil || inserted != 1 {
			return ErrCapacityConflict
		}
		return nil
	})
	if err != nil {
		return model.CapacityNativeCommand{}, "", err
	}
	return command, token, nil
}

// RevokeUnredeemedNativeCommand shares the dimension lock and row lock used by
// redemption. A late adapter can no longer redeem a revoked token. If redemption
// won the race, no retry authority is returned and only native readback remains.
// Request, identity, token hash and prior command records are never replaced.
func (s CapacityStore) RevokeUnredeemedNativeCommand(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, commandID uuid.UUID) (bool, error) {
	refused := false
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || current.LeaseExecutorID != s.ExecutorID || commandID == uuid.Nil {
			return ErrCapacityMutationAuthorization
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, commandID).Scan(&raw); err != nil {
			return err
		}
		var command model.CapacityNativeCommand
		if json.Unmarshal(raw, &command) != nil || command.PolicyID != policy.ID || command.PolicyChecksum != policy.Checksum || command.IntentGeneration != current.Generation || command.Namespace != current.Namespace || command.Environment != p.Environment || command.Domain != p.Domain || command.Dimension != p.Dimension || command.Adapter != p.AssessmentBinding.Snapshot.Adapter {
			return ErrCapacityConflict
		}
		if command.State != "issued" || command.AttemptID != uuid.Nil || command.RedeemedBy != "" {
			return nil
		}
		command.State, command.UpdatedAt = "refused_no_redemption", now
		raw, err := json.Marshal(command)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state=$2,command_record=$3,updated_at=$4 WHERE id=$1`, commandID, command.State, raw, now); err != nil {
			return err
		}
		refused = true
		return nil
	})
	return refused, err
}

// RedeemNativeCommand requires both the adapter's exact machine principal and
// the private invocation's opaque command token. Replays cannot send again.
func (s CapacityStore) RedeemNativeCommand(ctx context.Context, principal string, request model.CapacityNativeAuthorityRedeemRequest) (model.CapacityNativeAuthorityPermit, error) {
	var permit model.CapacityNativeAuthorityPermit
	if s.DB == nil || !s.ExecutionEnabled || principal == "" || len(request.AuthorityToken) != 64 || !nativeCapacityOperation(request.Capability) {
		return permit, ErrCapacityMutationAuthorization
	}
	decoded, err := hex.DecodeString(request.AuthorityToken)
	if err != nil || len(decoded) != 32 {
		return permit, ErrCapacityMutationAuthorization
	}
	digest := sha256.Sum256([]byte(request.AuthorityToken))
	hash := hex.EncodeToString(digest[:])
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE authority_token_sha256=$1`, hash).Scan(&raw); err != nil {
		return permit, ErrCapacityMutationAuthorization
	}
	var initial model.CapacityNativeCommand
	if json.Unmarshal(raw, &initial) != nil {
		return permit, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return permit, err
	}
	defer tx.Rollback()
	key, _ := json.Marshal([]string{initial.Namespace, initial.Environment, initial.Domain, initial.Dimension})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		return permit, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE authority_token_sha256=$1 FOR UPDATE`, hash).Scan(&raw); err != nil {
		return permit, ErrCapacityMutationAuthorization
	}
	var command model.CapacityNativeCommand
	if json.Unmarshal(raw, &command) != nil || command.CommandID != initial.CommandID || command.State != "issued" || command.AdapterPrincipalID != principal || command.Adapter.IntegrationInstanceID != request.IntegrationInstanceID || command.Adapter.IntegrationTypeID != request.IntegrationTypeID || command.Operation != request.Capability || command.RequestSHA256 != request.RequestSHA256 {
		return permit, ErrCapacityMutationAuthorization
	}
	var policyRaw []byte
	var checksum string
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT spec,checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 FOR SHARE`, command.PolicyID, command.Namespace).Scan(&policyRaw, &checksum, &active); err != nil || !active || checksum != command.PolicyChecksum {
		return permit, ErrCapacityConflict
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(policyRaw, &p) != nil || capacity.ValidatePolicy(p) != nil || p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || !p.ExecutionEnabled || p.HPAExecutionBinding.AdapterPrincipalID != principal || p.AssessmentBinding.Snapshot.Adapter != command.Adapter {
		return permit, ErrCapacityMutationAuthorization
	}
	if err := tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, command.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil || !active {
		return permit, ErrCapacityMutationAuthorization
	}
	if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(command.Adapter)); err != nil {
		return permit, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return permit, err
	}
	intent, err := loadCapacityIntent(ctx, tx, command.Namespace, p, true)
	if err != nil || intent.PolicyID != command.PolicyID || intent.PolicyChecksum != command.PolicyChecksum || intent.Generation != command.IntentGeneration || intent.FencingToken != command.FencingToken || intent.LeaseOwner != command.LeaseOwner || intent.LeaseExecutorID != command.ExecutorID || intent.RecoveryOnly || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.After(now) || !command.ExpiresAt.After(now) {
		return permit, ErrCapacityLease
	}
	command.State, command.RedeemedBy, command.AttemptID, command.UpdatedAt = "redeemed", principal, uuid.New(), now.UTC()
	raw, err = json.Marshal(command)
	if err != nil {
		return permit, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state=$2,command_record=$3,updated_at=$4 WHERE id=$1`, command.CommandID, command.State, raw, now); err != nil {
		return permit, err
	}
	if err := tx.Commit(); err != nil {
		return permit, err
	}
	return model.CapacityNativeAuthorityPermit{SchemaVersion: 1, CommandID: command.CommandID, AttemptID: command.AttemptID, Capability: command.Operation, RequestSHA256: command.RequestSHA256, ExpiresAt: command.ExpiresAt}, nil
}

func (s CapacityStore) MarkNativeCommandUncertain(ctx context.Context, commandID uuid.UUID) error {
	if commandID == uuid.Nil || !validCapacityExecutor(s.ExecutorID) {
		return ErrCapacityMutationAuthorization
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state='uncertain',command_record=jsonb_set(command_record,'{state}','"uncertain"'),updated_at=clock_timestamp() WHERE id=$1 AND command_record->>'executor_id'=$2 AND state IN ('issued','redeemed')`, commandID, s.ExecutorID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fmt.Errorf("%w: native command cannot change uncertainty state", ErrCapacityConflict)
	}
	return nil
}

// The digest is compact sorted-key JSON with exact number spelling. Native
// adapters use the same independent wire normalization before redemption.
func canonicalNativeCommandRequest(operation string, raw json.RawMessage) (json.RawMessage, string, error) {
	switch operation {
	case capacity.EnsureBoundHPAEnvelope:
		var out model.CapacityNativeHPARequest
		if capacity.DecodeNativeCapacity(raw, &out) != nil {
			return nil, "", ErrCapacityMutationAuthorization
		}
	case capacity.EnsureNativePodDrain:
		var out model.AdapterEnsureCapacityPodDrainRequest
		if capacity.DecodeNativeCapacity(raw, &out) != nil {
			return nil, "", ErrCapacityMutationAuthorization
		}
	case capacity.DestroyNativePodProtection:
		var out model.AdapterDestroyCapacityPodDrainProtectionRequest
		if capacity.DecodeNativeCapacity(raw, &out) != nil {
			return nil, "", ErrCapacityMutationAuthorization
		}
	default:
		return nil, "", ErrCapacityMutationAuthorization
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || fields == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, "", ErrCapacityMutationAuthorization
	}
	phase := "envelope"
	if operation == capacity.EnsureNativePodDrain {
		value, ok := fields["phase"].(string)
		if !ok || (value != "protect" && value != "terminate") {
			return nil, "", ErrCapacityMutationAuthorization
		}
		phase = value
	}
	if operation == capacity.DestroyNativePodProtection {
		phase = "release"
	}
	if _, exists := fields["authority_token"]; exists {
		return nil, "", ErrCapacityMutationAuthorization
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return nil, "", ErrCapacityMutationAuthorization
	}
	return canonical, phase, nil
}

// Native UID ownership cannot silently cross policy realms or dimensions.
func lockNativeBoundOwner(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, uid string) error {
	key, _ := json.Marshal([]string{"capacity-bound-native-uid", uid})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		return err
	}
	scope, _ := json.Marshal([]string{policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, policy.Metadata.Name})
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_native_scope_owners(native_uid,namespace,owner_scope)VALUES($1,$2,$3)ON CONFLICT DO NOTHING`, uid, policy.Metadata.Namespace, scope); err != nil {
		return err
	}
	var retained []byte
	if err := tx.QueryRowContext(ctx, `SELECT owner_scope FROM public.capacity_native_scope_owners WHERE native_uid=$1 FOR UPDATE`, uid).Scan(&retained); err != nil {
		return err
	}
	var a, b []string
	if json.Unmarshal(retained, &a) != nil || json.Unmarshal(scope, &b) != nil || len(a) != len(b) {
		return ErrCapacityConflict
	}
	for i := range a {
		if a[i] != b[i] {
			return ErrCapacityConflict
		}
	}
	return nil
}
