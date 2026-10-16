package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func validateNativeReleaseRedemption(c model.CapacityNativeCommand, p model.CapacityPolicySpec, r model.CapacityNativeAuthorityRedeemRequest) error {
	if c.ReleaseProtocol == "" {
		if r.ReleaseProtocol != "" || r.AdapterSourceCommit != "" {
			return ErrCapacityMutationAuthorization
		}
		return nil
	}
	b := p.HPAExecutionBinding.ReleaseRecovery
	if b == nil || c.Operation != capacity.DestroyNativePodProtection || c.Phase != "release" || c.ReleaseProtocol != capacity.NativeReleaseResultProtocol || r.ReleaseProtocol != c.ReleaseProtocol || r.AdapterSourceCommit != c.AdapterSourceCommit || b.Protocol != c.ReleaseProtocol || b.AdapterSourceCommit != c.AdapterSourceCommit {
		return ErrCapacityMutationAuthorization
	}
	return nil
}

func retainNativeReleaseRedemption(ctx context.Context, tx *sql.Tx, c model.CapacityNativeCommand) (string, error) {
	if c.ReleaseProtocol == "" {
		return "", nil
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(random)
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_native_release_results(command_id,attempt_id,protocol,adapter_source_commit,return_nonce_sha256,original_deadline) VALUES($1,$2,$3,$4,$5,$6)`, c.CommandID, c.AttemptID, c.ReleaseProtocol, c.AdapterSourceCommit, nativeArchiveSHA([]byte(nonce)), c.ExpiresAt)
	return nonce, err
}

func nativeReleaseResultComplete(r model.CapacityNativeReleaseResult) bool {
	return r.Protocol == capacity.NativeReleaseResultProtocol && r.CommandID != uuid.Nil && r.AttemptID != uuid.Nil && r.Capability == capacity.DestroyNativePodProtection && len(r.ReturnNonce) == 64 && len(r.RequestSHA256) == 64 && len(r.OriginalResponseSHA256) == 64 && len(r.AdapterSourceCommit) == 40 && r.OneSend && r.DoReturned && r.ReadReturned && r.CloseReturned && ((r.Outcome == "rejected_no_effect" && r.OriginalStatus == 409) || (r.Outcome == "applied" && r.OriginalStatus == 200))
}

func nativeReleaseRecordDeadline(ctx context.Context, original time.Time) error {
	err := errors.Join(ctx.Err(), context.Cause(ctx))
	if !time.Now().Before(original) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

// This authenticated callback retains the adapter's ORIGINAL result only. The
// caller acknowledgement is private in-process and cannot be supplied here.
func (s CapacityStore) RecordNativeReleaseResult(ctx context.Context, principal string, r model.CapacityNativeReleaseResult) error {
	if s.DB == nil || !s.ExecutionEnabled || !nativeReleaseResultComplete(r) {
		return ErrCapacityMutationAuthorization
	}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, r.CommandID).Scan(&raw); err != nil {
		return ErrCapacityMutationAuthorization
	}
	var initial model.CapacityNativeCommand
	if json.Unmarshal(raw, &initial) != nil {
		return ErrCapacityMutationAuthorization
	}
	policy, err := GetManifestByID(ctx, s.DB, initial.PolicyID)
	if err != nil {
		return ErrCapacityConflict
	}
	s.WorkflowID, s.ExecutorID, s.AdmissionOnly = initial.WorkflowID, initial.ExecutorID, initial.AdmissionOnly
	originalDeadline := initial.ExpiresAt
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(originalDeadline) {
		originalDeadline = deadline
	}
	if err := nativeReleaseRecordDeadline(ctx, originalDeadline); err != nil {
		return err
	}
	err = s.mutationTransaction(ctx, policy, false, initial.IntentGeneration, initial.FencingToken, initial.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, r.CommandID).Scan(&raw); err != nil {
			return err
		}
		var c model.CapacityNativeCommand
		if json.Unmarshal(raw, &c) != nil || (c.State != "redeemed" && c.State != "uncertain" && c.State != "rejected_no_effect") || c.AttemptID != r.AttemptID || c.AdapterPrincipalID != principal || c.RedeemedBy != principal || c.RequestSHA256 != r.RequestSHA256 || c.Adapter.IntegrationInstanceID != r.IntegrationInstanceID || c.Adapter.IntegrationTypeID != r.IntegrationTypeID || c.ReleaseProtocol != r.Protocol || c.AdapterSourceCommit != r.AdapterSourceCommit || c.ExecutorID != current.LeaseExecutorID || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(time.Now()) || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.ReleaseRecovery == nil || p.HPAExecutionBinding.ReleaseRecovery.Protocol != r.Protocol || p.HPAExecutionBinding.ReleaseRecovery.AdapterSourceCommit != r.AdapterSourceCommit {
			return ErrCapacityConflict
		}
		if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(c.Adapter)); err != nil {
			return err
		}
		var nonce string
		var previous []byte
		var ack sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT return_nonce_sha256,adapter_result,adapter_ack_at FROM public.capacity_native_release_results WHERE command_id=$1 AND attempt_id=$2 FOR UPDATE`, c.CommandID, c.AttemptID).Scan(&nonce, &previous, &ack); err != nil {
			return err
		}
		if nonce != nativeArchiveSHA([]byte(r.ReturnNonce)) {
			return ErrCapacityMutationAuthorization
		}
		r.ReturnNonce = "" // The one-use plaintext never enters durable records.
		payload, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if ack.Valid {
			if nativeCanonicalArchiveSHA(previous) != nativeCanonicalArchiveSHA(payload) {
				return ErrCapacityConflict
			}
			return nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_release_results SET adapter_result=$2,adapter_result_sha256=$3,adapter_ack_at=$4 WHERE command_id=$1 AND adapter_ack_at IS NULL`, c.CommandID, payload, nativeCanonicalArchiveSHA(payload), now)
		return err
	})
	return errors.Join(err, nativeReleaseRecordDeadline(ctx, originalDeadline))
}

// Called only after the private original transport has actually joined its
// Do/Read/Close. No HTTP endpoint or caller boolean can write this ACK.
func (s CapacityStore) AcknowledgeNativeReleaseCaller(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, id uuid.UUID) (model.CapacityNativeCommand, error) {
	var c model.CapacityNativeCommand
	if intent.LeaseExpiresAt == nil {
		return c, ErrCapacityLease
	}
	originalDeadline := *intent.LeaseExpiresAt
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(originalDeadline) {
		originalDeadline = deadline
	}
	if err := nativeReleaseRecordDeadline(ctx, originalDeadline); err != nil {
		return c, err
	}
	err := s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		var raw, result []byte
		var ack sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal(raw, &c) != nil || c.ExecutorID != s.ExecutorID || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.IntentGeneration != current.Generation || c.FencingToken != current.FencingToken || c.LeaseOwner != current.LeaseOwner || c.AttemptID == uuid.Nil || c.ReleaseProtocol != capacity.NativeReleaseResultProtocol || c.State != "redeemed" || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(time.Now()) || p.HPAExecutionBinding.ReleaseRecovery == nil || p.HPAExecutionBinding.ReleaseRecovery.AdapterSourceCommit != c.AdapterSourceCommit {
			return ErrCapacityConflict
		}
		if err := tx.QueryRowContext(ctx, `SELECT adapter_result,adapter_ack_at FROM public.capacity_native_release_results WHERE command_id=$1 AND attempt_id=$2 AND protocol=$3 AND adapter_source_commit=$4 FOR UPDATE`, c.CommandID, c.AttemptID, c.ReleaseProtocol, c.AdapterSourceCommit).Scan(&result, &ack); err != nil {
			return err
		}
		var r model.CapacityNativeReleaseResult
		if !ack.Valid || json.Unmarshal(result, &r) != nil || r.CommandID != c.CommandID || r.AttemptID != c.AttemptID || r.RequestSHA256 != c.RequestSHA256 || r.AdapterSourceCommit != c.AdapterSourceCommit || r.Outcome != "rejected_no_effect" || r.OriginalStatus != 409 || !r.OneSend || !r.DoReturned || !r.ReadReturned || !r.CloseReturned {
			return ErrCapacityConflict
		}
		if err := checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(c.Adapter)); err != nil {
			return err
		}
		c.State, c.OriginalResult, c.OriginalResultSHA256, c.CallerReturnObservedAt, c.UpdatedAt = "rejected_no_effect", result, nativeCanonicalArchiveSHA(result), &now, now
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_release_results SET caller_ack_at=$2 WHERE command_id=$1 AND caller_ack_at IS NULL`, c.CommandID, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state=$2,command_record=$3,updated_at=$4 WHERE id=$1 AND state='redeemed'`, c.CommandID, c.State, raw, now)
		return err
	})
	if !c.ExpiresAt.IsZero() {
		err = errors.Join(err, nativeReleaseRecordDeadline(ctx, originalDeadline))
	}
	return c, err
}

type nativeReleaseRecoveryAdmission struct {
	Parent    model.CapacityNativeCommand
	HPA       model.CapacityHPAEnvelopeResponse
	Inventory model.AdapterCapacityPodInventoryResponse
	Witness   model.AdapterCapacityPodTerminationResponse
}

// A separate admission transaction creates a new release-only authority with
// its own command/fence and immutable parent attempt. It cannot renew time.
func (s CapacityStore) IssueNativeReleaseRecovery(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, parent model.CapacityNativeCommand, request json.RawMessage, hpa model.CapacityHPAEnvelopeResponse, inventory model.AdapterCapacityPodInventoryResponse, witness model.AdapterCapacityPodTerminationResponse) (model.CapacityNativeCommand, string, error) {
	var subject struct {
		UID string `json:"expected_pod_uid"`
	}
	if json.Unmarshal(request, &subject) != nil || subject.UID == "" {
		return model.CapacityNativeCommand{}, "", ErrCapacityConflict
	}
	return s.issueNativeCommand(ctx, policy, intent, capacity.DestroyNativePodProtection, subject.UID, request, &nativeReleaseRecoveryAdmission{parent, hpa, inventory, witness})
}

func (s CapacityStore) validateNativeReleaseRecoveryAdmission(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, subject string, request []byte, a *nativeReleaseRecoveryAdmission, now time.Time) (int, int, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, a.Parent.CommandID).Scan(&raw); err != nil {
		return 0, 0, err
	}
	var old model.CapacityNativeCommand
	if json.Unmarshal(raw, &old) != nil || old.State != "rejected_no_effect" || old.ReleaseProtocol != capacity.NativeReleaseResultProtocol || old.Operation != capacity.DestroyNativePodProtection || old.Phase != "release" || old.CallerReturnObservedAt == nil || old.AttemptID == uuid.Nil || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.WorkflowID != s.WorkflowID || old.IntentGeneration != current.Generation || old.FencingToken != current.FencingToken || old.LeaseOwner != current.LeaseOwner || old.ExecutorID != s.ExecutorID || !old.ExpiresAt.After(now) || !old.ExpiresAt.After(time.Now()) || p.HPAExecutionBinding.ReleaseRecovery == nil || p.HPAExecutionBinding.ReleaseRecovery.AdapterSourceCommit != old.AdapterSourceCommit || current.LeaseExpiresAt == nil || old.ExpiresAt.After(*current.LeaseExpiresAt) || current.RecoveryOnly {
		return 0, 0, ErrCapacityConflict
	}
	var ack int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1 AND attempt_id=$2 AND adapter_ack_at IS NOT NULL AND caller_ack_at IS NOT NULL AND adapter_result_sha256=$3 AND original_deadline=$4`, old.CommandID, old.AttemptID, old.OriginalResultSHA256, old.ExpiresAt).Scan(&ack); err != nil || ack != 1 {
		return 0, 0, ErrCapacityConflict
	}
	cp, err := nativeLifetimeCheckpoint(ctx, tx, p, current, subject)
	if err != nil || cp.State != "confirmed" || cp.PolicyChecksum != policy.Checksum || capacity.NativePodWitness(p, cp, a.Witness.Observation, now) != nil || capacity.NativePodInventory(p, a.Inventory, now) != nil {
		return 0, 0, ErrCapacityConflict
	}
	var req model.AdapterDestroyCapacityPodDrainProtectionRequest
	if capacity.DecodeNativeCapacity(json.RawMessage(request), &req) != nil || req.ExpectedPodUID != cp.PodUID || req.ExpectedPodResourceVersion != a.Witness.Observation.PodResourceVersion {
		return 0, 0, ErrCapacityConflict
	}
	snapshot, err := capacity.BoundHPASnapshot(p, a.HPA, now)
	if err != nil || snapshot.ResourceUID != current.BaselineSnapshot.ResourceUID || snapshot.WorkloadUID != cp.WorkloadUID || snapshot.Units < p.Floor || snapshot.Units > p.Ceiling {
		return 0, 0, ErrCapacityConflict
	}
	found := false
	for _, pod := range a.Inventory.Pods {
		if pod.PodUID == subject {
			found = pod.PodName == cp.PodName && pod.WorkloadUID == cp.WorkloadUID && pod.PodResourceVersion == req.ExpectedPodResourceVersion
		}
	}
	if !found {
		return 0, 0, ErrCapacityConflict
	}
	var previous, terminal int
	// Permanent identities include hot and archived rows; no generation or TTL
	// can reset the four-command history for this UID/phase.
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE COALESCE(c.state,a.command_record->>'state') IN ('refused_no_redemption','rejected_no_effect')) FROM public.capacity_native_command_identities i LEFT JOIN public.capacity_native_commands c ON c.id=i.id LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id WHERE i.namespace=$1 AND i.environment=$2 AND i.domain=$3 AND i.dimension=$4 AND i.operation=$5 AND i.subject_uid=$6 AND i.phase='release'`, current.Namespace, p.Environment, p.Domain, p.Dimension, capacity.DestroyNativePodProtection, subject).Scan(&previous, &terminal); err != nil {
		return 0, 0, err
	}
	a.Parent = old
	return previous, terminal, nil
}

func retainNativeReleaseRecoveryDecision(ctx context.Context, tx *sql.Tx, c model.CapacityNativeCommand, a *nativeReleaseRecoveryAdmission, now time.Time) error {
	record := struct {
		Command            model.CapacityNativeCommand                 `json:"command"`
		ParentResultSHA256 string                                      `json:"parent_result_sha256"`
		HPA                model.CapacityHPAEnvelopeResponse           `json:"hpa"`
		Inventory          model.AdapterCapacityPodInventoryResponse   `json:"inventory"`
		Witness            model.AdapterCapacityPodTerminationResponse `json:"witness"`
	}{c, a.Parent.OriginalResultSHA256, a.HPA, a.Inventory, a.Witness}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 2<<20 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_release_recovery_decisions(id,parent_command_id,parent_attempt_id,command_id,fence,decision_record,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, c.RecoveryDecisionID, c.ParentCommandID, c.ParentAttemptID, c.CommandID, c.RecoveryFence, raw, now)
	return err
}

// The immutable archive retains the original rejected command and both ACKs;
// it never relabels rejection as an unredeemed token or confirmed release.
func nativeRejectedReleaseRetained(c model.CapacityNativeCommand) bool {
	var r model.CapacityNativeReleaseResult
	return c.State == "rejected_no_effect" && c.ReleaseProtocol == capacity.NativeReleaseResultProtocol && c.CallerReturnObservedAt != nil && c.CallerReturnObservedAt.Before(c.ExpiresAt) && c.AttemptID != uuid.Nil && c.Operation == capacity.DestroyNativePodProtection && c.Phase == "release" && nativeCanonicalArchiveSHA(c.OriginalResult) == c.OriginalResultSHA256 && capacity.DecodeNativeCapacity(c.OriginalResult, &r) == nil && r.CommandID == c.CommandID && r.AttemptID == c.AttemptID && r.RequestSHA256 == c.RequestSHA256 && r.AdapterSourceCommit == c.AdapterSourceCommit && r.ReturnNonce == "" && r.Outcome == "rejected_no_effect" && r.OriginalStatus == 409 && r.OneSend && r.DoReturned && r.ReadReturned && r.CloseReturned
}
