package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A permanent identity is a deny fence even if its HOT/archive body is missing.
// Call only after lockNativeBoundOwner, in the existing scope -> UID lock order.
func guardNativePreRegistrationAbortTx(ctx context.Context, tx *sql.Tx, uid string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1 AND operation=$2)+(SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 AND operation=$2)`, uid, capacity.DestroyNativeUnregisteredProtection).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrCapacityConflict
	}
	return nil
}

func nativeAbortCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var obj any
	if d.Decode(&obj) != nil {
		return nil, ErrCapacityConflict
	}
	return json.Marshal(obj)
}
func nativeAbortWorkflow(ctx context.Context, tx *sql.Tx, id uuid.UUID, policy model.Manifest, b model.CapacityNativeAbortBinding) error {
	if id == uuid.Nil {
		return ErrCapacityMutationAuthorization
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND active FOR SHARE`, id, policy.Metadata.Namespace).Scan(&raw); err != nil {
		return ErrCapacityMutationAuthorization
	}
	var wf map[string]json.RawMessage
	if json.Unmarshal(raw, &wf) != nil {
		return ErrCapacityMutationAuthorization
	}
	var trigger map[string]string
	var auth map[string]json.RawMessage
	if json.Unmarshal(wf["trigger"], &trigger) != nil || len(trigger) != 1 || trigger["mode"] != "manual" || json.Unmarshal(wf["authorization"], &auth) != nil || len(auth) == 0 {
		return ErrCapacityMutationAuthorization
	}
	var steps []map[string]json.RawMessage
	if json.Unmarshal(wf["steps"], &steps) != nil || len(steps) != 1 {
		return ErrCapacityMutationAuthorization
	}
	step := steps[0]
	for key := range step {
		switch key {
		case "id", "use", "with", "retry", "timeout_seconds":
		default:
			return ErrCapacityMutationAuthorization
		}
	}
	var idText string
	if json.Unmarshal(step["id"], &idText) != nil || idText == "" {
		return ErrCapacityMutationAuthorization
	}
	if retry, ok := step["retry"]; ok {
		var r map[string]int
		if json.Unmarshal(retry, &r) != nil || len(r) != 1 || r["max_attempts"] != 1 {
			return ErrCapacityMutationAuthorization
		}
	}
	var use map[string]string
	if json.Unmarshal(step["use"], &use) != nil || len(use) != 2 || use["kind"] != "yggdrasil" || use["operation"] != "capacity.abort_native_birth" {
		return ErrCapacityMutationAuthorization
	}
	var with map[string]json.RawMessage
	if json.Unmarshal(step["with"], &with) != nil || len(with) != 2 || bytes.Contains(with["binding"], []byte("{{")) {
		return ErrCapacityMutationAuthorization
	}
	var literal model.CapacityNativeAbortBinding
	if capacity.DecodeNativeCapacity(with["binding"], &literal) != nil || literal != b {
		return ErrCapacityMutationAuthorization
	}
	var confirmation string
	if json.Unmarshal(with["confirmation"], &confirmation) != nil || (confirmation != b.Confirmation && confirmation != "{{ inputs.confirmation }}") {
		return ErrCapacityMutationAuthorization
	}
	return nil
}

// Dedicated human-only transaction; ordinary policy workflow authorization is
// neither bypassed nor relaxed. Callback context is reconstructed from the
// retained command, never from an HTTP caller-selected workflow or executor.
func (s CapacityStore) nativeAbortTransaction(ctx context.Context, policy model.Manifest, b model.CapacityNativeAbortBinding, expected *model.CapacityIntent, resume, human bool, fn func(*sql.Tx, model.CapacityPolicySpec, *model.CapacityIntent, time.Time) error) (model.CapacityIntent, error) {
	var current model.CapacityIntent
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return current, err
	}
	if s.DB == nil || !s.ExecutionEnabled || !p.ExecutionEnabled || s.AdmissionOnly || len(p.MutationBindings) != 0 || !validCapacityExecutor(s.ExecutorID) || capacity.ValidateNativeAbortBinding(policy, p, b) != nil || (human && (s.ExecutorPowerOperator == "" || s.ExecutorPowerOperator != b.OperatorID)) {
		return current, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return current, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return current, err
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return current, err
	}
	var checksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil || !active || checksum != policy.Checksum {
		return current, ErrCapacityConflict
	}
	if err = nativeAbortWorkflow(ctx, tx, s.WorkflowID, policy, b); err != nil {
		return current, err
	}
	if err = checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(b.Adapter)); err != nil {
		return current, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return current, err
	}
	now = now.UTC()
	current, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return current, err
	}
	if failedServingQuarantineBlocks(&current) || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.PolicyName != policy.Metadata.Name || current.Generation != b.Generation || current.RecoveryOnly || !pendingCapacityPhase(current.Phase) || current.Phase == "proposed" || current.WitnessedUnenrolledExpansionCleanupID != "" || current.FailedUnwitnessedExpansionCleanupID != "" || current.WitnessedExpansionTerminalReconcile != nil || current.FailedExpansionTerminalReconcile != nil || current.InstalledReadinessHandoff != nil || current.FailedInstalledDisposal != nil {
		return current, ErrCapacityConflict
	}
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return current, err
	}
	if resume {
		if current.FencingToken >= maxCapacityGeneration || (current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(now)) {
			return current, ErrCapacityLease
		}
		current.FencingToken++
		current.LeaseOwner = uuid.NewString()
		current.LeaseExecutorID = s.ExecutorID
		expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
		current.LeaseExpiresAt = &expires
		current.Phase = "native_pending"
		current.UpdatedAt = now
	} else {
		if expected == nil {
			return current, ErrCapacityConflict
		}
		if err = s.checkLease(p, policy, &current, expected.Generation, expected.FencingToken, expected.LeaseOwner, now); err != nil {
			return current, err
		}
	}
	if err = fn(tx, p, &current, now); err != nil {
		return current, err
	}
	if resume {
		raw, e := json.Marshal(current)
		if e != nil {
			return current, e
		}
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, raw, now); err != nil {
			return current, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, current.Phase, "native:pre-registration-abort-lease-only"); err != nil {
			return current, err
		}
	}
	if ctx.Err() != nil {
		return current, ctx.Err()
	}
	return current, tx.Commit()
}

// Resume reserves a lease, not native UID ownership, before the observer runs.
func nativeAbortUIDLock(ctx context.Context, tx *sql.Tx, uid string) error {
	key, _ := json.Marshal([]string{"capacity-bound-native-uid", uid})
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key))
	return err
}
func (s CapacityStore) ResumeNativePreRegistrationAbort(ctx context.Context, policy model.Manifest, b model.CapacityNativeAbortBinding) (model.CapacityIntent, error) {
	return s.nativeAbortTransaction(ctx, policy, b, nil, true, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := nativeAbortUIDLock(ctx, tx, b.PodUID); err != nil {
			return err
		}
		return guardNativePreRegistrationAbortTx(ctx, tx, b.PodUID)
	})
}

func nativeAbortZeroHistory(ctx context.Context, tx *sql.Tx, uid string) (model.CapacityNativeAbortZeroHistory, error) {
	var z model.CapacityNativeAbortZeroHistory
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),
 (SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 OR command_record->'request'->>'expected_pod_uid'=$1),
 (SELECT count(*) FROM public.capacity_native_command_archive a JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1 OR a.command_record->'request'->>'expected_pod_uid'=$1)`, uid).Scan(&z.Lifetimes, &z.LifetimeArchives, &z.LegacyCheckpoints, &z.CommandIdentities, &z.HotCommands, &z.ArchivedCommands)
	return z, err
}
func (s CapacityStore) IssueNativePreRegistrationAbort(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, b model.CapacityNativeAbortBinding, o model.NativePreRegistrationAbortObservation) (model.CapacityNativeCommand, string, error) {
	var c model.CapacityNativeCommand
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return c, "", err
	}
	token := hex.EncodeToString(secret)
	clear(secret)
	_, err := s.nativeAbortTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
			return err
		}
		z, err := nativeAbortZeroHistory(ctx, tx, b.PodUID)
		if err != nil {
			return err
		}
		var unsettled int64
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','uncertain')`, current.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&unsettled); err != nil {
			return err
		}
		proof := model.CapacityNativeAbortProof{Schema: capacity.NativePreRegistrationAbortSchema, Binding: b, Observation: o, ZeroHistory: z, ScopeUnsettledCommands: unsettled, FencingToken: current.FencingToken, AuthoredAt: now}
		if capacity.ValidateNativeAbortProof(policy, p, proof, now) != nil {
			return ErrCapacityConflict
		}
		no := false
		request := model.AdapterDestroyCapacityPodUnregisteredProtectionRequest{ExpectedPodUID: b.PodUID, ExpectedPodResourceVersion: o.PodResourceVersion, Proof: proof, DryRun: &no}
		raw, err := nativeAbortCanonical(request)
		if err != nil || len(raw) > 32768 {
			return ErrCapacityConflict
		}
		c = model.CapacityNativeCommand{CommandID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID, Namespace: current.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, IntentGeneration: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: s.ExecutorID, Adapter: b.Adapter, AdapterPrincipalID: b.AdapterPrincipalID, Operation: capacity.DestroyNativeUnregisteredProtection, Phase: capacity.NativePreRegistrationAbortPhase, Sequence: 1, Request: raw, RequestSHA256: nativeArchiveSHA(raw), State: "issued", AuthorityTokenSHA256: nativeArchiveSHA([]byte(token)), CreatedAt: now, ExpiresAt: *current.LeaseExpiresAt, UpdatedAt: now, OriginPolicy: append(json.RawMessage(nil), policy.Spec...), OriginPolicySHA256: nativeCanonicalArchiveSHA(policy.Spec), ReleaseProtocol: capacity.NativePreRegistrationAbortProtocol, AdapterSourceCommit: b.AdapterSourceCommit}
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(c.ExpiresAt) {
			c.ExpiresAt = deadline
		}
		// Retain a conservative exact timestamp across PostgreSQL microsecond storage.
		// Truncating before canonicalization never extends the original deadline.
		c.ExpiresAt = c.ExpiresAt.UTC().Truncate(time.Microsecond)
		if !c.ExpiresAt.After(now) {
			return ErrCapacityLease
		}
		record, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.CommandID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, b.PodUID, c.Phase, c.Sequence, c.AuthorityTokenSHA256, c.RequestSHA256); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, c.CommandID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, b.PodUID, c.Phase, c.Sequence, c.State, c.AuthorityTokenSHA256, record, now)
		return err
	})
	if err != nil {
		return model.CapacityNativeCommand{}, "", err
	}
	return c, token, nil
}

// The immutable identity/digest, not a mutable HOT JSON flag, owns the proof.
func nativeAbortStored(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id uuid.UUID, lock bool) (model.CapacityNativeCommand, model.AdapterDestroyCapacityPodUnregisteredProtectionRequest, error) {
	var c model.CapacityNativeCommand
	var req model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	var raw []byte
	q := `SELECT command_record FROM public.capacity_native_commands WHERE id=$1`
	if lock {
		q += " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, q, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		var archiveSHA string
		err = tx.QueryRowContext(ctx, `SELECT command_record,record_sha256 FROM public.capacity_native_command_archive WHERE id=$1`, id).Scan(&raw, &archiveSHA)
		if err == nil && archiveSHA != nativeCanonicalArchiveSHA(raw) {
			return c, req, ErrCapacityConflict
		}
	}
	if err != nil {
		return c, req, ErrCapacityConflict
	}
	if json.Unmarshal(raw, &c) != nil || capacity.DecodeNativeCapacity(c.Request, &req) != nil {
		return c, req, ErrCapacityConflict
	}
	var ns, env, domain, dim, op, subject, phase, tokenSHA, requestSHA string
	var generation int64
	var sequence int
	if tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256 FROM public.capacity_native_command_identities WHERE id=$1`, id).Scan(&ns, &env, &domain, &dim, &generation, &op, &subject, &phase, &sequence, &tokenSHA, &requestSHA) != nil {
		return c, req, ErrCapacityConflict
	}
	canonical, err := nativeAbortCanonical(req)
	if err != nil || c.CommandID != id || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.Namespace != policy.Metadata.Namespace || c.Environment != p.Environment || c.Domain != p.Domain || c.Dimension != p.Dimension || c.Operation != capacity.DestroyNativeUnregisteredProtection || c.Phase != capacity.NativePreRegistrationAbortPhase || c.Sequence != 1 || req.ExpectedPodUID != req.Proof.Binding.PodUID || req.ExpectedPodResourceVersion != req.Proof.Observation.PodResourceVersion || req.DryRun == nil || *req.DryRun || req.AuthorityToken != "" || !c.CreatedAt.Equal(req.Proof.AuthoredAt) || !c.ExpiresAt.After(c.CreatedAt) || c.IntentGeneration != req.Proof.Binding.Generation || c.FencingToken != req.Proof.FencingToken || c.Adapter != req.Proof.Binding.Adapter || c.AdapterPrincipalID != req.Proof.Binding.AdapterPrincipalID || c.AdapterSourceCommit != req.Proof.Binding.AdapterSourceCommit || c.ReleaseProtocol != capacity.NativePreRegistrationAbortProtocol || c.AdmissionOnly || c.RequestSHA256 != nativeArchiveSHA(canonical) || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(c.OriginPolicy) || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(policy.Spec) || capacity.ValidateNativeAbortProof(policy, p, req.Proof, req.Proof.AuthoredAt) != nil || ns != c.Namespace || env != c.Environment || domain != c.Domain || dim != c.Dimension || generation != c.IntentGeneration || op != c.Operation || subject != req.ExpectedPodUID || phase != c.Phase || sequence != c.Sequence || tokenSHA != c.AuthorityTokenSHA256 || requestSHA != c.RequestSHA256 {
		return c, req, ErrCapacityConflict
	}
	if c.State == "confirmed" && nativeAbortConfirmed(ctx, tx, p, c, req.Proof.Binding) != nil {
		return c, req, ErrCapacityConflict
	}
	return c, req, nil
}

// Confirmed custody remains verifiable after compaction. Freshness is checked
// at the original in-process join, never reinterpreted as today's live lease.
func nativeAbortConfirmed(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, c model.CapacityNativeCommand, b model.CapacityNativeAbortBinding) error {
	if c.AttemptID == uuid.Nil || c.RedeemedBy != b.AdapterPrincipalID || c.CallerReturnObservedAt == nil || c.CallerReturnObservedAt.Before(c.CreatedAt) || !c.CallerReturnObservedAt.Before(c.ExpiresAt) || len(c.OriginalResult) == 0 || c.OriginalResultSHA256 != nativeCanonicalArchiveSHA(c.OriginalResult) {
		return ErrCapacityConflict
	}
	var readback model.AdapterCapacityPodUnregisteredTerminalResponse
	var result model.CapacityNativeReleaseResult
	if capacity.DecodeNativeCapacity(c.NativeReadback, &readback) != nil || capacity.ValidateNativeAbortRemoval(p, b, readback, *c.CallerReturnObservedAt) != nil || capacity.DecodeNativeCapacity(c.OriginalResult, &result) != nil || result.ReturnNonce != "" || result.CommandID != c.CommandID || result.AttemptID != c.AttemptID || result.Protocol != c.ReleaseProtocol || result.AdapterSourceCommit != c.AdapterSourceCommit || result.Capability != c.Operation || result.IntegrationInstanceID != c.Adapter.IntegrationInstanceID || result.IntegrationTypeID != c.Adapter.IntegrationTypeID || result.RequestSHA256 != c.RequestSHA256 || result.Outcome != "applied" || result.OriginalStatus != 200 || len(result.OriginalResponseSHA256) != 64 || !result.OneSend || !result.DoReturned || !result.ReadReturned || !result.CloseReturned {
		return ErrCapacityConflict
	}
	var persisted []byte
	var digest, nonceHash, protocol, source string
	var attempt uuid.UUID
	var adapterAck, callerAck sql.NullTime
	var deadline time.Time
	if tx.QueryRowContext(ctx, `SELECT attempt_id,protocol,adapter_source_commit,return_nonce_sha256,original_deadline,adapter_result,adapter_result_sha256,adapter_ack_at,caller_ack_at FROM public.capacity_native_release_results WHERE command_id=$1`, c.CommandID).Scan(&attempt, &protocol, &source, &nonceHash, &deadline, &persisted, &digest, &adapterAck, &callerAck) != nil {
		return ErrCapacityConflict
	}
	if attempt != c.AttemptID || protocol != c.ReleaseProtocol || source != c.AdapterSourceCommit || len(nonceHash) != 64 || !deadline.Equal(c.ExpiresAt) || !adapterAck.Valid || !callerAck.Valid || !callerAck.Time.Equal(*c.CallerReturnObservedAt) || adapterAck.Time.Before(c.CreatedAt) || adapterAck.Time.After(callerAck.Time) || !adapterAck.Time.Before(c.ExpiresAt) || digest != c.OriginalResultSHA256 || digest != nativeCanonicalArchiveSHA(persisted) {
		return ErrCapacityConflict
	}
	return nil
}
func (s CapacityStore) LoadNativePreRegistrationAbort(ctx context.Context, policy model.Manifest, uid string) (model.CapacityNativeCommand, bool, error) {
	var c model.CapacityNativeCommand
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return c, false, err
	}
	if s.DB == nil {
		return c, false, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return c, false, err
	}
	defer tx.Rollback()
	recovery, err := nativeAbortRecoveryPresent(ctx, tx, uid)
	if err != nil {
		return c, true, err
	}
	if recovery {
		c, _, err = nativeAbortRecoveryPair(ctx, tx, policy, p, uid, false)
		return c, true, err
	}
	var count int
	var idText sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT count(*),min(id::text) FROM public.capacity_native_command_identities WHERE subject_uid=$1 AND operation=$2`, uid, capacity.DestroyNativeUnregisteredProtection).Scan(&count, &idText); err != nil {
		return c, false, err
	}
	if count == 0 {
		var orphan int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 AND operation=$2`, uid, capacity.DestroyNativeUnregisteredProtection).Scan(&orphan); err != nil {
			return c, false, err
		}
		if orphan != 0 {
			return c, true, ErrCapacityConflict
		}
		return c, false, nil
	}
	if count != 1 || !idText.Valid {
		return c, true, ErrCapacityConflict
	}
	id, err := uuid.Parse(idText.String)
	if err != nil {
		return c, true, ErrCapacityConflict
	}
	c, _, err = nativeAbortStored(ctx, tx, policy, p, id, false)
	return c, true, err
}
func (s CapacityStore) nativeAbortInitial(ctx context.Context, id uuid.UUID) (model.Manifest, model.CapacityNativeCommand, model.CapacityNativeAbortBinding, error) {
	var c model.CapacityNativeCommand
	var req model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	var raw []byte
	if s.DB == nil || s.DB.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, id).Scan(&raw) != nil || json.Unmarshal(raw, &c) != nil || capacity.DecodeNativeCapacity(c.Request, &req) != nil {
		return model.Manifest{}, c, req.Proof.Binding, ErrCapacityConflict
	}
	policy, err := GetManifestByID(ctx, s.DB, c.PolicyID)
	return policy, c, req.Proof.Binding, err
}
func nativeAbortCurrent(c model.CapacityNativeCommand, current model.CapacityIntent, now time.Time) error {
	if c.IntentGeneration != current.Generation || c.FencingToken != current.FencingToken || c.LeaseOwner != current.LeaseOwner || c.ExecutorID != current.LeaseExecutorID || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(time.Now()) || current.LeaseExpiresAt == nil || c.ExpiresAt.After(*current.LeaseExpiresAt) {
		return ErrCapacityLease
	}
	return nil
}
func nativeAbortWrite(ctx context.Context, tx *sql.Tx, c model.CapacityNativeCommand) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_commands SET state=$2,command_record=$3,updated_at=$4 WHERE id=$1`, c.CommandID, c.State, raw, c.UpdatedAt)
	return err
}
func (s CapacityStore) RedeemNativePreRegistrationAbort(ctx context.Context, principal string, r model.CapacityNativeAuthorityRedeemRequest) (model.CapacityNativeAuthorityPermit, error) {
	var permit model.CapacityNativeAuthorityPermit
	decoded, err := hex.DecodeString(r.AuthorityToken)
	if err != nil || len(decoded) != 32 || strings.ToLower(r.AuthorityToken) != r.AuthorityToken {
		return permit, ErrCapacityMutationAuthorization
	}
	clear(decoded)
	if s.DB == nil {
		return permit, ErrCapacityMutationAuthorization
	}
	hash := nativeArchiveSHA([]byte(r.AuthorityToken))
	var id uuid.UUID
	if s.DB.QueryRowContext(ctx, `SELECT id FROM public.capacity_native_commands WHERE authority_token_sha256=$1`, hash).Scan(&id) != nil {
		return permit, ErrCapacityMutationAuthorization
	}
	if recovery, err := nativeAbortRecoverySelected(ctx, s.DB, id); err != nil {
		return permit, err
	} else if recovery {
		return s.redeemNativePreRegistrationAbortRecovery(ctx, principal, r)
	}
	policy, initial, b, err := s.nativeAbortInitial(ctx, id)
	if err != nil {
		return permit, err
	}
	s.WorkflowID, s.ExecutorID, s.AdmissionOnly = initial.WorkflowID, initial.ExecutorID, false
	expected := model.CapacityIntent{Generation: initial.IntentGeneration, FencingToken: initial.FencingToken, LeaseOwner: initial.LeaseOwner}
	_, err = s.nativeAbortTransaction(ctx, policy, b, &expected, false, false, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortStored(ctx, tx, policy, p, id, true)
		if err != nil {
			return err
		}
		if c.State != "issued" || c.AuthorityTokenSHA256 != hash || principal != b.AdapterPrincipalID || r.IntegrationInstanceID != b.Adapter.IntegrationInstanceID || r.IntegrationTypeID != b.Adapter.IntegrationTypeID || r.Capability != c.Operation || r.RequestSHA256 != c.RequestSHA256 || r.ReleaseProtocol != c.ReleaseProtocol || r.AdapterSourceCommit != c.AdapterSourceCommit {
			return ErrCapacityMutationAuthorization
		}
		if err = nativeAbortCurrent(c, *current, now); err != nil {
			return err
		}
		c.State, c.RedeemedBy, c.AttemptID, c.UpdatedAt = "redeemed", principal, uuid.New(), now
		nonce, err := retainNativeReleaseRedemption(ctx, tx, c)
		if err != nil {
			return err
		}
		if err = nativeAbortWrite(ctx, tx, c); err != nil {
			return err
		}
		permit = model.CapacityNativeAuthorityPermit{SchemaVersion: 1, CommandID: c.CommandID, AttemptID: c.AttemptID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, ExpiresAt: c.ExpiresAt, ReleaseProtocol: c.ReleaseProtocol, AdapterSourceCommit: c.AdapterSourceCommit, ReturnNonce: nonce}
		return nil
	})
	if err != nil {
		return model.CapacityNativeAuthorityPermit{}, err
	}
	return permit, nil
}
func nativeAbortResultComplete(r model.CapacityNativeReleaseResult) bool {
	nonce, e := hex.DecodeString(r.ReturnNonce)
	defer clear(nonce)
	return e == nil && len(nonce) == 32 && r.Protocol == capacity.NativePreRegistrationAbortProtocol && r.Capability == capacity.DestroyNativeUnregisteredProtection && r.CommandID != uuid.Nil && r.AttemptID != uuid.Nil && len(r.RequestSHA256) == 64 && len(r.OriginalResponseSHA256) == 64 && len(r.AdapterSourceCommit) == 40 && r.OneSend && r.DoReturned && r.ReadReturned && r.CloseReturned && ((r.Outcome == "applied" && r.OriginalStatus == 200) || (r.Outcome == "rejected_no_effect" && r.OriginalStatus == 409))
}
func (s CapacityStore) RecordNativePreRegistrationAbortResult(ctx context.Context, principal string, r model.CapacityNativeReleaseResult) error {
	if !nativeAbortResultComplete(r) {
		return ErrCapacityMutationAuthorization
	}
	if recovery, err := nativeAbortRecoverySelected(ctx, s.DB, r.CommandID); err != nil {
		return err
	} else if recovery {
		return s.recordNativePreRegistrationAbortResultRecovery(ctx, principal, r)
	}
	policy, initial, b, err := s.nativeAbortInitial(ctx, r.CommandID)
	if err != nil {
		return err
	}
	s.WorkflowID, s.ExecutorID, s.AdmissionOnly = initial.WorkflowID, initial.ExecutorID, false
	expected := model.CapacityIntent{Generation: initial.IntentGeneration, FencingToken: initial.FencingToken, LeaseOwner: initial.LeaseOwner}
	deadline := initial.ExpiresAt
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = nativeReleaseRecordDeadline(ctx, deadline); err != nil {
		return err
	}
	_, err = s.nativeAbortTransaction(ctx, policy, b, &expected, false, false, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortStored(ctx, tx, policy, p, r.CommandID, true)
		if err != nil {
			return err
		}
		if (c.State != "redeemed" && c.State != "uncertain") || c.AttemptID != r.AttemptID || c.RedeemedBy != principal || principal != b.AdapterPrincipalID || r.IntegrationInstanceID != c.Adapter.IntegrationInstanceID || r.IntegrationTypeID != c.Adapter.IntegrationTypeID || r.Capability != c.Operation || r.RequestSHA256 != c.RequestSHA256 || r.Protocol != c.ReleaseProtocol || r.AdapterSourceCommit != c.AdapterSourceCommit {
			return ErrCapacityMutationAuthorization
		}
		if err = nativeAbortCurrent(c, *current, now); err != nil {
			return err
		}
		var hash string
		var previous []byte
		var ack sql.NullTime
		if err = tx.QueryRowContext(ctx, `SELECT return_nonce_sha256,adapter_result,adapter_ack_at FROM public.capacity_native_release_results WHERE command_id=$1 AND attempt_id=$2 FOR UPDATE`, c.CommandID, c.AttemptID).Scan(&hash, &previous, &ack); err != nil {
			return err
		}
		if hash != nativeArchiveSHA([]byte(r.ReturnNonce)) {
			return ErrCapacityMutationAuthorization
		}
		r.ReturnNonce = ""
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
	return errors.Join(err, nativeReleaseRecordDeadline(ctx, deadline))
}
func (s CapacityStore) ConfirmNativePreRegistrationAbort(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, id uuid.UUID, response model.AdapterCapacityPodUnregisteredTerminalResponse, callerJoined bool) error {
	if !callerJoined {
		return ErrCapacityConflict
	}
	if recovery, err := nativeAbortRecoverySelected(ctx, s.DB, id); err != nil {
		return err
	} else if recovery {
		return s.confirmNativePreRegistrationAbortRecovery(ctx, policy, intent, id, response, callerJoined)
	}
	_, initial, b, err := s.nativeAbortInitial(ctx, id)
	if err != nil {
		return err
	}
	if initial.WorkflowID != s.WorkflowID || initial.ExecutorID != s.ExecutorID {
		return ErrCapacityMutationAuthorization
	}
	_, err = s.nativeAbortTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortStored(ctx, tx, policy, p, id, true)
		if err != nil {
			return err
		}
		if (c.State != "redeemed" && c.State != "uncertain") || c.AttemptID == uuid.Nil || c.RedeemedBy != b.AdapterPrincipalID || capacity.ValidateNativeAbortRemoval(p, b, response, now) != nil {
			return ErrCapacityConflict
		}
		if err = nativeAbortCurrent(c, *current, now); err != nil {
			return err
		}
		var result []byte
		var digest string
		var ack sql.NullTime
		if err = tx.QueryRowContext(ctx, `SELECT adapter_result,adapter_result_sha256,adapter_ack_at FROM public.capacity_native_release_results WHERE command_id=$1 AND attempt_id=$2 AND protocol=$3 AND adapter_source_commit=$4 FOR UPDATE`, c.CommandID, c.AttemptID, c.ReleaseProtocol, c.AdapterSourceCommit).Scan(&result, &digest, &ack); err != nil {
			return err
		}
		var r model.CapacityNativeReleaseResult
		if !ack.Valid || capacity.DecodeNativeCapacity(json.RawMessage(result), &r) != nil || digest != nativeCanonicalArchiveSHA(result) || r.ReturnNonce != "" || r.CommandID != c.CommandID || r.AttemptID != c.AttemptID || r.Protocol != c.ReleaseProtocol || r.Capability != c.Operation || r.IntegrationInstanceID != c.Adapter.IntegrationInstanceID || r.IntegrationTypeID != c.Adapter.IntegrationTypeID || r.AdapterSourceCommit != c.AdapterSourceCommit || r.RequestSHA256 != c.RequestSHA256 || r.Outcome != "applied" || r.OriginalStatus != 200 || !r.OneSend || !r.DoReturned || !r.ReadReturned || !r.CloseReturned {
			return ErrCapacityConflict
		}
		readback, err := json.Marshal(response)
		if err != nil || len(readback) > 32768 {
			return ErrCapacityConflict
		}
		c.State, c.NativeReadback, c.OriginalResult, c.OriginalResultSHA256, c.CallerReturnObservedAt, c.UpdatedAt = "confirmed", readback, result, digest, &now, now
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_release_results SET caller_ack_at=$2 WHERE command_id=$1 AND caller_ack_at IS NULL`, id, now); err != nil {
			return err
		}
		return nativeAbortWrite(ctx, tx, c)
	})
	return err
}
func (s CapacityStore) ArchiveNativePreRegistrationAbort(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, id uuid.UUID) error {
	if recovery, err := nativeAbortRecoverySelected(ctx, s.DB, id); err != nil {
		return err
	} else if recovery {
		return s.archiveNativePreRegistrationAbortRecovery(ctx, policy, intent, id)
	}
	_, _, b, err := s.nativeAbortInitial(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.nativeAbortTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortStored(ctx, tx, policy, p, id, true)
		if err != nil {
			return err
		}
		if c.State != "confirmed" || c.CallerReturnObservedAt == nil || c.OriginalResultSHA256 != nativeCanonicalArchiveSHA(c.OriginalResult) || c.WorkflowID != s.WorkflowID || c.ExecutorID != s.ExecutorID {
			return ErrCapacityConflict
		}
		if err = nativeAbortCurrent(c, *current, now); err != nil {
			return err
		}
		return archiveNativeCommand(ctx, tx, c)
	})
	return err
}
