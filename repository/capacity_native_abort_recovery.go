package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const nativeAbortRecoveryOperation = "capacity.recover_unredeemed_native_birth"

// This administrative path has its own exact, persisted human workflow. It
// never makes an ordinary abort or policy workflow a recovery authority.
func nativeAbortRecoveryWorkflow(ctx context.Context, tx *sql.Tx, id uuid.UUID, policy model.Manifest, b model.CapacityNativeAbortRecoveryBinding) error {
	var raw []byte
	if id == uuid.Nil || tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND active FOR SHARE`, id, policy.Metadata.Namespace).Scan(&raw) != nil {
		return ErrCapacityMutationAuthorization
	}
	var workflow map[string]json.RawMessage
	var dispatch string
	var trigger map[string]string
	var authorization map[string]json.RawMessage
	var steps []map[string]json.RawMessage
	if json.Unmarshal(raw, &workflow) != nil || json.Unmarshal(workflow["dispatch_mode"], &dispatch) != nil || dispatch != "sync" || json.Unmarshal(workflow["trigger"], &trigger) != nil || len(trigger) != 1 || trigger["mode"] != "manual" || json.Unmarshal(workflow["authorization"], &authorization) != nil || len(authorization) == 0 || json.Unmarshal(workflow["steps"], &steps) != nil || len(steps) != 1 {
		return ErrCapacityMutationAuthorization
	}
	step := steps[0]
	if len(step) != 5 {
		return ErrCapacityMutationAuthorization
	}
	for key := range step {
		switch key {
		case "id", "use", "with", "retry", "timeout_seconds":
		default:
			return ErrCapacityMutationAuthorization
		}
	}
	var name string
	var timeout int
	var retry map[string]int
	var use map[string]string
	var with map[string]json.RawMessage
	if json.Unmarshal(step["id"], &name) != nil || name == "" || json.Unmarshal(step["timeout_seconds"], &timeout) != nil || timeout != 90 || json.Unmarshal(step["retry"], &retry) != nil || len(retry) != 1 || retry["max_attempts"] != 1 || json.Unmarshal(step["use"], &use) != nil || len(use) != 2 || use["kind"] != "yggdrasil" || use["operation"] != nativeAbortRecoveryOperation || json.Unmarshal(step["with"], &with) != nil || len(with) != 2 || bytes.Contains(with["binding"], []byte("{{")) {
		return ErrCapacityMutationAuthorization
	}
	var literal model.CapacityNativeAbortRecoveryBinding
	var confirmation string
	left, err := nativeAbortCanonical(b)
	if err != nil || capacity.DecodeNativeCapacity(with["binding"], &literal) != nil {
		return ErrCapacityMutationAuthorization
	}
	right, err := nativeAbortCanonical(literal)
	if err != nil || !bytes.Equal(left, right) || json.Unmarshal(with["confirmation"], &confirmation) != nil || (confirmation != b.Native.Confirmation && confirmation != "{{ inputs.confirmation }}") {
		return ErrCapacityMutationAuthorization
	}
	return nil
}
func (s CapacityStore) nativeAbortRecoveryTransaction(ctx context.Context, policy model.Manifest, b model.CapacityNativeAbortRecoveryBinding, expected *model.CapacityIntent, resume, human bool, fn func(*sql.Tx, model.CapacityPolicySpec, *model.CapacityIntent, time.Time) error) (model.CapacityIntent, error) {
	var current model.CapacityIntent
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return current, err
	}
	if s.DB == nil || !s.ExecutionEnabled || !p.ExecutionEnabled || s.AdmissionOnly || len(p.MutationBindings) != 0 || !validCapacityExecutor(s.ExecutorID) || capacity.ValidateNativeAbortRecoveryBinding(policy, p, b) != nil || (human && (s.ExecutorPowerOperator == "" || s.ExecutorPowerOperator != b.Native.OperatorID)) {
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
	if err = nativeAbortRecoveryWorkflow(ctx, tx, s.WorkflowID, policy, b); err != nil {
		return current, err
	}
	if err = checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(b.Native.Adapter)); err != nil {
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
	if failedServingQuarantineBlocks(&current) || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.PolicyName != policy.Metadata.Name || current.Generation != b.Native.Generation || current.RecoveryOnly || !pendingCapacityPhase(current.Phase) || current.Phase == "proposed" || current.WitnessedUnenrolledExpansionCleanupID != "" || current.FailedUnwitnessedExpansionCleanupID != "" || current.WitnessedExpansionTerminalReconcile != nil || current.FailedExpansionTerminalReconcile != nil || current.InstalledReadinessHandoff != nil || current.FailedInstalledDisposal != nil {
		return current, ErrCapacityConflict
	}
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return current, err
	}
	if resume {
		if current.FencingToken != b.ExpectedIntentFencingToken || current.FencingToken >= maxCapacityGeneration || (current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(now)) {
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
		if expected == nil || current.FencingToken != b.ExpectedIntentFencingToken+1 {
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, current.Phase, "native:unredeemed-abort-recovery-lease-only"); err != nil {
			return current, err
		}
	}
	if ctx.Err() != nil {
		return current, ctx.Err()
	}
	return current, tx.Commit()
}

func nativeAbortRecoveryAbsent(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func nativeAbortRecoveryNoEffect(c model.CapacityNativeCommand) bool {
	return c.AttemptID == uuid.Nil && c.RedeemedBy == "" && nativeAbortRecoveryAbsent(c.NativeReadback) && nativeAbortRecoveryAbsent(c.OriginalResult) && c.OriginalResultSHA256 == "" && c.CallerReturnObservedAt == nil && c.ParentCommandID == "" && c.ParentAttemptID == "" && c.RecoveryDecisionID == "" && c.RecoveryFence == ""
}

// A custody digest never enters public bindings/proofs. The original request
// and token hash are compared only with their permanent server-side identity.
func nativeAbortRecoverySameTarget(a, b model.CapacityNativeAbortBinding) bool {
	a.Adapter, b.Adapter = model.CapacityObservationAdapterBinding{}, model.CapacityObservationAdapterBinding{}
	a.AdapterPrincipalID, b.AdapterPrincipalID = "", ""
	a.AdapterSourceCommit, b.AdapterSourceCommit = "", ""
	a.OperatorID, b.OperatorID = "", ""
	a.Confirmation, b.Confirmation = "", ""
	return a == b
}

func nativeAbortRecoverySameObservation(a, b model.NativePreRegistrationAbortObservation) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	a.WorkloadResourceVersion, b.WorkloadResourceVersion = "", ""
	x, e1 := nativeAbortCanonical(a)
	y, e2 := nativeAbortCanonical(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

// Count direct HOT/archive bodies as well as identities. An orphan or a body
// whose public target disagrees with its SQL subject cannot disappear in a JOIN.
func nativeAbortRecoveryHistory(ctx context.Context, tx *sql.Tx, uid string) (model.CapacityNativeAbortZeroHistory, error) {
	var z model.CapacityNativeAbortZeroHistory
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),
 (SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 OR command_record->'request'->>'expected_pod_uid'=$1),
 (SELECT count(*) FROM public.capacity_native_command_archive a LEFT JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1 OR a.command_record->'request'->>'expected_pod_uid'=$1)`, uid).Scan(&z.Lifetimes, &z.LifetimeArchives, &z.LegacyCheckpoints, &z.CommandIdentities, &z.HotCommands, &z.ArchivedCommands)
	return z, err
}
func nativeAbortRecoveryPending(ctx context.Context, tx *sql.Tx, c model.CapacityIntent, p model.CapacityPolicySpec) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','uncertain')`, c.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&n)
	return n, err
}
func nativeAbortRecoveryNoResult(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	var n int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1)+(SELECT count(*) FROM public.capacity_native_release_recovery_decisions WHERE parent_command_id=$1 OR command_id=$1)`, id).Scan(&n) != nil || n != 0 {
		return ErrCapacityConflict
	}
	return nil
}

// Bind every mutable HOT SQL identity column to the already verified canonical
// record and immutable identity. Old MarkUncertain may update only SQL's clock,
// so updated_at is deliberately not substituted for original record custody.
func nativeAbortRecoveryHotIdentity(ctx context.Context, tx *sql.Tx, c model.CapacityNativeCommand, uid string) error {
	var ns, env, domain, dimension, operation, subject, phase, state, token string
	var generation int64
	var sequence int
	if uid == "" || tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256 FROM public.capacity_native_commands WHERE id=$1`, c.CommandID).Scan(&ns, &env, &domain, &dimension, &generation, &operation, &subject, &phase, &sequence, &state, &token) != nil || ns != c.Namespace || env != c.Environment || domain != c.Domain || dimension != c.Dimension || generation != c.IntentGeneration || operation != c.Operation || subject != uid || phase != c.Phase || sequence != c.Sequence || state != c.State || token != c.AuthorityTokenSHA256 {
		return ErrCapacityConflict
	}
	return nil
}

func nativeAbortRecoveryParent(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortRecoveryBinding, now time.Time) (model.CapacityNativeCommand, model.AdapterDestroyCapacityPodUnregisteredProtectionRequest, error) {
	id, err := uuid.Parse(b.ParentCommandID)
	if err != nil {
		return model.CapacityNativeCommand{}, model.AdapterDestroyCapacityPodUnregisteredProtectionRequest{}, ErrCapacityConflict
	}
	parent, request, err := nativeAbortStored(ctx, tx, policy, p, id, true)
	if err != nil {
		return parent, request, err
	}
	if nativeAbortRecoveryHotIdentity(ctx, tx, parent, b.Native.PodUID) != nil {
		return parent, request, ErrCapacityConflict
	}
	var hot, archived int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1 AND state='uncertain'),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1)`, id).Scan(&hot, &archived) != nil || hot != 1 || archived != 0 || parent.State != "uncertain" || !nativeAbortRecoveryNoEffect(parent) || parent.FencingToken != b.ParentFencingToken || !parent.ExpiresAt.Equal(b.ParentExpiresAt) || !parent.ExpiresAt.Before(now) || !nativeAbortRecoverySameTarget(request.Proof.Binding, b.Native) || nativeAbortRecoveryNoResult(ctx, tx, id) != nil {
		return parent, request, ErrCapacityConflict
	}
	z, err := nativeAbortRecoveryHistory(ctx, tx, b.Native.PodUID)
	if err != nil || z != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, HotCommands: 1}) {
		return parent, request, ErrCapacityConflict
	}
	return parent, request, nil
}

func (s CapacityStore) ResumeNativePreRegistrationAbortRecovery(ctx context.Context, policy model.Manifest, b model.CapacityNativeAbortRecoveryBinding) (model.CapacityIntent, error) {
	return s.nativeAbortRecoveryTransaction(ctx, policy, b, nil, true, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		if _, _, err := nativeAbortRecoveryParent(ctx, tx, policy, p, b, now); err != nil {
			return err
		}
		n, err := nativeAbortRecoveryPending(ctx, tx, *current, p)
		if err != nil || n != 1 {
			return ErrCapacityConflict
		}
		return nil
	})
}

func (s CapacityStore) IssueNativePreRegistrationAbortRecovery(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, b model.CapacityNativeAbortRecoveryBinding, o model.NativePreRegistrationAbortObservation) (model.CapacityNativeCommand, string, error) {
	var child model.CapacityNativeCommand
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return child, "", err
	}
	token := hex.EncodeToString(secret)
	clear(secret)
	_, err := s.nativeAbortRecoveryTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		parent, original, err := nativeAbortRecoveryParent(ctx, tx, policy, p, b, now)
		if err != nil {
			return err
		}
		n, err := nativeAbortRecoveryPending(ctx, tx, *current, p)
		if err != nil || n != 1 || capacity.ValidateNativeAbortObservation(p, b.Native, o, now, true) != nil || !nativeAbortRecoverySameObservation(original.Proof.Observation, o) {
			return ErrCapacityConflict
		}
		before := parent
		parent.State, parent.UpdatedAt = "refused_no_redemption", now
		immutable := parent
		immutable.State, immutable.UpdatedAt = before.State, before.UpdatedAt
		if !reflect.DeepEqual(immutable, before) {
			return ErrCapacityConflict
		}
		if err = nativeAbortWrite(ctx, tx, parent); err != nil {
			return err
		}
		if err = archiveNativeCommand(ctx, tx, parent); err != nil {
			return err
		}
		retained, _, err := nativeAbortStored(ctx, tx, policy, p, parent.CommandID, false)
		var hot, archived int
		if err != nil || !reflect.DeepEqual(retained, parent) || tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1)`, parent.CommandID).Scan(&hot, &archived) != nil || hot != 0 || archived != 1 {
			return ErrCapacityConflict
		}
		history, err := nativeAbortRecoveryHistory(ctx, tx, b.Native.PodUID)
		pending, e := nativeAbortRecoveryPending(ctx, tx, *current, p)
		if err != nil || e != nil || history != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, ArchivedCommands: 1}) || pending != 0 {
			return ErrCapacityConflict
		}
		proof := model.CapacityNativeAbortRecoveryProof{Schema: capacity.NativePreRegistrationAbortRecoverySchema, Binding: b, Observation: o, History: history, ScopeUnsettledCommands: 0, Lineage: model.CapacityNativeAbortRecoveryLineage{ParentCommandID: b.ParentCommandID, ParentSequence: 1, PriorState: "uncertain", AdministrativeState: "refused_no_redemption", ParentFencingToken: b.ParentFencingToken, ParentExpiresAt: b.ParentExpiresAt, DispositionAt: now}, FencingToken: current.FencingToken, AuthoredAt: now}
		if capacity.ValidateNativeAbortRecoveryProof(policy, p, proof, now) != nil {
			return ErrCapacityConflict
		}
		no := false
		request := model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest{ExpectedPodUID: b.Native.PodUID, ExpectedPodResourceVersion: o.PodResourceVersion, Proof: proof, DryRun: &no}
		raw, err := nativeAbortCanonical(request)
		if err != nil || len(raw) > 32768 {
			return ErrCapacityConflict
		}
		child = model.CapacityNativeCommand{CommandID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID, Namespace: current.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, IntentGeneration: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: s.ExecutorID, Adapter: b.Native.Adapter, AdapterPrincipalID: b.Native.AdapterPrincipalID, Operation: capacity.DestroyNativeUnregisteredProtection, Phase: capacity.NativePreRegistrationAbortPhase, Sequence: 2, Request: raw, RequestSHA256: nativeArchiveSHA(raw), State: "issued", AuthorityTokenSHA256: nativeArchiveSHA([]byte(token)), CreatedAt: now, ExpiresAt: *current.LeaseExpiresAt, UpdatedAt: now, OriginPolicy: append(json.RawMessage(nil), policy.Spec...), OriginPolicySHA256: nativeCanonicalArchiveSHA(policy.Spec), ReleaseProtocol: capacity.NativePreRegistrationAbortProtocol, AdapterSourceCommit: b.Native.AdapterSourceCommit, ParentCommandID: b.ParentCommandID}
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(child.ExpiresAt) {
			child.ExpiresAt = deadline
		}
		child.ExpiresAt = child.ExpiresAt.UTC().Truncate(time.Microsecond)
		if !child.ExpiresAt.After(now) {
			return ErrCapacityLease
		}
		record, err := json.Marshal(child)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, child.CommandID, child.Namespace, child.Environment, child.Domain, child.Dimension, child.IntentGeneration, child.Operation, b.Native.PodUID, child.Phase, child.Sequence, child.AuthorityTokenSHA256, child.RequestSHA256); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, child.CommandID, child.Namespace, child.Environment, child.Domain, child.Dimension, child.IntentGeneration, child.Operation, b.Native.PodUID, child.Phase, child.Sequence, child.State, child.AuthorityTokenSHA256, record, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, current.Phase, "native:unredeemed-abort:uncertain:refused_no_redemption:"+parent.CommandID.String()+":"+child.CommandID.String())
		return err
	})
	if err != nil {
		return model.CapacityNativeCommand{}, "", err
	}
	return child, token, nil
}

func nativeAbortRecoverySelected(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	if db == nil {
		return false, ErrCapacityConflict
	}
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 UNION ALL SELECT command_record FROM public.capacity_native_command_archive WHERE id=$1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var command struct {
		Sequence int `json:"sequence"`
		Request  struct {
			Proof struct {
				Schema string `json:"schema"`
			} `json:"proof"`
		} `json:"request"`
	}
	if json.Unmarshal(raw, &command) != nil {
		return false, ErrCapacityConflict
	}
	return command.Sequence == 2 || command.Request.Proof.Schema == capacity.NativePreRegistrationAbortRecoverySchema, nil
}
func nativeAbortRecoveryPresent(ctx context.Context, tx *sql.Tx, uid string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT
	(SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1 AND operation=$3 AND sequence<>1)+
	(SELECT count(*) FROM public.capacity_native_commands WHERE (subject_uid=$1 OR command_record->'request'->>'expected_pod_uid'=$1) AND ((operation=$3 AND sequence<>1) OR command_record->'request'->'proof'->>'schema'=$2))+
	(SELECT count(*) FROM public.capacity_native_command_archive WHERE command_record->'request'->>'expected_pod_uid'=$1 AND (((command_record->>'operation')=$3 AND (command_record->>'sequence')<>'1') OR command_record->'request'->'proof'->>'schema'=$2))`, uid, capacity.NativePreRegistrationAbortRecoverySchema, capacity.DestroyNativeUnregisteredProtection).Scan(&n)
	return n != 0, err
}
func nativeAbortRecoveryBody(ctx context.Context, tx *sql.Tx, id uuid.UUID, lock bool) (model.CapacityNativeCommand, bool, error) {
	var c model.CapacityNativeCommand
	var raw []byte
	var state, token string
	query := `SELECT command_record,state,authority_token_sha256 FROM public.capacity_native_commands WHERE id=$1`
	if lock {
		query += " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, query, id).Scan(&raw, &state, &token)
	archived := false
	if errors.Is(err, sql.ErrNoRows) {
		var digest string
		err = tx.QueryRowContext(ctx, `SELECT command_record,record_sha256 FROM public.capacity_native_command_archive WHERE id=$1`, id).Scan(&raw, &digest)
		if err != nil || digest != nativeCanonicalArchiveSHA(raw) {
			return c, true, ErrCapacityConflict
		}
		archived = true
	}
	if err != nil || json.Unmarshal(raw, &c) != nil || c.CommandID != id {
		return c, archived, ErrCapacityConflict
	}
	if !archived && (c.State != state || c.AuthorityTokenSHA256 != token) {
		return c, false, ErrCapacityConflict
	}
	if !archived {
		var target struct {
			UID string `json:"expected_pod_uid"`
		}
		if json.Unmarshal(c.Request, &target) != nil || nativeAbortRecoveryHotIdentity(ctx, tx, c, target.UID) != nil {
			return c, false, ErrCapacityConflict
		}
	}
	var copies int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1)+(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1)`, id).Scan(&copies) != nil || copies != 1 {
		return c, archived, ErrCapacityConflict
	}
	return c, archived, nil
}
func nativeAbortRecoveryIdentity(ctx context.Context, tx *sql.Tx, c model.CapacityNativeCommand, uid string) error {
	var ns, env, domain, dimension, op, subject, phase, token, digest string
	var generation int64
	var sequence int
	if tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256 FROM public.capacity_native_command_identities WHERE id=$1`, c.CommandID).Scan(&ns, &env, &domain, &dimension, &generation, &op, &subject, &phase, &sequence, &token, &digest) != nil || ns != c.Namespace || env != c.Environment || domain != c.Domain || dimension != c.Dimension || generation != c.IntentGeneration || op != c.Operation || subject != uid || phase != c.Phase || sequence != c.Sequence || token != c.AuthorityTokenSHA256 || digest != c.RequestSHA256 || len(token) != 64 {
		return ErrCapacityConflict
	}
	return nil
}
func nativeAbortRecoveryPair(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, uid string, lock bool) (model.CapacityNativeCommand, model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest, error) {
	var child model.CapacityNativeCommand
	var request model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
	rows, err := tx.QueryContext(ctx, `SELECT id,sequence,operation,phase FROM public.capacity_native_command_identities WHERE subject_uid=$1 ORDER BY sequence,id`, uid)
	if err != nil {
		return child, request, err
	}
	var parentID, childID uuid.UUID
	count := 0
	valid := true
	for rows.Next() {
		var id uuid.UUID
		var sequence int
		var operation, phase string
		if rows.Scan(&id, &sequence, &operation, &phase) != nil {
			valid = false
			break
		}
		count++
		if operation != capacity.DestroyNativeUnregisteredProtection || phase != capacity.NativePreRegistrationAbortPhase {
			valid = false
		}
		if sequence == 1 && parentID == uuid.Nil {
			parentID = id
		} else if sequence == 2 && childID == uuid.Nil {
			childID = id
		} else {
			valid = false
		}
	}
	rowErr := rows.Err()
	_ = rows.Close()
	if rowErr != nil {
		return child, request, rowErr
	}
	if !valid || count != 2 || parentID == uuid.Nil || childID == uuid.Nil {
		return child, request, ErrCapacityConflict
	}
	child, archived, err := nativeAbortRecoveryBody(ctx, tx, childID, lock)
	if err != nil || capacity.DecodeNativeCapacity(child.Request, &request) != nil {
		return child, request, ErrCapacityConflict
	}
	proof, b := request.Proof, request.Proof.Binding
	canonical, e := nativeAbortCanonical(request)
	if e != nil || child.PolicyID != policy.ID || child.PolicyChecksum != policy.Checksum || child.Namespace != policy.Metadata.Namespace || child.Environment != p.Environment || child.Domain != p.Domain || child.Dimension != p.Dimension || child.Operation != capacity.DestroyNativeUnregisteredProtection || child.Phase != capacity.NativePreRegistrationAbortPhase || child.Sequence != 2 || child.ParentCommandID != parentID.String() || child.ParentAttemptID != "" || child.RecoveryDecisionID != "" || child.RecoveryFence != "" || b.ParentCommandID != parentID.String() || uid != b.Native.PodUID || request.ExpectedPodUID != uid || request.ExpectedPodResourceVersion != proof.Observation.PodResourceVersion || request.DryRun == nil || *request.DryRun || request.AuthorityToken != "" || child.IntentGeneration != b.Native.Generation || child.FencingToken != proof.FencingToken || !child.CreatedAt.Equal(proof.AuthoredAt) || !child.ExpiresAt.After(child.CreatedAt) || child.Adapter != b.Native.Adapter || child.AdapterPrincipalID != b.Native.AdapterPrincipalID || child.AdapterSourceCommit != b.Native.AdapterSourceCommit || child.ReleaseProtocol != capacity.NativePreRegistrationAbortProtocol || child.AdmissionOnly || child.RequestSHA256 != nativeArchiveSHA(canonical) || child.OriginPolicySHA256 != nativeCanonicalArchiveSHA(child.OriginPolicy) || child.OriginPolicySHA256 != nativeCanonicalArchiveSHA(policy.Spec) || capacity.ValidateNativeAbortRecoveryProof(policy, p, proof, proof.AuthoredAt) != nil || nativeAbortRecoveryIdentity(ctx, tx, child, uid) != nil {
		return child, request, ErrCapacityConflict
	}
	parent, original, e := nativeAbortStored(ctx, tx, policy, p, parentID, false)
	var parentHot, parentArchive int
	if e != nil || parent.State != "refused_no_redemption" || !nativeAbortRecoveryNoEffect(parent) || parent.FencingToken != b.ParentFencingToken || !parent.ExpiresAt.Equal(b.ParentExpiresAt) || !parent.UpdatedAt.Equal(proof.AuthoredAt) || !nativeAbortRecoverySameTarget(original.Proof.Binding, b.Native) || !nativeAbortRecoverySameObservation(original.Proof.Observation, proof.Observation) || nativeAbortRecoveryNoResult(ctx, tx, parentID) != nil || tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_commands WHERE id=$1),(SELECT count(*) FROM public.capacity_native_command_archive WHERE id=$1)`, parentID).Scan(&parentHot, &parentArchive) != nil || parentHot != 0 || parentArchive != 1 {
		return child, request, ErrCapacityConflict
	}
	history, e := nativeAbortRecoveryHistory(ctx, tx, uid)
	expected := model.CapacityNativeAbortZeroHistory{CommandIdentities: 2, HotCommands: 1, ArchivedCommands: 1}
	if archived {
		expected.HotCommands, expected.ArchivedCommands = 0, 2
	}
	if e != nil || history != expected {
		return child, request, ErrCapacityConflict
	}
	// The retained owner is a global realm fence, including for archived audits.
	var owner []byte
	scope, _ := json.Marshal([]string{policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, policy.Metadata.Name})
	if tx.QueryRowContext(ctx, `SELECT owner_scope FROM public.capacity_native_scope_owners WHERE native_uid=$1`, uid).Scan(&owner) != nil || nativeCanonicalArchiveSHA(owner) != nativeCanonicalArchiveSHA(scope) {
		return child, request, ErrCapacityConflict
	}
	var resultCount int
	var foreignDecision int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_recovery_decisions WHERE parent_command_id=$1 OR command_id=$1`, childID).Scan(&foreignDecision) != nil || foreignDecision != 0 {
		return child, request, ErrCapacityConflict
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1`, childID).Scan(&resultCount) != nil {
		return child, request, ErrCapacityConflict
	}
	if child.AttemptID == uuid.Nil {
		if resultCount != 0 || child.RedeemedBy != "" || !nativeAbortRecoveryAbsent(child.NativeReadback) || !nativeAbortRecoveryAbsent(child.OriginalResult) || child.OriginalResultSHA256 != "" || child.CallerReturnObservedAt != nil || (child.State != "issued" && child.State != "uncertain") {
			return child, request, ErrCapacityConflict
		}
	} else if resultCount != 1 || child.RedeemedBy != b.Native.AdapterPrincipalID || (child.State != "redeemed" && child.State != "uncertain" && child.State != "confirmed") {
		return child, request, ErrCapacityConflict
	}
	if archived && child.State != "confirmed" {
		return child, request, ErrCapacityConflict
	}
	if child.State == "confirmed" && nativeAbortConfirmed(ctx, tx, p, child, b.Native) != nil {
		return child, request, ErrCapacityConflict
	}
	return child, request, nil
}
func nativeAbortRecoveryStored(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id uuid.UUID, lock bool) (model.CapacityNativeCommand, model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest, error) {
	var raw []byte
	var req model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
	if tx.QueryRowContext(ctx, `SELECT command_record->'request' FROM public.capacity_native_commands WHERE id=$1 UNION ALL SELECT command_record->'request' FROM public.capacity_native_command_archive WHERE id=$1`, id).Scan(&raw) != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &req) != nil {
		return model.CapacityNativeCommand{}, req, ErrCapacityConflict
	}
	child, request, err := nativeAbortRecoveryPair(ctx, tx, policy, p, req.ExpectedPodUID, lock)
	if err != nil || child.CommandID != id {
		return child, request, ErrCapacityConflict
	}
	return child, request, nil
}
func (s CapacityStore) nativeAbortRecoveryInitial(ctx context.Context, id uuid.UUID) (model.Manifest, model.CapacityNativeCommand, model.CapacityNativeAbortRecoveryBinding, error) {
	var c model.CapacityNativeCommand
	var req model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
	var raw []byte
	if s.DB == nil || s.DB.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1`, id).Scan(&raw) != nil || json.Unmarshal(raw, &c) != nil || c.Sequence != 2 || capacity.DecodeNativeCapacity(c.Request, &req) != nil {
		return model.Manifest{}, c, req.Proof.Binding, ErrCapacityConflict
	}
	policy, err := GetManifestByID(ctx, s.DB, c.PolicyID)
	return policy, c, req.Proof.Binding, err
}

func (s CapacityStore) redeemNativePreRegistrationAbortRecovery(ctx context.Context, principal string, r model.CapacityNativeAuthorityRedeemRequest) (model.CapacityNativeAuthorityPermit, error) {
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
	policy, initial, b, err := s.nativeAbortRecoveryInitial(ctx, id)
	if err != nil {
		return permit, err
	}
	s.WorkflowID, s.ExecutorID, s.AdmissionOnly = initial.WorkflowID, initial.ExecutorID, false
	expected := model.CapacityIntent{Generation: initial.IntentGeneration, FencingToken: initial.FencingToken, LeaseOwner: initial.LeaseOwner}
	_, err = s.nativeAbortRecoveryTransaction(ctx, policy, b, &expected, false, false, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortRecoveryStored(ctx, tx, policy, p, id, true)
		if err != nil {
			return err
		}
		if c.State != "issued" || c.AuthorityTokenSHA256 != hash || principal != b.Native.AdapterPrincipalID || r.IntegrationInstanceID != b.Native.Adapter.IntegrationInstanceID || r.IntegrationTypeID != b.Native.Adapter.IntegrationTypeID || r.Capability != c.Operation || r.RequestSHA256 != c.RequestSHA256 || r.ReleaseProtocol != c.ReleaseProtocol || r.AdapterSourceCommit != c.AdapterSourceCommit {
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

func (s CapacityStore) recordNativePreRegistrationAbortResultRecovery(ctx context.Context, principal string, r model.CapacityNativeReleaseResult) error {
	if !nativeAbortResultComplete(r) {
		return ErrCapacityMutationAuthorization
	}
	policy, initial, b, err := s.nativeAbortRecoveryInitial(ctx, r.CommandID)
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
	_, err = s.nativeAbortRecoveryTransaction(ctx, policy, b, &expected, false, false, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortRecoveryStored(ctx, tx, policy, p, r.CommandID, true)
		if err != nil {
			return err
		}
		if (c.State != "redeemed" && c.State != "uncertain") || c.AttemptID != r.AttemptID || c.RedeemedBy != principal || principal != b.Native.AdapterPrincipalID || r.IntegrationInstanceID != c.Adapter.IntegrationInstanceID || r.IntegrationTypeID != c.Adapter.IntegrationTypeID || r.Capability != c.Operation || r.RequestSHA256 != c.RequestSHA256 || r.Protocol != c.ReleaseProtocol || r.AdapterSourceCommit != c.AdapterSourceCommit {
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

func (s CapacityStore) confirmNativePreRegistrationAbortRecovery(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, id uuid.UUID, response model.AdapterCapacityPodUnregisteredTerminalResponse, callerJoined bool) error {
	if !callerJoined {
		return ErrCapacityConflict
	}
	_, initial, b, err := s.nativeAbortRecoveryInitial(ctx, id)
	if err != nil {
		return err
	}
	if initial.WorkflowID != s.WorkflowID || initial.ExecutorID != s.ExecutorID {
		return ErrCapacityMutationAuthorization
	}
	_, err = s.nativeAbortRecoveryTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortRecoveryStored(ctx, tx, policy, p, id, true)
		if err != nil {
			return err
		}
		if (c.State != "redeemed" && c.State != "uncertain") || c.AttemptID == uuid.Nil || c.RedeemedBy != b.Native.AdapterPrincipalID || capacity.ValidateNativeAbortRemoval(p, b.Native, response, now) != nil {
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

func (s CapacityStore) archiveNativePreRegistrationAbortRecovery(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, id uuid.UUID) error {
	_, _, b, err := s.nativeAbortRecoveryInitial(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.nativeAbortRecoveryTransaction(ctx, policy, b, &intent, false, true, func(tx *sql.Tx, p model.CapacityPolicySpec, current *model.CapacityIntent, now time.Time) error {
		if err := lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
			return err
		}
		c, _, err := nativeAbortRecoveryStored(ctx, tx, policy, p, id, true)
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
