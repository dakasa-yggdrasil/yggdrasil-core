package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeAbortQuarantineWorkflow(ctx context.Context, tx *sql.Tx, id uuid.UUID, policy model.Manifest, b model.CapacityNativeAbortQuarantineBinding) error {
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
	if json.Unmarshal(step["id"], &name) != nil || name == "" || json.Unmarshal(step["timeout_seconds"], &timeout) != nil || timeout != 90 || json.Unmarshal(step["retry"], &retry) != nil || len(retry) != 1 || retry["max_attempts"] != 1 || json.Unmarshal(step["use"], &use) != nil || len(use) != 2 || use["kind"] != "yggdrasil" || use["operation"] != capacity.QuarantineUncertainNativeBirth || json.Unmarshal(step["with"], &with) != nil || len(with) != 2 || bytes.Contains(with["binding"], []byte("{{")) {
		return ErrCapacityMutationAuthorization
	}
	var literal model.CapacityNativeAbortQuarantineBinding
	var confirmation string
	left, err := nativeAbortCanonical(b)
	if err != nil || capacity.DecodeNativeCapacity(with["binding"], &literal) != nil {
		return ErrCapacityMutationAuthorization
	}
	right, err := nativeAbortCanonical(literal)
	if err != nil || !bytes.Equal(left, right) || json.Unmarshal(with["confirmation"], &confirmation) != nil || (confirmation != b.Confirmation && confirmation != "{{ inputs.confirmation }}") {
		return ErrCapacityMutationAuthorization
	}
	return nil
}

// The existing command and result seed are deliberately left byte-for-byte
// intact. This snapshot is private custody, never public response metadata.
func nativeAbortQuarantineFacts(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortQuarantineBinding, now time.Time, lock bool) (model.CapacityNativeCommand, string, string, string, error) {
	c, request, err := nativeAbortRecoveryPair(ctx, tx, policy, p, b.Native.PodUID, lock)
	if err != nil || c.CommandID.String() != b.CommandID || c.ParentCommandID != b.ParentCommandID || c.State != "uncertain" || c.Sequence != 2 || c.AttemptID == uuid.Nil || c.RedeemedBy != b.Native.AdapterPrincipalID || c.FencingToken != b.ExpectedIntentFencingToken || !reflect.DeepEqual(request.Proof.Binding.Native, b.Native) || !c.ExpiresAt.Before(now) || !nativeAbortRecoveryAbsent(c.NativeReadback) || !nativeAbortRecoveryAbsent(c.OriginalResult) || c.OriginalResultSHA256 != "" || c.CallerReturnObservedAt != nil {
		return c, "", "", "", ErrCapacityConflict
	}
	parent, archived, e := nativeAbortRecoveryBody(ctx, tx, uuid.MustParse(b.ParentCommandID), false)
	if e != nil || !archived || parent.State != "refused_no_redemption" {
		return c, "", "", "", ErrCapacityConflict
	}
	var childRaw, parentRaw []byte
	if tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR SHARE`, c.CommandID).Scan(&childRaw) != nil || tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_command_archive WHERE id=$1`, parent.CommandID).Scan(&parentRaw) != nil || nativeCanonicalArchiveSHA(childRaw) == "" || nativeCanonicalArchiveSHA(parentRaw) == "" {
		return c, "", "", "", ErrCapacityConflict
	}
	var closedParent, closedChild model.CapacityNativeCommand
	if capacity.DecodeNativeCapacity(json.RawMessage(parentRaw), &closedParent) != nil || capacity.DecodeNativeCapacity(json.RawMessage(childRaw), &closedChild) != nil {
		return c, "", "", "", ErrCapacityConflict
	}
	var raw []byte
	var attempt uuid.UUID
	var protocol, source, nonce string
	var deadline time.Time
	var result []byte
	var resultHash sql.NullString
	var adapterACK, callerACK sql.NullTime
	query := `SELECT row_to_json(r),attempt_id,protocol,adapter_source_commit,return_nonce_sha256,original_deadline,adapter_result,adapter_result_sha256,adapter_ack_at,caller_ack_at FROM public.capacity_native_release_results r WHERE command_id=$1`
	if lock {
		query += " FOR UPDATE"
	} else {
		query += " FOR SHARE"
	}
	if tx.QueryRowContext(ctx, query, c.CommandID).Scan(&raw, &attempt, &protocol, &source, &nonce, &deadline, &result, &resultHash, &adapterACK, &callerACK) != nil || attempt != c.AttemptID || protocol != c.ReleaseProtocol || source != c.AdapterSourceCommit || !deadline.Equal(c.ExpiresAt) || !deadline.Before(now) || len(nonce) != 64 || len(result) != 0 || resultHash.Valid || adapterACK.Valid || callerACK.Valid {
		return c, "", "", "", ErrCapacityConflict
	}
	// SQL primary keys and retained body identities are independently checked.
	var directHot, directArchive, directLegacy int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_native_lifetimes WHERE checkpoint_record->>'pod_uid'=$1),(SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE bundle_record->'checkpoint'->>'pod_uid'=$1),(SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE checkpoint_record->>'pod_uid'=$1)`, b.Native.PodUID).Scan(&directHot, &directArchive, &directLegacy) != nil || directHot != 0 || directArchive != 0 || directLegacy != 0 {
		return c, "", "", "", ErrCapacityConflict
	}
	return c, nativeCanonicalArchiveSHA(parentRaw), nativeCanonicalArchiveSHA(childRaw), nativeCanonicalArchiveSHA(raw), nil
}

// A receipt never settles an uncertain return. Missing/tampered original facts
// or a result/ACK arriving make the receipt unusable, rather than hiding them.
func nativeAbortQuarantineValidated(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id uuid.UUID) (bool, error) {
	var raw []byte
	var digest, uid, ns, env, domain, dimension string
	err := tx.QueryRowContext(ctx, `SELECT quarantine_record,record_sha256,subject_uid,namespace,environment,domain,dimension FROM public.capacity_native_abort_quarantines WHERE command_id=$1`, id).Scan(&raw, &digest, &uid, &ns, &env, &domain, &dimension)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var q model.CapacityNativeAbortQuarantine
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &q) != nil || digest != nativeCanonicalArchiveSHA(raw) || q.Schema != capacity.NativeAbortQuarantineSchema || q.Binding.CommandID != id.String() || uid != q.Binding.Native.PodUID || ns != policy.Metadata.Namespace || env != p.Environment || domain != p.Domain || dimension != p.Dimension || capacity.ValidateNativeAbortQuarantineBinding(policy, p, q.Binding) != nil || !capacity.NativeProcessNonce(q.WorkflowID) || !validCapacityExecutor(q.ExecutorID) || q.OperatorID != q.Binding.Native.OperatorID || q.QuarantinedAt.IsZero() || !q.LeaseExpiredAt.Before(q.QuarantinedAt) || q.History != (model.CapacityNativeAbortZeroHistory{CommandIdentities: 2, HotCommands: 1, ArchivedCommands: 1}) || capacity.ValidateNativeAbortQuarantineAbsence(p, q.Binding.Native, q.Observation, q.QuarantinedAt) != nil {
		return false, ErrCapacityConflict
	}
	_, parentSHA, childSHA, seedSHA, e := nativeAbortQuarantineFacts(ctx, tx, policy, p, q.Binding, q.QuarantinedAt, false)
	if e != nil || parentSHA != q.ParentRecordSHA256 || childSHA != q.CommandRecordSHA256 || seedSHA != q.ResultSeedSHA256 {
		return false, ErrCapacityConflict
	}
	return true, nil
}

func (s CapacityStore) QuarantineNativeUncertainAbort(ctx context.Context, policy model.Manifest, b model.CapacityNativeAbortQuarantineBinding, observed model.AdapterCapacityPodUnregisteredTerminalResponse) (model.CapacityNativeUnsettledCounts, error) {
	var counts model.CapacityNativeUnsettledCounts
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil || !s.ExecutionEnabled || !p.ExecutionEnabled || len(p.MutationBindings) != 0 || s.AdmissionOnly || !validCapacityExecutor(s.ExecutorID) || s.ExecutorPowerOperator != b.Native.OperatorID || capacity.ValidateNativeAbortQuarantineBinding(policy, p, b) != nil {
		return counts, ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return counts, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return counts, err
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return counts, err
	}
	var checksum string
	var active bool
	if tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active) != nil || !active || checksum != policy.Checksum {
		return counts, ErrCapacityConflict
	}
	if err = nativeAbortQuarantineWorkflow(ctx, tx, s.WorkflowID, policy, b); err != nil {
		return counts, err
	}
	if err = checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(b.Native.Adapter)); err != nil {
		return counts, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return counts, err
	}
	now = now.UTC()
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.PolicyName != policy.Metadata.Name || current.Namespace != policy.Metadata.Namespace || current.Environment != p.Environment || current.Domain != p.Domain || current.Dimension != p.Dimension || current.Generation != b.Native.Generation || current.FencingToken != b.ExpectedIntentFencingToken || current.RecoveryOnly || current.Phase != "native_pending" || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Before(now) || failedServingQuarantineBlocks(&current) {
		return counts, ErrCapacityConflict
	}
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return counts, err
	}
	if err = lockNativeBoundOwner(ctx, tx, policy, p, b.Native.PodUID); err != nil {
		return counts, err
	}
	if capacity.ValidateNativeAbortQuarantineAbsence(p, b.Native, observed, now) != nil {
		return counts, ErrCapacityConflict
	}
	original, parentSHA, childSHA, seedSHA, err := nativeAbortQuarantineFacts(ctx, tx, policy, p, b, now, true)
	if err != nil {
		return counts, err
	}
	if current.LeaseOwner != original.LeaseOwner || current.LeaseExecutorID != original.ExecutorID {
		return counts, ErrCapacityConflict
	}
	var existing int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_abort_quarantines WHERE command_id=$1 OR subject_uid=$2`, b.CommandID, b.Native.PodUID).Scan(&existing) != nil || existing != 0 {
		return counts, ErrCapacityConflict
	}
	q := model.CapacityNativeAbortQuarantine{Schema: capacity.NativeAbortQuarantineSchema, Binding: b, WorkflowID: s.WorkflowID.String(), ExecutorID: s.ExecutorID, OperatorID: s.ExecutorPowerOperator, Observation: observed, History: model.CapacityNativeAbortZeroHistory{CommandIdentities: 2, HotCommands: 1, ArchivedCommands: 1}, ParentRecordSHA256: parentSHA, CommandRecordSHA256: childSHA, ResultSeedSHA256: seedSHA, LeaseExpiredAt: *current.LeaseExpiresAt, QuarantinedAt: now}
	raw, err := nativeAbortCanonical(q)
	if err != nil {
		return counts, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_abort_quarantines(command_id,subject_uid,namespace,environment,domain,dimension,record_sha256,quarantine_record)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, b.CommandID, b.Native.PodUID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, nativeCanonicalArchiveSHA(raw), raw); err != nil {
		return counts, err
	}
	counts, err = nativeActiveUnsettledTx(ctx, tx, policy, p, "")
	if err != nil {
		return counts, err
	}
	if counts.RawUnsettled != 1 || counts.ActiveUnsettled != 0 || counts.Quarantined != 1 {
		return counts, ErrCapacityConflict
	}
	if ctx.Err() != nil {
		return counts, ctx.Err()
	}
	return counts, tx.Commit()
}

// Scope-local active blockers remain fail-closed. Raw ledger rows are never
// filtered/deleted. The subject of a quarantine can never use this exclusion.
func nativeActiveUnsettledTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, subject string) (model.CapacityNativeUnsettledCounts, error) {
	var out model.CapacityNativeUnsettledCounts
	// Enumerate receipts independently of HOT rows. Missing/moved bodies must
	// not turn a retained quarantine into an apparently empty active ledger.
	receiptRows, err := tx.QueryContext(ctx, `SELECT q.command_id FROM public.capacity_native_abort_quarantines q JOIN public.capacity_native_command_identities i ON i.id=q.command_id WHERE (q.namespace=$1 AND q.environment=$2 AND q.domain=$3 AND q.dimension=$4) OR (i.namespace=$1 AND i.environment=$2 AND i.domain=$3 AND i.dimension=$4) ORDER BY q.command_id`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return out, err
	}
	var receiptIDs []uuid.UUID
	for receiptRows.Next() {
		var id uuid.UUID
		if receiptRows.Scan(&id) != nil {
			receiptRows.Close()
			return out, ErrCapacityConflict
		}
		receiptIDs = append(receiptIDs, id)
	}
	err = receiptRows.Err()
	receiptRows.Close()
	if err != nil {
		return out, err
	}
	for _, id := range receiptIDs {
		valid, e := nativeAbortQuarantineValidated(ctx, tx, policy, p, id)
		if e != nil || !valid {
			return out, ErrCapacityConflict
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,command_record FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','uncertain') ORDER BY id`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return out, err
	}
	type item struct {
		id  uuid.UUID
		raw []byte
	}
	var records []item
	for rows.Next() {
		var r item
		if rows.Scan(&r.id, &r.raw) != nil {
			rows.Close()
			return out, ErrCapacityConflict
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for _, r := range records {
		out.RawUnsettled++
		valid, e := nativeAbortQuarantineValidated(ctx, tx, policy, p, r.id)
		if e != nil {
			return out, e
		}
		if valid {
			var c model.CapacityNativeCommand
			if capacity.DecodeNativeCapacity(json.RawMessage(r.raw), &c) != nil || c.CommandID != r.id || c.State != "uncertain" {
				return out, ErrCapacityConflict
			}
			var request model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
			if capacity.DecodeNativeCapacity(c.Request, &request) != nil {
				return out, ErrCapacityConflict
			}
			if subject == request.ExpectedPodUID {
				return out, ErrCapacityConflict
			}
			out.Quarantined++
			continue
		}
		out.ActiveUnsettled++
	}
	return out, nil
}

func (s CapacityStore) NativeUnsettledCounts(ctx context.Context, policy model.Manifest) (model.CapacityNativeUnsettledCounts, error) {
	var out model.CapacityNativeUnsettledCounts
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return out, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, err
	}
	out, err = nativeActiveUnsettledTx(ctx, tx, policy, p, "")
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s CapacityStore) NativeAbortCommandQuarantined(ctx context.Context, policy model.Manifest, id uuid.UUID) (bool, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return false, err
	}
	ok, err := nativeAbortQuarantineValidated(ctx, tx, policy, p, id)
	if err != nil {
		return false, err
	}
	return ok, tx.Commit()
}
