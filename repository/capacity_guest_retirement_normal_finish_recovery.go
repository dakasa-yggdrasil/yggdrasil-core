package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestRetirementForwardNormalFinishRecoveryMode = "normal_finish_recovery"
const GuestRetirementForwardNormalFinishRecoverySchema = "original_normal_finish_recovery_v1"

// These are references to closed retained originals, never native-OFF proof.
// The original successful Guest call and the failed finish remain immutable.
type GuestRetirementForwardNormalFinishRecoveryProof struct {
	Schema                  string    `json:"schema"`
	RequestingRunID         string    `json:"requesting_run_id"`
	FailedRunID             string    `json:"failed_run_id"`
	FailedRunSHA256         string    `json:"failed_run_sha256"`
	FailedFinishACKAt       time.Time `json:"failed_finish_ack_at"`
	NativeOffReadID         string    `json:"native_off_read_id"`
	NativeOffPreparedSHA256 string    `json:"native_off_prepared_sha256"`
	NativeOffReturnSHA256   string    `json:"native_off_return_sha256"`
	OriginalContextDeadline time.Time `json:"original_context_deadline"`
	OriginalLeaseExpiresAt  time.Time `json:"original_lease_expires_at"`
}

// TryRequestGuestRetirementNormalFinishRecovery is selected by the real plan
// before aggregate useful coverage: its powered-off target cannot report.
// There is no new Guest call, provider write, expiry renewal or caller proof.
func (s CapacityStore) TryRequestGuestRetirementNormalFinishRecovery(ctx context.Context, policy model.Manifest) (bool, error) {
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || s.OriginalRunID == uuid.Nil || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return false, err
	}
	current, err := loadCapacityIntent(ctx, s.DB, policy.Metadata.Namespace, p, false)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if current.RecoveryOnly || current.FloorDegraded || (current.Phase != "draining" && current.Phase != "drained") || current.LeaseExpiresAt == nil {
		return false, nil
	}
	id := ""
	if current.RetirementForward != nil {
		if current.RetirementForward.Mode != GuestRetirementForwardNormalFinishRecoveryMode || current.RetirementForward.Stage == "requested" || current.RetirementForward.Stage == "terminal" {
			return false, nil
		}
		id = current.RetirementForward.RetirementRequestID
		var written bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)`, id).Scan(&written); err != nil {
			return false, err
		}
		if written {
			return false, nil
		} // The unchanged settled-absence continuation owns this write.
	} else {
		// Match the immutable original executor/epoch, not the newest request.
		rows, e := s.DB.QueryContext(ctx, `SELECT r.id::text FROM public.capacity_vm_retirement_intents r
   JOIN public.capacity_guest_original_retirement_contexts c ON c.intent_id=r.id
   JOIN public.capacity_guest_original_caller_returns v ON v.intent_id=r.id
   WHERE c.executor_id=$1 AND r.intent_record->>'generation'=$2
    AND r.intent_record->>'fence'=$3 AND r.intent_record->>'policy_id'=$4
    AND v.original_record->>'status'='200' AND v.original_record->>'body_persisted'='true'
    AND v.original_record->>'preflight_failed'='false' AND v.original_record->>'do_failed'='false'
    AND v.original_record->>'read_failed'='false' AND v.original_record->>'close_failed'='false'
    AND v.original_record->>'original_context_failed'='false'
    AND (v.original_record->>'driver_returned_at')::timestamptz<r.original_deadline
   ORDER BY r.id LIMIT 2`, current.LeaseExecutorID, current.Generation, current.FencingToken, policy.ID.String())
		if e != nil {
			return false, e
		}
		ids := []string{}
		for rows.Next() {
			var x string
			if e = rows.Scan(&x); e != nil {
				rows.Close()
				return false, e
			}
			ids = append(ids, x)
		}
		e, closeErr := rows.Err(), rows.Close()
		if e != nil {
			return false, e
		}
		if closeErr != nil {
			return false, closeErr
		}
		if len(ids) == 0 {
			return false, nil
		}
		if len(ids) != 1 {
			return false, ErrCapacityConflict
		}
		id = ids[0]
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Natural expiry is a PG comparison. A live original is not a failed retry.
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return false, err
	}
	if current.LeaseExpiresAt.After(now) {
		return false, nil
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return false, err
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return false, err
	}
	_, err = s.requestNormalFinishRecoveryTx(ctx, tx, id, nil, "source:normal-finish-recovery", s.OriginalRunID.String())
	if err != nil {
		return false, err
	}
	if !guestReconcileLive(ctx) {
		return false, ErrCapacityLease
	}
	return true, tx.Commit()
}

// The existing closed seven-field API may select this state, but cannot select
// its mode, proof, clocks, run identity or a replacement native observation.
func (s CapacityStore) requestNormalFinishHistorical(ctx context.Context, req model.CapacityGuestRetirementForwardRequest, issuer string, revalidate func(context.Context) error) (GuestRetirementForward, bool, error) {
	var zero GuestRetirementForward
	var normal bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns c
  JOIN public.capacity_vm_retirement_intents r ON r.id=c.intent_id WHERE r.id=$1
  AND c.original_record->>'status'='200' AND c.original_record->>'body_persisted'='true'
  AND c.original_record->>'preflight_failed'='false' AND c.original_record->>'do_failed'='false'
  AND c.original_record->>'read_failed'='false' AND c.original_record->>'close_failed'='false'
  AND c.original_record->>'original_context_failed'='false'
  AND (c.original_record->>'driver_returned_at')::timestamptz<r.original_deadline)`, req.RetirementRequestID).Scan(&normal)
	if err != nil || !normal {
		return zero, normal, err
	}
	if err = revalidate(ctx); err != nil {
		return zero, true, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, true, err
	}
	defer tx.Rollback()
	r, err := s.requestNormalFinishRecoveryTx(ctx, tx, req.RetirementRequestID, &req, issuer, "")
	if err != nil {
		return zero, true, err
	}
	if err = revalidate(ctx); err != nil {
		return zero, true, err
	}
	if ctx.Err() != nil {
		return zero, true, ErrCapacityConflict
	}
	return r, true, tx.Commit()
}

func (s CapacityStore) requestNormalFinishRecoveryTx(ctx context.Context, tx *sql.Tx, id string, req *model.CapacityGuestRetirementForwardRequest, issuer, ownRun string) (GuestRetirementForward, error) {
	var zero GuestRetirementForward
	x, err := s.retirementForwardSnapshotForNormalFinishTx(ctx, tx, id, true)
	if err != nil {
		return zero, err
	}
	if req != nil && (req.PreregistrationID != x.original.Preregistration.PreregistrationID || req.PolicyID != x.policy.ID.String() || req.PolicyChecksum != x.policy.Checksum || req.Generation != x.current.Generation || req.FencingToken != x.current.FencingToken || req.IntentSHA256 != capacity.BusinessCreationSHA256(x.intentWire)) {
		return zero, ErrCapacityConflict
	}
	if x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) || x.current.FailedUnwitnessedExpansionCleanupID != "" || x.current.FailedExpansionTerminalReconcile != nil {
		return zero, ErrCapacityConflict
	}
	r := forwardRecord(x, s, GuestRetirementForwardNormalFinishRecoveryMode, "requested", issuer)
	r.RunID = ""
	if m := x.current.RetirementForward; m != nil {
		if m.Mode != GuestRetirementForwardNormalFinishRecoveryMode || (m.Stage != "admitted" && m.Stage != "off_qualified") || m.RetirementRequestID != id {
			return zero, ErrCapacityConflict
		}
		parent, sha, e := loadRetirementForwardTx(ctx, tx, m.ID, m.Stage)
		if e != nil || parent.NormalFinishRecovery == nil || !reflect.DeepEqual(parent.Evidence, x.evidence) {
			return zero, ErrCapacityConflict
		}
		r.RootAdmissionID = parent.RootAdmissionID
		r.ParentAdmissionID = parent.ID
		r.ParentAdmissionSHA256 = sha
	}
	proof, run, err := s.normalFinishRecoveryProofTx(ctx, tx, x, ownRun)
	if err != nil {
		return zero, err
	}
	r.NormalFinishRecovery = &proof
	r.FailedRun = run
	if err = retirementForwardQuietTx(ctx, tx, x, ownRun, ""); err != nil {
		return zero, err
	}
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return zero, err
	}
	next := x.current
	next.RetirementForward = retirementForwardMarker(r)
	next.UpdatedAt = x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "normal-finish-recovery:"+r.ID+":requested"); err != nil {
		return zero, err
	}
	return r, nil
}

func (s CapacityStore) normalFinishRecoveryProofTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, ownRun string) (GuestRetirementForwardNormalFinishRecoveryProof, []byte, error) {
	var p GuestRetirementForwardNormalFinishRecoveryProof
	i := x.original.Request.Intent
	if x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) {
		return p, nil, ErrCapacityConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT original_context_deadline FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, i.RequestID).Scan(&p.OriginalContextDeadline); err != nil {
		return p, nil, err
	}
	if !x.now.After(p.OriginalContextDeadline) || !x.now.After(i.OriginalDeadline) {
		return p, nil, ErrCapacityConflict
	}
	// This branch admits only the first DELETE. Any existing write stays in its
	// exact accepted/settled continuation lane; it is never sent a second time.
	var writes int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, i.RequestID).Scan(&writes); err != nil || writes != 0 {
		return p, nil, ErrCapacityConflict
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND grant_record#>>'{grant,capability}'=$5 AND generation=$6`, x.binding.IntegrationInstanceID, x.binding.ScopeChecksum, x.binding.ProfileName, i.Slot, x.binding.DestroyCapability, x.current.Generation).Scan(&n); err != nil || n != 0 {
		return p, nil, ErrCapacityConflict
	}
	read, preparedSHA, returnedSHA, recorded, err := normalFinishClosedOffFailureTx(ctx, tx, x)
	if err != nil {
		return p, nil, err
	}
	// The exact current failed owner, not any older failure or caller-picked ID.
	rows, err := tx.QueryContext(ctx, `SELECT w.id::text FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id
  WHERE j.envelope::jsonb#>>'{workflow,id}'=$1 AND w.status='failed' AND w.finished_at=j.returned_at
   AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at IS NOT NULL
   AND w.result#>>'{steps,0,metadata,generation}'=$2 AND w.result#>>'{steps,0,metadata,fencing_token}'=$3
   AND w.result#>>'{steps,0,metadata,lease_owner}'=$4 ORDER BY w.id LIMIT 2`, i.WorkflowID, x.current.Generation, x.current.FencingToken, x.current.LeaseOwner)
	if err != nil {
		return p, nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return p, nil, err
		}
		ids = append(ids, id)
	}
	er, cl := rows.Err(), rows.Close()
	if er != nil {
		return p, nil, er
	}
	if cl != nil {
		return p, nil, cl
	}
	if len(ids) != 1 {
		return p, nil, ErrCapacityConflict
	}
	run, err := s.normalFinishFailedRunTx(ctx, tx, x, ids[0])
	if err != nil {
		return p, nil, err
	}
	var returned, ack time.Time
	if err = tx.QueryRowContext(ctx, `SELECT j.returned_at,j.finalization_ack_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE w.id=$1 AND j.state='returned' AND j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at`, ids[0]).Scan(&returned, &ack); err != nil || recorded.After(returned) || ack.Before(returned) || ack.After(x.now) {
		return p, nil, ErrCapacityConflict
	}
	// A previous read-only owner must close every own row before this new claim.
	if x.current.RetirementForward != nil {
		var open int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forward_reads r
   WHERE r.admission_id=$1 AND (r.kind<>'off' OR r.recorded_at>$2 OR
    r.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.id=r.id AND v.stage='returned'))`, x.current.RetirementForward.ID, returned).Scan(&open)
		if err != nil || open != 0 {
			return p, nil, ErrCapacityConflict
		}
	}
	p.Schema = GuestRetirementForwardNormalFinishRecoverySchema
	p.RequestingRunID = ownRun
	p.FailedRunID = ids[0]
	p.FailedRunSHA256 = capacity.BusinessCreationSHA256(run)
	p.FailedFinishACKAt = ack
	p.NativeOffReadID = read.ReadID
	p.NativeOffPreparedSHA256 = preparedSHA
	p.NativeOffReturnSHA256 = returnedSHA
	p.OriginalLeaseExpiresAt = *x.current.LeaseExpiresAt
	return p, run, nil
}

func normalFinishClosedOffFailureTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot) (GuestNativePoweroffReadV2, string, string, time.Time, error) {
	var prepared GuestNativePoweroffReadV2
	var returned GuestNativePoweroffReturnV2
	var preparedSHA, returnedSHA string
	var preparedWire, returnWire []byte
	var preparedAt, returnedAt time.Time
	rows, err := tx.QueryContext(ctx, `SELECT observation_sha256,original_wire,original_native_join_wire,recorded_at,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1 ORDER BY recorded_at,id`, x.original.Request.Intent.RequestID)
	if err != nil {
		return prepared, "", "", returnedAt, err
	}
	n := 0
	for rows.Next() {
		var sha string
		var raw, join []byte
		var at time.Time
		var same bool
		if err = rows.Scan(&sha, &raw, &join, &at, &same); err != nil {
			rows.Close()
			return prepared, "", "", returnedAt, err
		}
		if !same || capacity.BusinessCreationSHA256(raw) != sha {
			rows.Close()
			return prepared, "", "", returnedAt, ErrCapacityConflict
		}
		switch n {
		case 0:
			if capacity.DecodeGuestLifecycle(raw, &prepared) != nil {
				rows.Close()
				return prepared, "", "", returnedAt, ErrCapacityConflict
			}
			preparedWire = raw
			preparedSHA = sha
			preparedAt = at
		case 1:
			if capacity.DecodeGuestLifecycle(raw, &returned) != nil || !reflect.DeepEqual(join, preparedWire) {
				rows.Close()
				return prepared, "", "", returnedAt, ErrCapacityConflict
			}
			returnWire = raw
			returnedSHA = sha
			returnedAt = at
		default:
			rows.Close()
			return prepared, "", "", returnedAt, ErrCapacityConflict
		}
		n++
	}
	er, cl := rows.Err(), rows.Close()
	if er != nil {
		return prepared, "", "", returnedAt, er
	}
	if cl != nil {
		return prepared, "", "", returnedAt, cl
	}
	i := x.original.Request.Intent
	if n != 2 || len(returnWire) == 0 || prepared.Schema != "original_core_guest_native_poweroff_read_challenge_v2" || !validCapacityExecutor(prepared.ReadID) || prepared.IntentID != i.RequestID || prepared.IntentSHA256 != capacity.GuestRetirementSHA(i) || prepared.OriginalCallerSHA256 != x.evidence.CallerSHA256 || prepared.MutationBindingSHA256 != capacity.GuestRetirementSHA(x.binding) || prepared.AdapterSourceCommit != x.binding.OriginalProviderSourceCommit || prepared.Tuple != i.Tuple || prepared.IssuedAtCore.IsZero() || !prepared.OriginalDeadlineCore.After(prepared.IssuedAtCore) || prepared.OriginalDeadlineCore.Sub(prepared.IssuedAtCore) > 5*time.Second || returned.Schema != "original_core_guest_native_poweroff_read_return_v2" || !reflect.DeepEqual(returned.Challenge, prepared) || !returned.CallFailed || returned.OriginalContextFailed || !returned.OriginalReturnedAtCore.Before(prepared.OriginalDeadlineCore) || returned.Plan != nil || (returned.Status != "" && returned.Status != "observed") || returned.StartedAtCore.Before(prepared.IssuedAtCore) || returned.OriginalReturnedAtCore.Before(returned.StartedAtCore) || returned.OriginalReturnedAtCore.After(returnedAt) || returnedAt.Before(preparedAt) || returnedAt.After(x.now) {
		return prepared, "", "", returnedAt, ErrCapacityConflict
	}
	return prepared, preparedSHA, returnedSHA, returnedAt, nil
}

func (s CapacityStore) normalFinishFailedRunTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, id string) ([]byte, error) {
	var wire, result []byte
	if err := tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, id, uuid.MustParse(x.original.Request.Intent.WorkflowID), x.now).Scan(&wire, &result); err != nil {
		return nil, err
	}
	var out struct {
		Status string                        `json:"status"`
		Steps  []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(result, &out) != nil || out.Status != "failed" || len(out.Steps) != 7 {
		return nil, ErrCapacityConflict
	}
	steps := map[string]model.WorkflowRunStepResult{}
	for _, step := range out.Steps {
		if _, ok := steps[step.ID]; ok {
			return nil, ErrCapacityConflict
		}
		steps[step.ID] = step
	}
	for _, id := range []string{"provision-original-notify", "complete-original-provision", "refresh-original-membership", "complete-original-retirement"} {
		if steps[id].Status != "skipped" {
			return nil, ErrCapacityConflict
		}
	}
	retire, finish := steps["retire-original-guest"], steps["finish-original-retirement"]
	if steps["plan-original-guest"].Status != "succeeded" || retire.Status != "succeeded" || finish.Status != "failed" || retire.Metadata["request_id"] != x.original.Request.Intent.RequestID {
		return nil, ErrCapacityConflict
	}
	if x.current.RetirementForward == nil {
		if retire.Metadata["intent_sha256"] != capacity.GuestRetirementSHA(x.original.Request.Intent) || retire.Metadata["native_poweroff_known"] != false {
			return nil, ErrCapacityConflict
		}
	} else if retire.Metadata["retirement_forward_id"] != x.current.RetirementForward.ID {
		return nil, ErrCapacityConflict
	}
	wf := model.Manifest{ID: uuid.MustParse(x.original.Request.Intent.WorkflowID)}
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1 AND active`, wf.ID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum); err != nil {
		return nil, err
	}
	own := s
	own.WorkflowID = wf.ID
	own.guestReconcile = &guestReconcileSource{workflow: wf}
	if err := own.installedGuestDispatchRunTx(ctx, tx, x.policy, x.spec, uuid.MustParse(id), result); err != nil {
		return nil, err
	}
	return wire, nil
}
