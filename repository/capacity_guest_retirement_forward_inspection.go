package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// GuestRetirementForwardInspection is a later factual observation, never an
// admission or a claim about which branch an earlier HTTP request reached.
type GuestRetirementForwardInspection struct {
	Schema              string `json:"schema"`
	RequestSHA256       string `json:"request_sha256,omitempty"`
	BarrierSHA256       string `json:"barrier_sha256,omitempty"`
	DiagnosticSource    string `json:"diagnostic_source"`
	InspectedCoreSource string `json:"inspected_core_source"`
	Stage               string `json:"stage"`
	FailureClass        string `json:"failure_class,omitempty"`
	SQLState            string `json:"sqlstate,omitempty"`
	ReadChecksPassed    bool   `json:"read_checks_passed"`
	TypedIntentCAS      bool   `json:"typed_intent_cas"`
	RolledBack          bool   `json:"rolled_back"`
	MutationAttempted   bool   `json:"mutation_attempted"`
	AdmissionCreated    bool   `json:"admission_created"`
	FailedRunCount      int    `json:"failed_run_count"`
}

type forwardInspectionKey struct{}

// Absent from ordinary request contexts. It only records a fixed Source label;
// it cannot alter an existing validation predicate or transaction operation.
func forwardInspectionStage(ctx context.Context, stage string) {
	if report, ok := ctx.Value(forwardInspectionKey{}).(*GuestRetirementForwardInspection); ok {
		report.Stage = stage
	}
}

func forwardInspectionFailure(report *GuestRetirementForwardInspection, err error) {
	if err == nil {
		return
	}
	report.ReadChecksPassed = false
	report.FailureClass = "validation_refused"
	var pg *pq.Error
	switch {
	case errors.As(err, &pg):
		report.FailureClass, report.SQLState = "postgres", string(pg.Code)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		report.FailureClass = "context_ended"
	case errors.Is(err, sql.ErrNoRows):
		report.FailureClass = "missing_row"
	}
}

// InspectGuestRetirementForwardHistorical invokes only the existing read-side
// validators. FOR SHARE/UPDATE and transaction advisory locks are transient;
// PostgreSQL READ ONLY cannot run those SELECTs. There is no Commit or DML call.
// The supplied barrier is the inspected Core process, not this diagnostic build.
func (s CapacityStore) InspectGuestRetirementForwardHistorical(parent context.Context, req model.CapacityGuestRetirementForwardRequest, operator string, barrier CapacityDispatchExecutorBarrier, inspectedCore, expectedDatabase string) (report GuestRetirementForwardInspection) {
	report = GuestRetirementForwardInspection{Schema: "guest_retirement_forward_readonly_inspection_v1", DiagnosticSource: capacity.CurrentGuestCoreSource(), InspectedCoreSource: inspectedCore, Stage: "inputs"}
	ctx, stop := context.WithTimeout(parent, 20*time.Second)
	defer stop()
	ctx = context.WithValue(ctx, forwardInspectionKey{}, &report)
	actor, actorErr := uuid.Parse(operator)
	if s.DB == nil || actorErr != nil || actor == uuid.Nil || actor.String() != operator || len(inspectedCore) != 40 || !validCapacityDispatchExecutorBarrier(barrier) || barrier.SourceCommit != inspectedCore || !validCapacityExecutor(req.PreregistrationID) || !validCapacityExecutor(req.RetirementRequestID) || !validCapacityExecutor(req.PolicyID) || !capacity.ValidDigest(req.PolicyChecksum) || !capacity.ValidDigest(req.IntentSHA256) || req.Generation < 1 || req.FencingToken < 1 || expectedDatabase == "" {
		forwardInspectionFailure(&report, ErrCapacityConflict)
		return
	}
	forwardInspectionStage(ctx, "begin")
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	defer func() {
		err := tx.Rollback()
		report.RolledBack = err == nil
		if err != nil {
			// A context-triggered rollback may already have completed; do not
			// claim independently observed rollback success from ErrTxDone.
			report.ReadChecksPassed = false
			if report.FailureClass == "" {
				report.Stage = "rollback"
				forwardInspectionFailure(&report, err)
			}
		}
	}()
	forwardInspectionStage(ctx, "database")
	var database string
	if err = tx.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil || database != expectedDatabase {
		if err == nil {
			err = ErrCapacityConflict
		}
		forwardInspectionFailure(&report, err)
		return
	}
	forwardInspectionStage(ctx, "operator_current")
	if err = inspectForwardOperatorTx(ctx, tx, operator); err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	x, err := s.retirementForwardSnapshotTx(ctx, tx, req.RetirementRequestID)
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	i := x.original.Request.Intent
	forwardInspectionStage(ctx, "historical_seven_cas_and_barrier")
	if x.original.Preregistration.PreregistrationID != req.PreregistrationID || x.policy.ID.String() != req.PolicyID || x.policy.Checksum != req.PolicyChecksum || x.current.Generation != req.Generation || x.current.FencingToken != req.FencingToken || capacity.BusinessCreationSHA256(x.intentWire) != req.IntentSHA256 || x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) || !barrier.ProcessStartedAt.After(*x.current.LeaseExpiresAt) || !barrier.ProcessStartedAt.After(i.OriginalDeadline) || barrier.ProcessStartedAt.After(x.now) {
		forwardInspectionFailure(&report, ErrCapacityConflict)
		return
	}
	forwardInspectionStage(ctx, "original_context_barrier")
	var deadline time.Time
	if err = tx.QueryRowContext(ctx, `SELECT original_context_deadline FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, i.RequestID).Scan(&deadline); err != nil || !barrier.ProcessStartedAt.After(deadline) {
		if err == nil {
			err = ErrCapacityConflict
		}
		forwardInspectionFailure(&report, err)
		return
	}
	forwardInspectionStage(ctx, "exact_failed_run_selection")
	rows, err := tx.QueryContext(ctx, `SELECT w.id::text FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE j.envelope::jsonb#>>'{workflow,id}'=$1 AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND w.result#>>'{steps,0,metadata,generation}'=$2 AND w.result#>>'{steps,0,metadata,fencing_token}'=$3 AND w.result#>>'{steps,0,metadata,lease_owner}'=$4 ORDER BY w.id LIMIT 2`, i.WorkflowID, x.current.Generation, x.current.FencingToken, x.current.LeaseOwner)
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	report.FailedRunCount = len(ids)
	if err == nil {
		err = rowErr
	}
	if err == nil {
		err = closeErr
	}
	if err == nil && len(ids) != 1 {
		err = ErrCapacityConflict
	}
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	if _, err = s.failedForwardRetirementRunTx(ctx, tx, x, ids[0]); err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	forwardInspectionStage(ctx, "adoptable_destroy")
	destroy, err := forwardAdoptableDestroyTx(ctx, tx, x)
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	if err = retirementForwardQuietTx(ctx, tx, x, "", destroy); err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	forwardInspectionStage(ctx, "existing_forward_marker")
	// This inspector diagnoses the first root admission, not a new continuation.
	if x.current.RetirementForward != nil {
		forwardInspectionFailure(&report, ErrCapacityConflict)
		return
	}
	forwardInspectionStage(ctx, "operator_revalidation")
	if err = inspectForwardOperatorTx(ctx, tx, operator); err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	forwardInspectionStage(ctx, "typed_intent_cas_prediction")
	before, err := json.Marshal(x.current)
	if err == nil {
		err = tx.QueryRowContext(ctx, `SELECT intent=$5::jsonb FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, x.current.Namespace, x.current.Environment, x.current.Domain, x.current.Dimension, string(before)).Scan(&report.TypedIntentCAS)
	}
	if err == nil && !report.TypedIntentCAS {
		err = ErrCapacityConflict
	}
	if err != nil {
		forwardInspectionFailure(&report, err)
		return
	}
	report.Stage, report.ReadChecksPassed = "read_checks_complete_no_admission", true
	return
}

func inspectForwardOperatorTx(ctx context.Context, tx *sql.Tx, operator string) error {
	c, err := GetCollaboratorTx(ctx, tx, operator)
	if err != nil {
		return err
	}
	if c.ID.String() != operator || c.Status != "active" {
		return ErrCapacityConflict
	}
	actions, err := resolveYggdrasilPermissionsOn(ctx, tx, c.ID, c.Traits)
	if err != nil {
		return err
	}
	for _, action := range actions {
		if action == YggdrasilGodModeAction {
			return nil
		}
	}
	return ErrCapacityConflict
}
