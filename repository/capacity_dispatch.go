package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const CapacityDispatchProtocol = "capacity_dispatch_prestart_v1"
const MaxCapacityDispatchPendingWakes = 32

var ErrCapacityDispatchEnvelope = errors.New("capacity dispatch envelope refused")
var ErrCapacityDispatchClaim = errors.New("capacity dispatch claim unavailable or stale")
var ErrCapacityDispatchSaturated = errors.New("capacity dispatch pending wakes saturated")
var ErrCapacityDispatchUnknown = errors.New("capacity dispatch actual return is uncertain")

// CapacityDispatchManifestPin names an exact original catalog revision. It
// contains infrastructure identities, never credentials or collaborator data.
type CapacityDispatchManifestPin struct {
	ID        uuid.UUID `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Checksum  string    `json:"checksum"`
}

// CapacityDispatchEnvelope is a private, closed scheduled or demand request. The server
// reconstructs authorization from the operator-owned principal binding; Auth
// and user/caller payloads have no field in this durable protocol.
type CapacityDispatchEnvelope struct {
	Protocol            string                       `json:"protocol"`
	JobID               uuid.UUID                    `json:"job_id"`
	RunID               uuid.UUID                    `json:"run_id"`
	Realm               string                       `json:"realm"`
	Environment         string                       `json:"environment"`
	Domain              string                       `json:"domain"`
	Dimension           string                       `json:"dimension"`
	SourceTick          string                       `json:"source_tick"`
	Policy              CapacityDispatchManifestPin  `json:"policy"`
	Workflow            CapacityDispatchManifestPin  `json:"workflow"`
	RBAC                CapacityDispatchManifestPin  `json:"rbac"`
	AuthorizationPolicy *CapacityDispatchManifestPin `json:"authorization_policy,omitempty"`
	MachinePrincipalID  string                       `json:"machine_principal_id"`
	PrincipalSHA256     string                       `json:"principal_sha256"`
	BindingSHA256       string                       `json:"binding_sha256"`
	Inputs              map[string]any               `json:"inputs"`
	Metadata            map[string]any               `json:"metadata"`
	InputsSHA256        string                       `json:"inputs_sha256"`
	MetadataSHA256      string                       `json:"metadata_sha256"`
}

// LeaseExpiresAt is the fixed original invocation deadline for this claim.
// There is no renewal API, and StartedAt is an immutable possible-start marker.
type CapacityDispatchJob struct {
	CapacityDispatchEnvelope
	EnvelopeSHA256    string
	State             string
	LeaseOwner        uuid.UUID
	FencingToken      int64
	LeaseExpiresAt    *time.Time
	StartedAt         *time.Time
	ReturnedAt        *time.Time
	FinalizationAckAt *time.Time
	PendingWakeCount  int
}

// CapacityDispatchEnvelopeHashes uses the same deterministic JSON encoding as
// admission. Callers must construct only the closed request accepted below.
func CapacityDispatchEnvelopeHashes(e CapacityDispatchEnvelope) (string, string, error) {
	i, err := capacityDispatchCanonicalJSON(e.Inputs)
	if err != nil {
		return "", "", ErrCapacityDispatchEnvelope
	}
	m, err := capacityDispatchCanonicalJSON(e.Metadata)
	if err != nil {
		return "", "", ErrCapacityDispatchEnvelope
	}
	return capacityDispatchSHA(i), capacityDispatchSHA(m), nil
}

// EnqueueCapacityDispatch shares the caller's original tick transaction. The
// caller must rollback on any error; this method never commits a partial tick.
// Duplicate/new wakes return the immutable active job without inserting a run.
func EnqueueCapacityDispatch(ctx context.Context, tx *sql.Tx, e CapacityDispatchEnvelope) (CapacityDispatchJob, bool, error) {
	if tx == nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	raw, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		return CapacityDispatchJob{}, false, err
	}
	// Serialize admission even when this dimension has no row yet. No native
	// capacity authority is acquired by this transaction-scoped SQL lock.
	scope, _ := json.Marshal([]string{e.Realm, e.Environment, e.Domain, e.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(scope)); err != nil {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	var duplicate uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT job_id FROM public.capacity_dispatch_wakes WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND source_tick=$5`, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick).Scan(&duplicate)
	if err == nil {
		job, readErr := readCapacityDispatchJob(ctx, tx, duplicate, false)
		return job, true, readErr
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	var activeID uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND (state IN ('queued','started','unknown') OR (state='returned' AND finalization_ack_at IS NULL)) FOR UPDATE`, e.Realm, e.Environment, e.Domain, e.Dimension).Scan(&activeID)
	if err == nil {
		job, readErr := readCapacityDispatchJob(ctx, tx, activeID, false)
		if readErr != nil || job.Protocol != CapacityDispatchProtocol {
			return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
		}
		if job.PendingWakeCount >= MaxCapacityDispatchPendingWakes {
			return CapacityDispatchJob{}, false, ErrCapacityDispatchSaturated
		}
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET pending_wake_count=pending_wake_count+1, updated_at=clock_timestamp() WHERE id=$1`, job.JobID); err != nil {
			return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
		}
		if err = insertCapacityDispatchWake(ctx, tx, e, job.JobID); err != nil {
			return CapacityDispatchJob{}, false, err
		}
		job.PendingWakeCount++
		return job, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	version := e.Workflow.Version
	if err = InsertWorkflowRunTx(ctx, tx, e.RunID, model.ManifestSelector{Namespace: e.Workflow.Namespace, Name: e.Workflow.Name, Version: &version}, e.Inputs, e.Metadata); err != nil {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_jobs (id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(raw), capacityDispatchSHA(raw)); err != nil {
		return CapacityDispatchJob{}, false, ErrCapacityDispatchEnvelope
	}
	if err = insertCapacityDispatchWake(ctx, tx, e, e.JobID); err != nil {
		return CapacityDispatchJob{}, false, err
	}
	return CapacityDispatchJob{CapacityDispatchEnvelope: e, EnvelopeSHA256: capacityDispatchSHA(raw), State: "queued", PendingWakeCount: 1}, false, nil
}

func insertCapacityDispatchWake(ctx context.Context, tx *sql.Tx, e CapacityDispatchEnvelope, jobID uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_wakes (realm,environment,domain,dimension,source_tick,job_id) VALUES ($1,$2,$3,$4,$5,$6)`, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, jobID)
	if err != nil {
		return ErrCapacityDispatchEnvelope
	}
	return nil
}

// ClaimCapacityDispatch only adopts new protocol-v1 queued rows with no
// possible-start marker. An elapsed started/unknown lease is never replayable.
func ClaimCapacityDispatch(ctx context.Context, db *sql.DB, realm, environment string, owner uuid.UUID, lease time.Duration) (CapacityDispatchJob, error) {
	if db == nil || owner == uuid.Nil || !capacityDispatchText(realm, 64) || !capacityDispatchText(environment, 128) || lease < time.Second || lease > 5*time.Minute || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	defer tx.Rollback()
	var id uuid.UUID
	const claimQuery = `SELECT j.id FROM public.capacity_dispatch_jobs j
		JOIN public.workflow_runs r ON r.id=j.run_id
		WHERE j.realm=$1 AND j.environment=$2 AND j.protocol=$3 AND j.state='queued'
		AND j.started_at IS NULL AND (j.lease_expires_at IS NULL OR j.lease_expires_at <= clock_timestamp())
		AND r.status='pending' AND r.started_at IS NULL
		AND EXISTS (SELECT 1 FROM public.manifests m WHERE m.id::text=j.envelope::jsonb #>> '{policy,id}'
		    AND m.kind='capacity_policy' AND m.active AND m.checksum=j.envelope::jsonb #>> '{policy,checksum}')
		AND EXISTS (SELECT 1 FROM public.manifests m WHERE m.id::text=j.envelope::jsonb #>> '{workflow,id}'
		    AND m.kind='workflow' AND m.active AND m.checksum=j.envelope::jsonb #>> '{workflow,checksum}')
		AND EXISTS (SELECT 1 FROM public.manifests m WHERE m.id::text=j.envelope::jsonb #>> '{rbac,id}'
		    AND m.kind='rbac' AND m.active AND m.checksum=j.envelope::jsonb #>> '{rbac,checksum}')
		AND (NOT (j.envelope::jsonb ? 'authorization_policy') OR EXISTS
		    (SELECT 1 FROM public.manifests m WHERE m.id::text=j.envelope::jsonb #>> '{authorization_policy,id}'
		     AND m.kind='policy' AND m.active AND m.checksum=j.envelope::jsonb #>> '{authorization_policy,checksum}'))
		ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED`
	err = tx.QueryRowContext(ctx, claimQuery, realm, environment, CapacityDispatchProtocol).Scan(&id)
	if err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	job, err := readCapacityDispatchJob(ctx, tx, id, false)
	if err != nil || checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET lease_owner=$2,fencing_token=fencing_token+1,lease_expires_at=clock_timestamp()+($3 * interval '1 microsecond'),updated_at=clock_timestamp() WHERE id=$1 AND fencing_token < 9007199254740991`, id, owner, lease.Microseconds()); err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	next, err := readCapacityDispatchJob(ctx, tx, id, false)
	if err != nil || next.LeaseOwner != owner || next.FencingToken != job.FencingToken+1 {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	if err = tx.Commit(); err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	return next, nil
}

// ValidateCapacityDispatchClaim checks the original envelope/run, current
// exact catalog pins, owner, fence and database deadline. Current machine/RBAC
// authorization is additionally required by the private server-owned service.
func ValidateCapacityDispatchClaim(ctx context.Context, db *sql.DB, job CapacityDispatchJob, allowStarted bool) error {
	if db == nil || capacityDispatchContextFailure(ctx) != nil {
		return ErrCapacityDispatchClaim
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ErrCapacityDispatchClaim
	}
	defer tx.Rollback()
	current, err := readCapacityDispatchJob(ctx, tx, job.JobID, false)
	if err != nil || !sameCapacityDispatchClaim(current, job) || checkCapacityDispatchOriginal(ctx, tx, current) != nil {
		return ErrCapacityDispatchClaim
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !liveCapacityDispatchClaim(current, now, allowStarted) {
		return ErrCapacityDispatchClaim
	}
	return nil
}

// StartCapacityDispatch commits the possible-start marker and original run's
// running status together, before the caller crosses RunWorkflow. A crash in
// that gap remains unknown even if the actual invocation never happened.
func StartCapacityDispatch(ctx context.Context, db *sql.DB, job CapacityDispatchJob) (CapacityDispatchJob, error) {
	if db == nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	defer tx.Rollback()
	current, err := readCapacityDispatchJob(ctx, tx, job.JobID, true)
	var now time.Time
	if err != nil || !sameCapacityDispatchClaim(current, job) || checkCapacityDispatchOriginal(ctx, tx, current) != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !liveCapacityDispatchClaim(current, now, false) {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.workflow_runs SET status='running',started_at=$2,updated_at=clock_timestamp() WHERE id=$1 AND status='pending' AND started_at IS NULL`, job.RunID, now)
	if err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='started',started_at=$2,updated_at=clock_timestamp() WHERE id=$1`, job.JobID, now); err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	current.State, current.StartedAt = "started", &now
	if err = tx.Commit(); err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	// Commit can itself return after the absolute deadline. Its durable marker
	// remains HOLD; never hand the caller permission to invoke from that late
	// acknowledgement. The worker also rechecks current authorization.
	if err = ValidateCapacityDispatchClaim(ctx, db, current, true); err != nil {
		return current, ErrCapacityDispatchClaim
	}
	return current, nil
}

// FinishCapacityDispatch is called only after the original RunWorkflow really
// returned. Cancellation, late return, changed pins or typed unknown keeps the
// active dimension blocked. A cleanup context can record uncertainty, but can
// never turn a cancelled original context into a successful finalization.
func FinishCapacityDispatch(ctx context.Context, db *sql.DB, job CapacityDispatchJob, response model.RunWorkflowResponse, actualReturnedAt time.Time, runErr error, beforeRelease ...func(context.Context) error) error {
	if db == nil {
		return ErrCapacityDispatchClaim
	}
	originalContextErr := capacityDispatchContextFailure(ctx)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(writeCtx, nil)
	if err != nil {
		return ErrCapacityDispatchClaim
	}
	defer tx.Rollback()
	current, err := readCapacityDispatchJob(writeCtx, tx, job.JobID, true)
	if err != nil || !sameCapacityDispatchClaim(current, job) || current.State != "started" || current.StartedAt == nil || actualReturnedAt.IsZero() {
		return ErrCapacityDispatchClaim
	}
	var now time.Time
	if err = tx.QueryRowContext(writeCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return ErrCapacityDispatchClaim
	}
	uncertain := originalContextErr != nil || capacityDispatchContextFailure(ctx) != nil || !liveCapacityDispatchClaim(current, now, true) || checkCapacityDispatchOriginal(writeCtx, tx, current) != nil || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)
	status := strings.ToLower(strings.TrimSpace(response.Status))
	if response.Workflow.ID != current.Workflow.ID || response.Workflow.Namespace != current.Workflow.Namespace || response.Workflow.Name != current.Workflow.Name || response.Workflow.Version != current.Workflow.Version || response.Workflow.Kind != "workflow" {
		uncertain = true
	}
	if status != "succeeded" && status != "committed" && status != "failed" && status != "cancelled" {
		uncertain = true
	}
	state, runStatus := "returned", "failed"
	if !uncertain && runErr == nil && (status == "succeeded" || status == "committed") {
		runStatus = "succeeded"
	}
	errMessage := capacityDispatchReturnError(runErr, originalContextErr, uncertain)
	if uncertain {
		state = "unknown"
	}
	resultJSON, err := json.Marshal(response)
	if err != nil {
		return ErrCapacityDispatchUnknown
	}
	// The row is locked and the original tuple is unchanged. The absolute
	// deadline is checked again in the final mutation, so lock waits cannot
	// convert a return after the deadline into success.
	if !uncertain {
		var live bool
		if originalContextErr = capacityDispatchContextFailure(ctx); originalContextErr != nil {
			uncertain = true
		}
		if err = tx.QueryRowContext(writeCtx, `SELECT clock_timestamp() < $1`, *current.LeaseExpiresAt).Scan(&live); err != nil || !live || uncertain {
			uncertain, state, runStatus = true, "unknown", "failed"
			if errMessage == "" {
				errMessage = ErrCapacityDispatchUnknown.Error()
			}
		}
	}
	if err = tx.QueryRowContext(writeCtx, `WITH final_clock AS MATERIALIZED (SELECT clock_timestamp() AS at) UPDATE public.capacity_dispatch_jobs SET state=CASE WHEN $2='returned' AND final_clock.at >= lease_expires_at THEN 'unknown' ELSE $2 END,returned_at=$3,return_status=$4,return_error=CASE WHEN $2='returned' AND final_clock.at >= lease_expires_at THEN $6 ELSE NULLIF($5,'') END,updated_at=final_clock.at FROM final_clock WHERE id=$1 RETURNING state`, job.JobID, state, actualReturnedAt, status, errMessage, ErrCapacityDispatchUnknown.Error()).Scan(&state); err != nil {
		return ErrCapacityDispatchClaim
	}
	if state == "unknown" {
		uncertain, runStatus = true, "failed"
		if errMessage == "" {
			errMessage = ErrCapacityDispatchUnknown.Error()
		}
	}
	result, err := tx.ExecContext(writeCtx, `UPDATE public.workflow_runs SET status=$2,result=$3::jsonb,error=NULLIF($4,''),finished_at=$5,updated_at=clock_timestamp() WHERE id=$1 AND (status='running' OR ($7 AND status='cancelled')) AND started_at=$6`, job.RunID, runStatus, string(resultJSON), errMessage, actualReturnedAt, *current.StartedAt, uncertain)
	if err != nil {
		return ErrCapacityDispatchClaim
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityDispatchClaim
	}
	if err = tx.Commit(); err != nil {
		return ErrCapacityDispatchClaim
	}
	// returned WITHOUT an acknowledgment stays active in the unique dimension
	// index and admission query. Only this actual first Commit return, checked
	// under the original owner, permits the separate acknowledgment recording.
	// It is never proof of the worker's caller or product SDK return.
	ackErr := capacityDispatchContextFailure(ctx)
	var acknowledgedLive bool
	if clockErr := db.QueryRowContext(writeCtx, `SELECT clock_timestamp() < $1`, *current.LeaseExpiresAt).Scan(&acknowledgedLive); clockErr != nil || !acknowledgedLive {
		ackErr = errors.Join(ackErr, context.DeadlineExceeded)
	}
	if ackErr != nil {
		if markErr := markCapacityDispatchFinalizationUnknown(writeCtx, db, current, capacityDispatchReturnError(nil, ackErr, true)); markErr != nil {
			return errors.Join(ErrCapacityDispatchUnknown, ackErr, markErr)
		}
		return errors.Join(ErrCapacityDispatchUnknown, runErr, ackErr)
	}
	if uncertain {
		return errors.Join(ErrCapacityDispatchUnknown, runErr, originalContextErr)
	}
	for _, fence := range beforeRelease {
		if fence == nil {
			ackErr = ErrCapacityDispatchClaim
		} else {
			ackErr = errors.Join(ackErr, fence(ctx))
		}
	}
	ackErr = errors.Join(ackErr, capacityDispatchContextFailure(ctx))
	if ackErr != nil {
		markErr := markCapacityDispatchFinalizationUnknown(writeCtx, db, current, capacityDispatchReturnError(nil, ackErr, true))
		return errors.Join(ErrCapacityDispatchUnknown, runErr, ackErr, markErr)
	}
	ackErr = acknowledgeCapacityDispatchFinalization(ctx, db, current)
	return errors.Join(runErr, ackErr)
}

func acknowledgeCapacityDispatchFinalization(ctx context.Context, db *sql.DB, job CapacityDispatchJob) error {
	if capacityDispatchContextFailure(ctx) != nil {
		return ErrCapacityDispatchUnknown
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrCapacityDispatchUnknown
	}
	defer tx.Rollback()
	current, err := readCapacityDispatchJob(ctx, tx, job.JobID, true)
	if err != nil || !sameCapacityDispatchClaim(current, job) || current.State != "returned" || current.ReturnedAt == nil || current.FinalizationAckAt != nil || checkCapacityDispatchOriginal(ctx, tx, current) != nil {
		return ErrCapacityDispatchUnknown
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND state='returned' AND finalization_ack_at IS NULL AND lease_expires_at>clock_timestamp()`, job.JobID)
	if err != nil {
		return ErrCapacityDispatchUnknown
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrCapacityDispatchUnknown
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(ErrCapacityDispatchUnknown, err)
	}
	// This write records the already OBSERVED first Commit acknowledgment.
	// A late reply to this second write does not erase that prior truthful
	// observation or assert a successful caller return; publication still fails.
	return errors.Join(capacityDispatchContextFailure(ctx))
}

func markCapacityDispatchFinalizationUnknown(ctx context.Context, db *sql.DB, job CapacityDispatchJob, reason string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrCapacityDispatchClaim
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='unknown',finalization_error=$9,updated_at=clock_timestamp() WHERE id=$1 AND run_id=$2 AND realm=$3 AND environment=$4 AND envelope_sha256=$5 AND lease_owner=$6 AND fencing_token=$7 AND lease_expires_at=$8 AND state IN ('returned','unknown') AND finalization_ack_at IS NULL AND returned_at IS NOT NULL`, job.JobID, job.RunID, job.Realm, job.Environment, job.EnvelopeSHA256, job.LeaseOwner, job.FencingToken, *job.LeaseExpiresAt, reason)
	if err != nil {
		return ErrCapacityDispatchClaim
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityDispatchClaim
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.workflow_runs SET status='failed',error=$2,updated_at=clock_timestamp() WHERE id=$1 AND started_at=$3`, job.RunID, reason, *job.StartedAt); err != nil {
		return ErrCapacityDispatchClaim
	}
	if err = tx.Commit(); err != nil {
		return ErrCapacityDispatchClaim
	}
	return nil
}

func capacityDispatchContextFailure(ctx context.Context) error {
	err := errors.Join(ctx.Err(), context.Cause(ctx))
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

func capacityDispatchReturnError(runErr, contextErr error, uncertain bool) string {
	if errors.Is(contextErr, context.DeadlineExceeded) || errors.Is(runErr, context.DeadlineExceeded) {
		return "capacity dispatch original deadline exceeded"
	}
	if contextErr != nil || errors.Is(runErr, context.Canceled) {
		return "capacity dispatch original context refused"
	}
	if runErr != nil {
		return "capacity dispatch original workflow returned error"
	}
	if uncertain {
		return ErrCapacityDispatchUnknown.Error()
	}
	return ""
}

type capacityDispatchQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readCapacityDispatchJob(ctx context.Context, db capacityDispatchQueryer, id uuid.UUID, lock bool) (CapacityDispatchJob, error) {
	query := `SELECT id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,pending_wake_count,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var job CapacityDispatchJob
	var raw string
	var owner uuid.NullUUID
	var lease, started, returned, acknowledged sql.NullTime
	if err := db.QueryRowContext(ctx, query, id).Scan(&job.JobID, &job.RunID, &job.Protocol, &job.Realm, &job.Environment, &job.Domain, &job.Dimension, &job.SourceTick, &raw, &job.EnvelopeSHA256, &job.State, &owner, &job.FencingToken, &lease, &started, &returned, &job.PendingWakeCount, &acknowledged); err != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchClaim
	}
	var envelope CapacityDispatchEnvelope
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || capacityDispatchSHA([]byte(raw)) != job.EnvelopeSHA256 {
		return CapacityDispatchJob{}, ErrCapacityDispatchEnvelope
	}
	encoded, err := encodeCapacityDispatchEnvelope(envelope)
	if err != nil || string(encoded) != raw || envelope.JobID != job.JobID || envelope.RunID != job.RunID || envelope.Protocol != job.Protocol || envelope.Realm != job.Realm || envelope.Environment != job.Environment || envelope.Domain != job.Domain || envelope.Dimension != job.Dimension || envelope.SourceTick != job.SourceTick {
		return CapacityDispatchJob{}, ErrCapacityDispatchEnvelope
	}
	job.CapacityDispatchEnvelope = envelope
	if owner.Valid {
		job.LeaseOwner = owner.UUID
	}
	if lease.Valid {
		job.LeaseExpiresAt = &lease.Time
	}
	if started.Valid {
		job.StartedAt = &started.Time
	}
	if returned.Valid {
		job.ReturnedAt = &returned.Time
	}
	if acknowledged.Valid {
		job.FinalizationAckAt = &acknowledged.Time
	}
	return job, nil
}

func sameCapacityDispatchClaim(a, b CapacityDispatchJob) bool {
	raw, err := encodeCapacityDispatchEnvelope(b.CapacityDispatchEnvelope)
	return err == nil && a.EnvelopeSHA256 == b.EnvelopeSHA256 && capacityDispatchSHA(raw) == a.EnvelopeSHA256 && a.JobID == b.JobID && a.RunID == b.RunID && a.LeaseOwner != uuid.Nil && a.LeaseOwner == b.LeaseOwner && a.FencingToken > 0 && a.FencingToken == b.FencingToken && a.LeaseExpiresAt != nil && b.LeaseExpiresAt != nil && a.LeaseExpiresAt.Equal(*b.LeaseExpiresAt)
}

func liveCapacityDispatchClaim(job CapacityDispatchJob, now time.Time, allowStarted bool) bool {
	return job.Protocol == CapacityDispatchProtocol && job.LeaseExpiresAt != nil && now.Before(*job.LeaseExpiresAt) && ((job.State == "queued" && job.StartedAt == nil) || (allowStarted && job.State == "started" && job.StartedAt != nil && job.ReturnedAt == nil))
}

func checkCapacityDispatchOriginal(ctx context.Context, db capacityDispatchQueryer, job CapacityDispatchJob) error {
	var namespace, name string
	var status string
	var started, finished sql.NullTime
	var version sql.NullInt32
	var inputs, metadata []byte
	if err := db.QueryRowContext(ctx, `SELECT workflow_namespace,workflow_name,workflow_version,inputs,metadata,status,started_at,finished_at FROM public.workflow_runs WHERE id=$1`, job.RunID).Scan(&namespace, &name, &version, &inputs, &metadata, &status, &started, &finished); err != nil || namespace != job.Workflow.Namespace || name != job.Workflow.Name || !version.Valid || int(version.Int32) != job.Workflow.Version {
		return ErrCapacityDispatchClaim
	}
	if (job.State == "queued" && (status != "pending" || started.Valid)) || (job.State == "started" && (status != "running" || !started.Valid || job.StartedAt == nil || !started.Time.Equal(*job.StartedAt))) {
		return ErrCapacityDispatchClaim
	}
	if job.State == "returned" && ((status != "succeeded" && status != "failed") || !started.Valid || job.StartedAt == nil || !started.Time.Equal(*job.StartedAt) || !finished.Valid || job.ReturnedAt == nil || !finished.Time.Equal(*job.ReturnedAt)) {
		return ErrCapacityDispatchClaim
	}
	var i, m map[string]any
	if json.Unmarshal(inputs, &i) != nil || json.Unmarshal(metadata, &m) != nil {
		return ErrCapacityDispatchClaim
	}
	inputsSHA, metadataSHA, err := CapacityDispatchEnvelopeHashes(CapacityDispatchEnvelope{Inputs: i, Metadata: m})
	if err != nil || inputsSHA != job.InputsSHA256 || metadataSHA != job.MetadataSHA256 {
		return ErrCapacityDispatchClaim
	}
	pins := []struct {
		kind string
		pin  CapacityDispatchManifestPin
	}{{"capacity_policy", job.Policy}, {"workflow", job.Workflow}, {"rbac", job.RBAC}}
	if job.AuthorizationPolicy != nil {
		pins = append(pins, struct {
			kind string
			pin  CapacityDispatchManifestPin
		}{"policy", *job.AuthorizationPolicy})
	}
	for _, p := range pins {
		var current bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.manifests WHERE id=$1 AND kind=$2 AND namespace=$3 AND name=$4 AND version=$5 AND checksum=$6 AND active=TRUE)`, p.pin.ID, p.kind, p.pin.Namespace, p.pin.Name, p.pin.Version, p.pin.Checksum).Scan(&current); err != nil || !current {
			return ErrCapacityDispatchClaim
		}
	}
	return nil
}

func encodeCapacityDispatchEnvelope(e CapacityDispatchEnvelope) ([]byte, error) {
	if e.Protocol != CapacityDispatchProtocol || e.JobID == uuid.Nil || e.RunID == uuid.Nil || !capacityDispatchText(e.Realm, 64) || e.Policy.Namespace != e.Realm || !capacityDispatchText(e.Environment, 128) || !capacityDispatchText(e.Domain, 128) || !capacityDispatchText(e.Dimension, 128) || !capacityDispatchText(e.SourceTick, 256) || !capacityDispatchText(e.MachinePrincipalID, 128) || !capacityDispatchPin(e.Policy) || !capacityDispatchPin(e.Workflow) || !capacityDispatchPin(e.RBAC) || (e.AuthorizationPolicy != nil && !capacityDispatchPin(*e.AuthorizationPolicy)) || !capacityDispatchDigest(e.PrincipalSHA256) || !capacityDispatchDigest(e.BindingSHA256) {
		return nil, ErrCapacityDispatchEnvelope
	}
	// Accept only the fixed policy selector. Raw caller inputs and source
	// measurements cannot cross this admission boundary.
	expected, _ := json.Marshal(map[string]any{"policy": map[string]any{"namespace": e.Policy.Namespace, "name": e.Policy.Name}})
	inputs, err := capacityDispatchCanonicalJSON(e.Inputs)
	if err != nil || string(inputs) != string(expected) {
		return nil, ErrCapacityDispatchEnvelope
	}
	if e.Metadata[WorkflowRunCreatorMachinePrincipalMetadataKey] != e.MachinePrincipalID || e.Metadata["manifest_id"] != e.Workflow.ID.String() {
		return nil, ErrCapacityDispatchEnvelope
	}
	demand := e.Metadata["triggered_by"] == "capacity_demand"
	if demand {
		eventID, ok := e.Metadata["source_event_id"].(string)
		runID, runOK := e.Metadata["source_run_id"].(string)
		workflowID, workflowOK := e.Metadata["source_workflow_id"].(string)
		bodySHA, hashOK := e.Metadata["source_event_sha256"].(string)
		if !ok || !runOK || !workflowOK || !hashOK || !canonicalDemandUUID(eventID) || !canonicalDemandUUID(runID) || !canonicalDemandUUID(workflowID) || !capacityDispatchDigest(bodySHA) || e.SourceTick != "event:"+eventID {
			return nil, ErrCapacityDispatchEnvelope
		}
	} else if e.Metadata["triggered_by"] != "workflow_scheduler" || e.Metadata["scheduled_for"] != e.SourceTick {
		return nil, ErrCapacityDispatchEnvelope
	}
	for key, value := range e.Metadata {
		s, ok := value.(string)
		if !ok || !capacityDispatchText(s, 256) {
			return nil, ErrCapacityDispatchEnvelope
		}
		switch key {
		case WorkflowRunCreatorMachinePrincipalMetadataKey, "triggered_by", "manifest_id":
		case "scheduled_for":
			if demand {
				return nil, ErrCapacityDispatchEnvelope
			}
		case "source_event_id", "source_run_id", "source_workflow_id", "source_event_sha256":
			if !demand {
				return nil, ErrCapacityDispatchEnvelope
			}
		case "capacity_dispatch_protocol":
			if s != e.Protocol {
				return nil, ErrCapacityDispatchEnvelope
			}
		case "capacity_dispatch_job_id":
			if s != e.JobID.String() {
				return nil, ErrCapacityDispatchEnvelope
			}
		default:
			return nil, ErrCapacityDispatchEnvelope
		}
	}
	i, m, err := CapacityDispatchEnvelopeHashes(e)
	if err != nil || e.InputsSHA256 != i || e.MetadataSHA256 != m {
		return nil, ErrCapacityDispatchEnvelope
	}
	raw, err := capacityDispatchCanonicalJSON(e)
	if err != nil || len(raw) > 16384 {
		return nil, ErrCapacityDispatchEnvelope
	}
	return raw, nil
}

func capacityDispatchPin(p CapacityDispatchManifestPin) bool {
	return p.ID != uuid.Nil && capacityDispatchText(p.Namespace, 64) && capacityDispatchText(p.Name, 64) && p.Version > 0 && capacityDispatchDigest(p.Checksum)
}

func capacityDispatchText(s string, limit int) bool {
	return s != "" && len(s) <= limit && s == strings.TrimSpace(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func capacityDispatchDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func capacityDispatchSHA(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func capacityDispatchCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err = d.Decode(&normalized); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}
