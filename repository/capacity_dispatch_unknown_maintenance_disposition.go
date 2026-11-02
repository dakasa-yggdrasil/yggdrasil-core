package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	CapacityDispatchUnknownMaintenanceReason     = "unknown_failed_maintenance_dispatch_disposed"
	CapacityDispatchUnknownMaintenanceScanSchema = "unknown_maintenance_dispatch_effect_scan_v1"
)

var ErrCapacityDispatchUnknownMaintenanceDisposition = errors.New("unknown failed maintenance dispatch disposition refused")

// Closed CAS expectations. None is authority and Issuer is server-owned.
type CapacityDispatchUnknownMaintenanceDispositionRequest struct {
	CapacityDispatchAbandonedDispositionRequest
	ExpectedReturnedAt    time.Time `json:"expected_returned_at"`
	ExpectedRunSHA256     string    `json:"expected_run_sha256"`
	ExpectedMembersSHA256 string    `json:"expected_members_sha256"`
}

type CapacityDispatchUnknownMaintenanceEffectScan struct {
	Schema                       string                                     `json:"schema"`
	Base                         CapacityDispatchFinalizationLostEffectScan `json:"base"`
	CurrentMembers               json.RawMessage                            `json:"current_members"`
	CurrentMembersSHA256         string                                     `json:"current_members_sha256"`
	CurrentMemberCount           int                                        `json:"current_member_count"`
	PolicyEpochValid             bool                                       `json:"policy_epoch_valid"`
	RefreshOnlyResult            bool                                       `json:"refresh_only_result"`
	InvalidMaintenanceCanaryRows int                                        `json:"invalid_maintenance_canary_rows"`
}

func (s CapacityDispatchUnknownMaintenanceEffectScan) tolerable() bool {
	base := s.Base
	if base.CanaryChallengesSinceStart < 0 || base.CanaryNoncesSinceStart < 0 || base.CanaryPossibleSendsSinceStart < 0 || base.CanaryReturnsSinceStart < 0 {
		return false
	}
	base.CanaryChallengesSinceStart, base.CanaryNoncesSinceStart, base.CanaryPossibleSendsSinceStart, base.CanaryReturnsSinceStart = 0, 0, 0, 0
	var members []json.RawMessage
	return s.Schema == CapacityDispatchUnknownMaintenanceScanSchema && s.PolicyEpochValid && s.RefreshOnlyResult && s.InvalidMaintenanceCanaryRows == 0 &&
		s.CurrentMemberCount >= 1 && s.CurrentMemberCount <= 8 && json.Unmarshal(s.CurrentMembers, &members) == nil && len(members) == s.CurrentMemberCount &&
		capacityDispatchDigest(s.CurrentMembersSHA256) && base.tolerable()
}

type CapacityDispatchUnknownMaintenanceDisposition struct {
	ID                     uuid.UUID                                    `json:"id"`
	JobID                  uuid.UUID                                    `json:"job_id"`
	RunID                  uuid.UUID                                    `json:"run_id"`
	OriginalDispatchSHA256 string                                       `json:"original_dispatch_sha256"`
	OriginalRunSHA256      string                                       `json:"original_run_sha256"`
	OriginalReturnedAt     time.Time                                    `json:"original_returned_at"`
	CurrentMembersSHA256   string                                       `json:"current_members_sha256"`
	ExecutorBarrier        string                                       `json:"executor_barrier"`
	CoreProcessStartedAt   time.Time                                    `json:"disposing_core_process_started_at"`
	CoreHostname           string                                       `json:"disposing_core_hostname"`
	CorePID                int                                          `json:"disposing_core_pid"`
	CoreSourceCommit       string                                       `json:"disposing_core_source_commit"`
	Issuer                 string                                       `json:"issuer"`
	Reason                 string                                       `json:"reason"`
	HistoricalReturn       string                                       `json:"historical_return"`
	RecordedAt             time.Time                                    `json:"recorded_at"`
	EffectScan             CapacityDispatchUnknownMaintenanceEffectScan `json:"provider_mutation_evidence"`
	State                  string                                       `json:"dispatch_state"`
}

func validCapacityDispatchUnknownMaintenanceRequest(r CapacityDispatchUnknownMaintenanceDispositionRequest) bool {
	return validCapacityDispatchAbandonedRequest(r.CapacityDispatchAbandonedDispositionRequest) && !r.ExpectedReturnedAt.IsZero() &&
		capacityDispatchDigest(r.ExpectedRunSHA256) && capacityDispatchDigest(r.ExpectedMembersSHA256)
}

// This transaction does not run a workflow or update its historical return.
// It locks scope -> job -> run, proves the failed refresh and closed evidence,
// writes one immutable receipt and moves only the job to its distinct terminal.
func DisposeUnknownMaintenanceDispatch(ctx context.Context, db *sql.DB, r CapacityDispatchUnknownMaintenanceDispositionRequest, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (CapacityDispatchUnknownMaintenanceDisposition, error) {
	refused := CapacityDispatchUnknownMaintenanceDisposition{}
	if db == nil || revalidate == nil || !validCapacityDispatchUnknownMaintenanceRequest(r) || !validCapacityDispatchExecutorBarrier(barrier) || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	defer tx.Rollback()
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil || !capacityDispatchAbandonedLockSafe(initial.Realm, initial.Environment, initial.Domain, initial.Dimension) {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(scope)); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	if err != nil || job.Realm != initial.Realm || job.Environment != initial.Environment || job.Domain != initial.Domain || job.Dimension != initial.Dimension ||
		job.Protocol != CapacityDispatchProtocol || job.State != "unknown" || job.StartedAt == nil || job.ReturnedAt == nil || job.LeaseExpiresAt == nil || job.FinalizationAckAt != nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken || job.LeaseOwner != r.ExpectedLeaseOwner ||
		job.PendingWakeCount != r.ExpectedPendingWakeCount || !job.ReturnedAt.Equal(r.ExpectedReturnedAt) {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	// Catalog publication does not take the capacity scope lock. Keep exact
	// pinned manifests and current membership rows locked through the commit.
	authorizationID := uuid.Nil
	if job.AuthorizationPolicy != nil {
		authorizationID = job.AuthorizationPolicy.ID
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM public.manifests WHERE id IN($1,$2,$3,$4) ORDER BY id FOR SHARE`, job.Policy.ID, job.Workflow.ID, job.RBAC.ID, authorizationID); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT namespace FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT slot FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY id FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	var now time.Time
	var runSHA string
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM public.workflow_runs w WHERE id=$1 FOR UPDATE`, job.RunID).Scan(&now, &runSHA); err != nil ||
		runSHA != r.ExpectedRunSHA256 || now.Before(job.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) || !barrier.ProcessStartedAt.After(*job.LeaseExpiresAt) || barrier.ProcessStartedAt.After(now) ||
		checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	var raw string
	var accepted bool
	if err = tx.QueryRowContext(ctx, `WITH s AS (SELECT public.unknown_maintenance_dispatch_effect_scan($1) AS evidence) SELECT evidence::text,public.unknown_maintenance_dispatch_effect_scan_tolerable(evidence) FROM s`, job.JobID).Scan(&raw, &accepted); err != nil || !accepted {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	var scan CapacityDispatchUnknownMaintenanceEffectScan
	if json.Unmarshal([]byte(raw), &scan) != nil || !scan.tolerable() || scan.CurrentMembersSHA256 != r.ExpectedMembersSHA256 {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	id := uuid.New()
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_unknown_maintenance_dispositions(id,job_id,run_id,original_dispatch_sha256,original_run_sha256,original_returned_at,current_members_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,issuer,reason,historical_return,recorded_at,provider_mutation_evidence)
 SELECT $1,j.id,j.run_id,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),$3,j.returned_at,$4,$5,$6,$7,$8,$9,$10,$11,'unknown',clock_timestamp(),$12::jsonb FROM public.capacity_dispatch_jobs j WHERE j.id=$2`,
		id, job.JobID, runSHA, r.ExpectedMembersSHA256, CapacityDispatchAbandonedBarrier, barrier.ProcessStartedAt, barrier.Hostname, barrier.PID, barrier.SourceCommit, r.Issuer, CapacityDispatchUnknownMaintenanceReason, raw); err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='unknown_maintenance_disposed',unknown_maintenance_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1 AND state='unknown' AND finalization_ack_at IS NULL AND unknown_maintenance_disposition_id IS NULL`, job.JobID, id)
	if err != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	receipt, err := readCapacityDispatchUnknownMaintenanceDisposition(ctx, tx, job.JobID)
	if err != nil || receipt.ID != id || receipt.OriginalRunSHA256 != runSHA {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchUnknownMaintenanceDisposition, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	return receipt, nil
}

func ReadCapacityDispatchUnknownMaintenanceDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (CapacityDispatchUnknownMaintenanceDisposition, error) {
	if db == nil || jobID == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchUnknownMaintenanceDisposition{}, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	return readCapacityDispatchUnknownMaintenanceDisposition(ctx, db, jobID)
}

func readCapacityDispatchUnknownMaintenanceDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (CapacityDispatchUnknownMaintenanceDisposition, error) {
	var d CapacityDispatchUnknownMaintenanceDisposition
	var raw, runSHA, runStatus, runError, returnStatus, returnError string
	var returned, ack sql.NullTime
	var linked uuid.NullUUID
	err := db.QueryRowContext(ctx, `SELECT d.id,d.job_id,d.run_id,d.original_dispatch_sha256,d.original_run_sha256,d.original_returned_at,d.current_members_sha256,d.executor_barrier,d.disposing_core_process_started_at,d.disposing_core_hostname,d.disposing_core_pid,d.disposing_core_source_commit,d.issuer,d.reason,d.historical_return,d.recorded_at,d.provider_mutation_evidence::text,j.state,j.returned_at,j.finalization_ack_at,j.unknown_maintenance_disposition_id,
 encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),w.status,w.error,j.return_status,j.return_error
 FROM public.capacity_dispatch_unknown_maintenance_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(
		&d.ID, &d.JobID, &d.RunID, &d.OriginalDispatchSHA256, &d.OriginalRunSHA256, &d.OriginalReturnedAt, &d.CurrentMembersSHA256, &d.ExecutorBarrier, &d.CoreProcessStartedAt, &d.CoreHostname, &d.CorePID, &d.CoreSourceCommit, &d.Issuer, &d.Reason, &d.HistoricalReturn, &d.RecordedAt, &raw, &d.State, &returned, &ack, &linked, &runSHA, &runStatus, &runError, &returnStatus, &returnError)
	if err != nil || json.Unmarshal([]byte(raw), &d.EffectScan) != nil || !d.EffectScan.tolerable() || d.EffectScan.CurrentMembersSHA256 != d.CurrentMembersSHA256 ||
		d.State != "unknown_maintenance_disposed" || !linked.Valid || linked.UUID != d.ID || !returned.Valid || !returned.Time.Equal(d.OriginalReturnedAt) || ack.Valid ||
		d.OriginalRunSHA256 != runSHA || runStatus != "failed" || returnStatus != "failed" || runError != returnError || returnError != "capacity dispatch original deadline exceeded" ||
		d.Reason != CapacityDispatchUnknownMaintenanceReason || d.HistoricalReturn != "unknown" || d.ExecutorBarrier != CapacityDispatchAbandonedBarrier {
		return CapacityDispatchUnknownMaintenanceDisposition{}, ErrCapacityDispatchUnknownMaintenanceDisposition
	}
	return d, nil
}
