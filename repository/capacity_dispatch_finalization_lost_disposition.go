package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ADR-0090: an administrative terminal for a started dispatch whose original
// executor returned (shown only by operator evidence, for example the
// PostgreSQL log of the cancelled finalization) but whose first finalization
// write was lost with the process that held the in-memory return. It never
// re-dispatches, never writes returned_at, return_status or the original
// acknowledgment, and records the historical return as unknown.
const (
	CapacityDispatchFinalizationLostReason      = "finalization_lost_started_dispatch_disposed"
	CapacityDispatchFinalizationLostRunError    = "finalization_lost_disposed: return observed but not recorded; historical outcome unknown"
	CapacityDispatchFinalizationLostObservation = "observed_by_operator_evidence_not_recorded"
	CapacityDispatchFinalizationLostScanSchema  = "finalization_lost_dispatch_effect_scan_v1"
	// Operator evidence is opaque UTF-8 text of at most this many bytes.
	CapacityDispatchFinalizationLostEvidenceMax = 8192
)

var ErrCapacityDispatchFinalizationLostDisposition = errors.New("finalization-lost started capacity dispatch disposition refused")

// Every HTTP field except Evidence is a compare-and-swap expectation, never
// authority. Evidence is retained verbatim with its SHA-256 and is never
// parsed. Issuer comes from the authenticated administrative boundary only.
type CapacityDispatchFinalizationLostDispositionRequest struct {
	JobID                    uuid.UUID `json:"job_id"`
	ExpectedRunID            uuid.UUID `json:"expected_run_id"`
	ExpectedEnvelopeSHA256   string    `json:"expected_envelope_sha256"`
	ExpectedFencingToken     int64     `json:"expected_fencing_token"`
	ExpectedLeaseOwner       uuid.UUID `json:"expected_lease_owner"`
	ExpectedPendingWakeCount int       `json:"expected_pending_wake_count"`
	Evidence                 string    `json:"finalization_evidence"`
	Issuer                   string    `json:"-"`
}

// The migration83 scan plus the two tolerated, row-proved bookkeeping
// effects. Its JSON is the flat object produced by
// public.finalization_lost_dispatch_effect_scan.
type CapacityDispatchFinalizationLostEffectScan struct {
	CapacityDispatchAbandonedEffectScan
	Schema                        string `json:"schema"`
	BaseSchema                    string `json:"base_schema"`
	PureAssessmentIntentUpdates   int64  `json:"pure_assessment_intent_updates"`
	ObservationRefreshSlotUpdates int64  `json:"observation_refresh_slot_updates"`
}

// tolerable mirrors public.finalization_lost_dispatch_effect_scan_tolerable:
// every migration83 counter is zero except at most one intent update that is
// a proved unleased hold with no generation, fence or phase move (other intent
// fields are not compared; see ADR-0090) and slot updates that are proved
// observation refreshes.
func (s CapacityDispatchFinalizationLostEffectScan) tolerable() bool {
	base := s.CapacityDispatchAbandonedEffectScan
	if s.Schema != CapacityDispatchFinalizationLostScanSchema || s.BaseSchema != CapacityDispatchAbandonedScanSchema ||
		base.IntentsUpdatedSinceStart < 0 || base.IntentsUpdatedSinceStart > 1 ||
		base.IntentsUpdatedSinceStart != s.PureAssessmentIntentUpdates ||
		base.ResourceSlotsUpdatedSinceStart < 0 || base.ResourceSlotsUpdatedSinceStart != s.ObservationRefreshSlotUpdates {
		return false
	}
	base.Schema = CapacityDispatchAbandonedScanSchema
	base.IntentsUpdatedSinceStart, base.ResourceSlotsUpdatedSinceStart = 0, 0
	return base.zero()
}

// The immutable receipt joined with the current (terminal) job and run. The
// evidence body is kept in the database; reads export its hash and size.
type CapacityDispatchFinalizationLostDisposition struct {
	ID                       uuid.UUID                                  `json:"id"`
	JobID                    uuid.UUID                                  `json:"job_id"`
	RunID                    uuid.UUID                                  `json:"run_id"`
	Realm                    string                                     `json:"realm"`
	Environment              string                                     `json:"environment"`
	Domain                   string                                     `json:"domain"`
	Dimension                string                                     `json:"dimension"`
	EnvelopeSHA256           string                                     `json:"envelope_sha256"`
	FencingToken             int64                                      `json:"fencing_token"`
	LeaseOwner               uuid.UUID                                  `json:"lease_owner"`
	LeaseExpiresAt           time.Time                                  `json:"lease_expires_at"`
	StartedAt                time.Time                                  `json:"started_at"`
	PendingWakeCount         int                                        `json:"pending_wake_count"`
	OriginalDispatchSHA256   string                                     `json:"original_dispatch_sha256"`
	OriginalRunSHA256        string                                     `json:"original_run_sha256"`
	ExecutorBarrier          string                                     `json:"executor_barrier"`
	CoreProcessStartedAt     time.Time                                  `json:"disposing_core_process_started_at"`
	CoreHostname             string                                     `json:"disposing_core_hostname"`
	CorePID                  int                                        `json:"disposing_core_pid"`
	CoreSourceCommit         string                                     `json:"disposing_core_source_commit"`
	MinimumLeaseAgeSeconds   int                                        `json:"minimum_lease_age_seconds"`
	RecordedAt               time.Time                                  `json:"recorded_at"`
	Issuer                   string                                     `json:"issuer"`
	Reason                   string                                     `json:"reason"`
	ReturnObservation        string                                     `json:"return_observation"`
	HistoricalReturn         string                                     `json:"historical_return"`
	RunStatus                string                                     `json:"run_status"`
	RunError                 string                                     `json:"run_error"`
	EvidenceSHA256           string                                     `json:"operator_evidence_sha256"`
	EvidenceBytes            int                                        `json:"operator_evidence_bytes"`
	EffectScan               CapacityDispatchFinalizationLostEffectScan `json:"provider_mutation_evidence"`
	State                    string                                     `json:"state"`
	ReturnedAt               *time.Time                                 `json:"returned_at"`
	FinalizationAckAt        *time.Time                                 `json:"finalization_ack_at"`
	WorkflowRunStatus        string                                     `json:"workflow_run_status"`
	WorkflowRunFinishedAt    *time.Time                                 `json:"workflow_run_finished_at"`
	WorkflowRunResultPresent bool                                       `json:"workflow_run_result_present"`
}

// ValidCapacityDispatchFinalizationEvidence accepts non-empty valid UTF-8 of
// at most 8 KiB with no control character other than tab, CR and LF.
func ValidCapacityDispatchFinalizationEvidence(evidence string) bool {
	if evidence == "" || len(evidence) > CapacityDispatchFinalizationLostEvidenceMax || !utf8.ValidString(evidence) || strings.TrimSpace(evidence) == "" {
		return false
	}
	for _, r := range evidence {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return false
		}
	}
	return true
}

func capacityDispatchFinalizationEvidenceSHA(evidence string) string {
	sum := sha256.Sum256([]byte(evidence))
	return hex.EncodeToString(sum[:])
}

func validCapacityDispatchFinalizationLostRequest(r CapacityDispatchFinalizationLostDispositionRequest) bool {
	return ValidCapacityDispatchFinalizationEvidence(r.Evidence) && validCapacityDispatchAbandonedRequest(CapacityDispatchAbandonedDispositionRequest{
		JobID: r.JobID, ExpectedRunID: r.ExpectedRunID, ExpectedEnvelopeSHA256: r.ExpectedEnvelopeSHA256, ExpectedFencingToken: r.ExpectedFencingToken,
		ExpectedLeaseOwner: r.ExpectedLeaseOwner, ExpectedPendingWakeCount: r.ExpectedPendingWakeCount, Issuer: r.Issuer,
	})
}

// DisposeFinalizationLostStartedDispatch closes one started job
// administratively in a single transaction, in the ADR-0089 lock order: scope
// advisory lock (Enqueue order), job FOR UPDATE, run FOR UPDATE, then receipt,
// job terminal and run close. revalidate rechecks the current operator at the
// commit boundary. A refused precondition writes nothing; the caller must
// re-read state and never retry blind.
func DisposeFinalizationLostStartedDispatch(ctx context.Context, db *sql.DB, r CapacityDispatchFinalizationLostDispositionRequest, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (CapacityDispatchFinalizationLostDisposition, error) {
	refused := CapacityDispatchFinalizationLostDisposition{}
	if db == nil || revalidate == nil || !validCapacityDispatchFinalizationLostRequest(r) || !validCapacityDispatchExecutorBarrier(barrier) || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	defer tx.Rollback()
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil || !capacityDispatchAbandonedLockSafe(initial.Realm, initial.Environment, initial.Domain, initial.Dimension) {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(scope)); err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	if err != nil || job.Realm != initial.Realm || job.Environment != initial.Environment || job.Domain != initial.Domain || job.Dimension != initial.Dimension {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	var now time.Time
	var returnStatus, returnError, finalizationError, failedID, nativeID, enrolledID, abandonedID, lostID sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),return_status,return_error,finalization_error,failed_original_disposition_id::text,native_denied_disposition_id::text,enrolled_failed_disposition_id::text,abandoned_disposition_id::text,finalization_lost_disposition_id::text FROM public.capacity_dispatch_jobs WHERE id=$1`, job.JobID).
		Scan(&now, &returnStatus, &returnError, &finalizationError, &failedID, &nativeID, &enrolledID, &abandonedID, &lostID); err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if job.Protocol != CapacityDispatchProtocol || job.State != "started" || job.StartedAt == nil || job.ReturnedAt != nil || job.FinalizationAckAt != nil ||
		returnStatus.Valid || returnError.Valid || finalizationError.Valid || failedID.Valid || nativeID.Valid || enrolledID.Valid || abandonedID.Valid || lostID.Valid ||
		job.LeaseExpiresAt == nil || job.LeaseOwner == uuid.Nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken ||
		job.LeaseOwner != r.ExpectedLeaseOwner || job.PendingWakeCount != r.ExpectedPendingWakeCount ||
		now.Before(job.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) ||
		!barrier.ProcessStartedAt.After(*job.LeaseExpiresAt) || barrier.ProcessStartedAt.After(now) {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if err = checkCapacityDispatchAbandonedRun(ctx, tx, job); err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	var scanRaw string
	if err = tx.QueryRowContext(ctx, `SELECT public.finalization_lost_dispatch_effect_scan($1,$2,$3,$4,$5,$6,$7)::text`, job.Realm, job.Environment, job.Domain, job.Dimension, job.JobID, *job.StartedAt, *job.LeaseExpiresAt).Scan(&scanRaw); err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	scan, err := decodeCapacityDispatchFinalizationLostScan([]byte(scanRaw))
	if err != nil || !scan.tolerable() {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	id := uuid.New()
	var recordedAt time.Time
	if err = tx.QueryRowContext(ctx, `INSERT INTO public.capacity_dispatch_finalization_lost_dispositions(id,job_id,run_id,realm,environment,domain,dimension,envelope_sha256,fencing_token,lease_owner,lease_expires_at,started_at,pending_wake_count,original_dispatch_sha256,original_run_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,minimum_lease_age_seconds,recorded_at,issuer,reason,return_observation,historical_return,run_status,run_error,operator_evidence,operator_evidence_sha256,provider_mutation_evidence)
SELECT $1,j.id,j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count,
 encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),
 $3,$4,$5,$6,$7,$8,clock_timestamp(),$9,$10,$11,'unknown','failed',$12,$13,$14,$15::jsonb
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$2
RETURNING recorded_at`,
		id, job.JobID, CapacityDispatchAbandonedBarrier, barrier.ProcessStartedAt, barrier.Hostname, barrier.PID, barrier.SourceCommit,
		capacityDispatchAbandonedMinimumAgeSec, r.Issuer, CapacityDispatchFinalizationLostReason, CapacityDispatchFinalizationLostObservation,
		CapacityDispatchFinalizationLostRunError, r.Evidence, capacityDispatchFinalizationEvidenceSHA(r.Evidence), scanRaw).Scan(&recordedAt); err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='finalization_lost_disposed',finalization_lost_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1 AND state='started' AND run_id=$3 AND envelope_sha256=$4 AND fencing_token=$5 AND lease_owner=$6 AND pending_wake_count=$7 AND returned_at IS NULL AND finalization_ack_at IS NULL AND abandoned_disposition_id IS NULL AND finalization_lost_disposition_id IS NULL`,
		job.JobID, id, job.RunID, job.EnvelopeSHA256, job.FencingToken, job.LeaseOwner, job.PendingWakeCount)
	if err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	// Administrative close of the original run, NOT its return: the fixed error
	// says the return was observed but not recorded and its outcome is unknown.
	result, err = tx.ExecContext(ctx, `UPDATE public.workflow_runs SET status='failed',error=$2,finished_at=$3,updated_at=clock_timestamp() WHERE id=$1 AND status='running' AND started_at=$4 AND finished_at IS NULL AND result IS NULL AND error IS NULL`,
		job.RunID, CapacityDispatchFinalizationLostRunError, recordedAt, *job.StartedAt)
	if err != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	receipt, err := readCapacityDispatchFinalizationLostDisposition(ctx, tx, job.JobID)
	if err != nil || receipt.ID != id || receipt.RunID != job.RunID || receipt.FencingToken != job.FencingToken || receipt.EvidenceSHA256 != capacityDispatchFinalizationEvidenceSHA(r.Evidence) {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchFinalizationLostDisposition, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		// Read the immutable receipt to reconcile a late/unknown HTTP result.
		return refused, ErrCapacityDispatchFinalizationLostDisposition
	}
	return receipt, nil
}

func decodeCapacityDispatchFinalizationLostScan(raw []byte) (CapacityDispatchFinalizationLostEffectScan, error) {
	var scan CapacityDispatchFinalizationLostEffectScan
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&scan); err != nil || d.More() || scan.Schema != CapacityDispatchFinalizationLostScanSchema {
		return CapacityDispatchFinalizationLostEffectScan{}, ErrCapacityDispatchFinalizationLostDisposition
	}
	return scan, nil
}

func ReadCapacityDispatchFinalizationLostDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (CapacityDispatchFinalizationLostDisposition, error) {
	if db == nil || jobID == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchFinalizationLostDisposition{}, ErrCapacityDispatchFinalizationLostDisposition
	}
	return readCapacityDispatchFinalizationLostDisposition(ctx, db, jobID)
}

func readCapacityDispatchFinalizationLostDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (CapacityDispatchFinalizationLostDisposition, error) {
	var d CapacityDispatchFinalizationLostDisposition
	var scanRaw string
	var returned, acknowledged, runFinished sql.NullTime
	var linked uuid.NullUUID
	err := db.QueryRowContext(ctx, `SELECT d.id,d.job_id,d.run_id,d.realm,d.environment,d.domain,d.dimension,d.envelope_sha256,d.fencing_token,d.lease_owner,d.lease_expires_at,d.started_at,d.pending_wake_count,d.original_dispatch_sha256,d.original_run_sha256,d.executor_barrier,d.disposing_core_process_started_at,d.disposing_core_hostname,d.disposing_core_pid,d.disposing_core_source_commit,d.minimum_lease_age_seconds,d.recorded_at,d.issuer,d.reason,d.return_observation,d.historical_return,d.run_status,d.run_error,d.operator_evidence_sha256,octet_length(d.operator_evidence),d.provider_mutation_evidence::text,
 j.state,j.returned_at,j.finalization_ack_at,j.finalization_lost_disposition_id,w.status,w.finished_at,w.result IS NOT NULL
 FROM public.capacity_dispatch_finalization_lost_dispositions d
 JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id AND j.envelope_sha256=d.envelope_sha256 AND j.fencing_token=d.fencing_token AND j.lease_owner=d.lease_owner
 JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(
		&d.ID, &d.JobID, &d.RunID, &d.Realm, &d.Environment, &d.Domain, &d.Dimension, &d.EnvelopeSHA256, &d.FencingToken, &d.LeaseOwner,
		&d.LeaseExpiresAt, &d.StartedAt, &d.PendingWakeCount, &d.OriginalDispatchSHA256, &d.OriginalRunSHA256, &d.ExecutorBarrier,
		&d.CoreProcessStartedAt, &d.CoreHostname, &d.CorePID, &d.CoreSourceCommit, &d.MinimumLeaseAgeSeconds, &d.RecordedAt, &d.Issuer,
		&d.Reason, &d.ReturnObservation, &d.HistoricalReturn, &d.RunStatus, &d.RunError, &d.EvidenceSHA256, &d.EvidenceBytes, &scanRaw,
		&d.State, &returned, &acknowledged, &linked, &d.WorkflowRunStatus, &runFinished, &d.WorkflowRunResultPresent)
	if err != nil {
		return CapacityDispatchFinalizationLostDisposition{}, ErrCapacityDispatchFinalizationLostDisposition
	}
	if d.EffectScan, err = decodeCapacityDispatchFinalizationLostScan([]byte(scanRaw)); err != nil || !d.EffectScan.tolerable() ||
		d.State != "finalization_lost_disposed" || !linked.Valid || linked.UUID != d.ID || returned.Valid || acknowledged.Valid ||
		d.Reason != CapacityDispatchFinalizationLostReason || d.ReturnObservation != CapacityDispatchFinalizationLostObservation ||
		d.HistoricalReturn != "unknown" || d.ExecutorBarrier != CapacityDispatchAbandonedBarrier ||
		d.RunStatus != "failed" || d.RunError != CapacityDispatchFinalizationLostRunError || d.WorkflowRunStatus != d.RunStatus ||
		!runFinished.Valid || !runFinished.Time.Equal(d.RecordedAt) || d.WorkflowRunResultPresent ||
		d.EvidenceBytes < 1 || d.EvidenceBytes > CapacityDispatchFinalizationLostEvidenceMax || !capacityDispatchDigest(d.EvidenceSHA256) ||
		!d.CoreProcessStartedAt.After(d.LeaseExpiresAt) || d.RecordedAt.Before(d.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) {
		return CapacityDispatchFinalizationLostDisposition{}, ErrCapacityDispatchFinalizationLostDisposition
	}
	d.WorkflowRunFinishedAt = &runFinished.Time
	return d, nil
}
