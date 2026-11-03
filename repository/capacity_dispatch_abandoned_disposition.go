package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ADR-0089: an administrative terminal for a started dispatch whose executor
// is gone and whose actual return was never recorded. It never re-dispatches,
// never writes returned_at, return_status or the original acknowledgment, and
// records the historical return as unknown.
const (
	CapacityDispatchAbandonedReason        = "abandoned_started_dispatch_disposed"
	CapacityDispatchAbandonedRunError      = "abandoned_started_dispatch_disposed: historical outcome unknown"
	CapacityDispatchAbandonedBarrier       = "disposing_core_process_started_after_lease_expiry_v1"
	CapacityDispatchAbandonedScanSchema    = "abandoned_started_dispatch_effect_scan_v2"
	CapacityDispatchAbandonedMinimumAge    = 15 * time.Minute
	capacityDispatchAbandonedMinimumAgeSec = 900
	// The effect scan window opens this many seconds before the database
	// started_at, because many scanned columns carry application clock values.
	CapacityDispatchAbandonedClockSkewMarginSec = 30
)

var ErrCapacityDispatchAbandonedDisposition = errors.New("abandoned started capacity dispatch disposition refused")

var capacityDispatchAbandonedHostname = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
var capacityDispatchAbandonedSource = regexp.MustCompile(`^([0-9a-f]{40})?$`)

// Every HTTP field is a compare-and-swap expectation, never authority. Issuer
// comes from the authenticated administrative boundary only.
type CapacityDispatchAbandonedDispositionRequest struct {
	JobID                    uuid.UUID `json:"job_id"`
	ExpectedRunID            uuid.UUID `json:"expected_run_id"`
	ExpectedEnvelopeSHA256   string    `json:"expected_envelope_sha256"`
	ExpectedFencingToken     int64     `json:"expected_fencing_token"`
	ExpectedLeaseOwner       uuid.UUID `json:"expected_lease_owner"`
	ExpectedPendingWakeCount int       `json:"expected_pending_wake_count"`
	Issuer                   string    `json:"-"`
}

// Server-owned facts about the Core process performing the disposal. They are
// never read from the request. A process that started after the original lease
// expired cannot be the original in-process executor of that claim; it says
// nothing about other replicas or about requests already accepted remotely.
type CapacityDispatchExecutorBarrier struct {
	ProcessStartedAt time.Time
	Hostname         string
	PID              int
	SourceCommit     string
}

// The closed in-database scan of the enumerated Core ledgers for the job
// scope since the possible start (minus the fixed clock-skew margin), plus the
// job's own original Notify-window marker with no time bound. All counts must
// be zero. It is not a provider read and not every Core table.
type CapacityDispatchAbandonedEffectScan struct {
	Schema                                 string `json:"schema"`
	ClockSkewMarginSeconds                 int64  `json:"clock_skew_margin_seconds"`
	GrantsCreatedOrUpdatedSince            int64  `json:"grants_created_or_updated_since_start"`
	OpenUndisposedGrants                   int64  `json:"open_undisposed_grants"`
	PreregistrationsSinceStart             int64  `json:"preregistrations_since_start"`
	CreateWitnessesSinceStart              int64  `json:"create_witnesses_since_start"`
	EnrollmentsSinceStart                  int64  `json:"enrollments_since_start"`
	InstallationsSinceStart                int64  `json:"installations_since_start"`
	QualificationProbeChallengesSinceStart int64  `json:"qualification_probe_challenges_since_start"`
	QualificationSourceReturnsSinceStart   int64  `json:"qualification_native_source_returns_since_start"`
	SourceRecoveryChallengesSinceStart     int64  `json:"source_recovery_cleanup_challenges_since_start"`
	SourceRecoveryEffectPermitsSinceStart  int64  `json:"source_recovery_cleanup_effect_permits_since_start"`
	PartialNativeOffReconciliationsSince   int64  `json:"partial_nativeoff_reconciliations_since_start"`
	PartialNativeOffReadsSinceStart        int64  `json:"partial_nativeoff_reads_since_start"`
	PrejournalRefusalRecoveriesSinceStart  int64  `json:"prejournal_refusal_recoveries_since_start"`
	PresendRetirementRecoveriesSinceStart  int64  `json:"presend_retirement_recoveries_since_start"`
	RetirementIntentsSinceStart            int64  `json:"retirement_intents_since_start"`
	RetirementContextsSinceStart           int64  `json:"retirement_contexts_since_start"`
	RetirementOriginalReturnsSinceStart    int64  `json:"retirement_original_returns_since_start"`
	RetirementDeleteBindingsSinceStart     int64  `json:"retirement_delete_bindings_since_start"`
	RetirementNativeReadbacksSinceStart    int64  `json:"retirement_native_readbacks_since_start"`
	CallerPossibleSendsSinceStart          int64  `json:"caller_possible_sends_since_start"`
	CallerReturnsSinceStart                int64  `json:"caller_returns_since_start"`
	RuntimeSnapshotChallengesSinceStart    int64  `json:"runtime_snapshot_challenges_since_start"`
	RuntimeSnapshotReturnsSinceStart       int64  `json:"runtime_snapshot_returns_since_start"`
	AuthorityReadsSinceStart               int64  `json:"authority_reads_since_start"`
	AuthorityReturnsSinceStart             int64  `json:"authority_returns_since_start"`
	AuthorityTransportReturnsSinceStart    int64  `json:"authority_transport_returns_since_start"`
	NativePoweroffReadsSinceStart          int64  `json:"native_poweroff_reads_since_start"`
	CanaryChallengesSinceStart             int64  `json:"canary_challenges_since_start"`
	CanaryNoncesSinceStart                 int64  `json:"canary_nonces_since_start"`
	CanaryPossibleSendsSinceStart          int64  `json:"canary_possible_sends_since_start"`
	CanaryReturnsSinceStart                int64  `json:"canary_returns_since_start"`
	IntentsUpdatedSinceStart               int64  `json:"intents_updated_since_start"`
	NotifyWindowMarkersForJob              int64  `json:"notify_window_markers_for_job"`
	IntentEventsSinceStart                 int64  `json:"intent_events_since_start"`
	NativeCommandsSinceStart               int64  `json:"native_commands_since_start"`
	NativeLifetimesUpdatedSinceStart       int64  `json:"native_lifetimes_updated_since_start"`
	NativeLifetimeArchivesSinceStart       int64  `json:"native_lifetime_archives_since_start"`
	NativePodCheckpointsSinceStart         int64  `json:"native_pod_checkpoints_since_start"`
	ExecutorActivityUpdatedSinceStart      int64  `json:"executor_activity_updated_since_start"`
	ResourceSlotsUpdatedSinceStart         int64  `json:"resource_slots_updated_since_start"`
	ProviderReadPerformed                  bool   `json:"provider_read_performed"`
	ProviderQuiescenceProved               bool   `json:"provider_quiescence_proved"`
}

func (s CapacityDispatchAbandonedEffectScan) zero() bool {
	counts := []int64{s.GrantsCreatedOrUpdatedSince, s.OpenUndisposedGrants, s.PreregistrationsSinceStart, s.CreateWitnessesSinceStart,
		s.EnrollmentsSinceStart, s.InstallationsSinceStart, s.QualificationProbeChallengesSinceStart, s.QualificationSourceReturnsSinceStart,
		s.SourceRecoveryChallengesSinceStart, s.SourceRecoveryEffectPermitsSinceStart, s.PartialNativeOffReconciliationsSince,
		s.PartialNativeOffReadsSinceStart, s.PrejournalRefusalRecoveriesSinceStart, s.PresendRetirementRecoveriesSinceStart,
		s.RetirementIntentsSinceStart, s.RetirementContextsSinceStart, s.RetirementOriginalReturnsSinceStart,
		s.RetirementDeleteBindingsSinceStart, s.RetirementNativeReadbacksSinceStart, s.CallerPossibleSendsSinceStart,
		s.CallerReturnsSinceStart, s.RuntimeSnapshotChallengesSinceStart, s.RuntimeSnapshotReturnsSinceStart,
		s.AuthorityReadsSinceStart, s.AuthorityReturnsSinceStart, s.AuthorityTransportReturnsSinceStart, s.NativePoweroffReadsSinceStart,
		s.CanaryChallengesSinceStart, s.CanaryNoncesSinceStart, s.CanaryPossibleSendsSinceStart, s.CanaryReturnsSinceStart,
		s.IntentsUpdatedSinceStart, s.NotifyWindowMarkersForJob, s.IntentEventsSinceStart, s.NativeCommandsSinceStart,
		s.NativeLifetimesUpdatedSinceStart, s.NativeLifetimeArchivesSinceStart, s.NativePodCheckpointsSinceStart,
		s.ExecutorActivityUpdatedSinceStart, s.ResourceSlotsUpdatedSinceStart}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return s.Schema == CapacityDispatchAbandonedScanSchema && s.ClockSkewMarginSeconds == CapacityDispatchAbandonedClockSkewMarginSec &&
		!s.ProviderReadPerformed && !s.ProviderQuiescenceProved
}

// The scope advisory-lock key is Go json.Marshal output here and in Enqueue,
// but array_to_json in the migration83 receipt guard. They are byte-identical
// only for printable ASCII without <, > and &, which Go HTML-escapes.
func capacityDispatchAbandonedLockSafe(names ...string) bool {
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "<>&") {
			return false
		}
		for i := 0; i < len(name); i++ {
			if name[i] < 0x20 || name[i] > 0x7e {
				return false
			}
		}
	}
	return true
}

// The immutable receipt joined with the current (terminal) job and run.
type CapacityDispatchAbandonedDisposition struct {
	ID                       uuid.UUID                           `json:"id"`
	JobID                    uuid.UUID                           `json:"job_id"`
	RunID                    uuid.UUID                           `json:"run_id"`
	Realm                    string                              `json:"realm"`
	Environment              string                              `json:"environment"`
	Domain                   string                              `json:"domain"`
	Dimension                string                              `json:"dimension"`
	EnvelopeSHA256           string                              `json:"envelope_sha256"`
	FencingToken             int64                               `json:"fencing_token"`
	LeaseOwner               uuid.UUID                           `json:"lease_owner"`
	LeaseExpiresAt           time.Time                           `json:"lease_expires_at"`
	StartedAt                time.Time                           `json:"started_at"`
	PendingWakeCount         int                                 `json:"pending_wake_count"`
	OriginalDispatchSHA256   string                              `json:"original_dispatch_sha256"`
	OriginalRunSHA256        string                              `json:"original_run_sha256"`
	ExecutorBarrier          string                              `json:"executor_barrier"`
	CoreProcessStartedAt     time.Time                           `json:"disposing_core_process_started_at"`
	CoreHostname             string                              `json:"disposing_core_hostname"`
	CorePID                  int                                 `json:"disposing_core_pid"`
	CoreSourceCommit         string                              `json:"disposing_core_source_commit"`
	MinimumLeaseAgeSeconds   int                                 `json:"minimum_lease_age_seconds"`
	RecordedAt               time.Time                           `json:"recorded_at"`
	Issuer                   string                              `json:"issuer"`
	Reason                   string                              `json:"reason"`
	HistoricalReturn         string                              `json:"historical_return"`
	RunStatus                string                              `json:"run_status"`
	RunError                 string                              `json:"run_error"`
	EffectScan               CapacityDispatchAbandonedEffectScan `json:"provider_mutation_evidence"`
	State                    string                              `json:"state"`
	ReturnedAt               *time.Time                          `json:"returned_at"`
	FinalizationAckAt        *time.Time                          `json:"finalization_ack_at"`
	WorkflowRunStatus        string                              `json:"workflow_run_status"`
	WorkflowRunFinishedAt    *time.Time                          `json:"workflow_run_finished_at"`
	WorkflowRunResultPresent bool                                `json:"workflow_run_result_present"`
}

func validCapacityDispatchAbandonedRequest(r CapacityDispatchAbandonedDispositionRequest) bool {
	actor := strings.TrimPrefix(r.Issuer, "collaborator:")
	actorID, err := uuid.Parse(actor)
	return r.JobID != uuid.Nil && r.ExpectedRunID != uuid.Nil && r.ExpectedLeaseOwner != uuid.Nil &&
		capacityDispatchDigest(r.ExpectedEnvelopeSHA256) && r.ExpectedFencingToken >= 1 && r.ExpectedFencingToken <= 9007199254740991 &&
		r.ExpectedPendingWakeCount >= 1 && r.ExpectedPendingWakeCount <= MaxCapacityDispatchPendingWakes &&
		err == nil && actorID != uuid.Nil && r.Issuer == "collaborator:"+actorID.String()
}

func validCapacityDispatchExecutorBarrier(b CapacityDispatchExecutorBarrier) bool {
	return !b.ProcessStartedAt.IsZero() && capacityDispatchAbandonedHostname.MatchString(b.Hostname) && b.PID > 0 &&
		capacityDispatchAbandonedSource.MatchString(b.SourceCommit)
}

// DisposeAbandonedStartedDispatch closes one started job administratively in a
// single transaction: scope advisory lock (Enqueue order), job FOR UPDATE, run
// FOR UPDATE, then receipt, job terminal and run close. revalidate rechecks the
// current operator at the commit boundary. A refused precondition writes
// nothing; the caller must re-read state and never retry blind.
func DisposeAbandonedStartedDispatch(ctx context.Context, db *sql.DB, r CapacityDispatchAbandonedDispositionRequest, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (CapacityDispatchAbandonedDisposition, error) {
	refused := CapacityDispatchAbandonedDisposition{}
	if db == nil || revalidate == nil || !validCapacityDispatchAbandonedRequest(r) || !validCapacityDispatchExecutorBarrier(barrier) || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	defer tx.Rollback()
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil || !capacityDispatchAbandonedLockSafe(initial.Realm, initial.Environment, initial.Domain, initial.Dimension) {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(scope)); err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	if err != nil || job.Realm != initial.Realm || job.Environment != initial.Environment || job.Domain != initial.Domain || job.Dimension != initial.Dimension {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	var now time.Time
	var returnStatus, returnError, finalizationError, failedID, nativeID, enrolledID, abandonedID sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),return_status,return_error,finalization_error,failed_original_disposition_id::text,native_denied_disposition_id::text,enrolled_failed_disposition_id::text,abandoned_disposition_id::text FROM public.capacity_dispatch_jobs WHERE id=$1`, job.JobID).
		Scan(&now, &returnStatus, &returnError, &finalizationError, &failedID, &nativeID, &enrolledID, &abandonedID); err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if job.Protocol != CapacityDispatchProtocol || job.State != "started" || job.StartedAt == nil || job.ReturnedAt != nil || job.FinalizationAckAt != nil ||
		returnStatus.Valid || returnError.Valid || finalizationError.Valid || failedID.Valid || nativeID.Valid || enrolledID.Valid || abandonedID.Valid ||
		job.LeaseExpiresAt == nil || job.LeaseOwner == uuid.Nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken ||
		job.LeaseOwner != r.ExpectedLeaseOwner || job.PendingWakeCount != r.ExpectedPendingWakeCount ||
		now.Before(job.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) ||
		!barrier.ProcessStartedAt.After(*job.LeaseExpiresAt) || barrier.ProcessStartedAt.After(now) {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if err = checkCapacityDispatchAbandonedRun(ctx, tx, job); err != nil {
		return refused, err
	}
	var scanRaw string
	if err = tx.QueryRowContext(ctx, `SELECT public.abandoned_started_dispatch_effect_scan($1,$2,$3,$4,$5,$6)::text`, job.Realm, job.Environment, job.Domain, job.Dimension, job.JobID, *job.StartedAt).Scan(&scanRaw); err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	scan, err := decodeCapacityDispatchAbandonedScan([]byte(scanRaw))
	if err != nil || !scan.zero() {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	id := uuid.New()
	var recordedAt time.Time
	if err = tx.QueryRowContext(ctx, `INSERT INTO public.capacity_dispatch_abandoned_dispositions(id,job_id,run_id,realm,environment,domain,dimension,envelope_sha256,fencing_token,lease_owner,lease_expires_at,started_at,pending_wake_count,original_dispatch_sha256,original_run_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,minimum_lease_age_seconds,recorded_at,issuer,reason,historical_return,run_status,run_error,provider_mutation_evidence)
SELECT $1,j.id,j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count,
 encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),
 $3,$4,$5,$6,$7,$8,clock_timestamp(),$9,$10,'unknown','failed',$11,$12::jsonb
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$2
RETURNING recorded_at`,
		id, job.JobID, CapacityDispatchAbandonedBarrier, barrier.ProcessStartedAt, barrier.Hostname, barrier.PID, barrier.SourceCommit,
		capacityDispatchAbandonedMinimumAgeSec, r.Issuer, CapacityDispatchAbandonedReason, CapacityDispatchAbandonedRunError, scanRaw).Scan(&recordedAt); err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='abandoned_disposed',abandoned_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1 AND state='started' AND run_id=$3 AND envelope_sha256=$4 AND fencing_token=$5 AND lease_owner=$6 AND pending_wake_count=$7 AND returned_at IS NULL AND finalization_ack_at IS NULL AND abandoned_disposition_id IS NULL`,
		job.JobID, id, job.RunID, job.EnvelopeSHA256, job.FencingToken, job.LeaseOwner, job.PendingWakeCount)
	if err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	// Administrative close of the original run, NOT its return: the fixed error
	// says the historical outcome is unknown and finished_at is the disposal.
	result, err = tx.ExecContext(ctx, `UPDATE public.workflow_runs SET status='failed',error=$2,finished_at=$3,updated_at=clock_timestamp() WHERE id=$1 AND status='running' AND started_at=$4 AND finished_at IS NULL AND result IS NULL AND error IS NULL`,
		job.RunID, CapacityDispatchAbandonedRunError, recordedAt, *job.StartedAt)
	if err != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	receipt, err := readCapacityDispatchAbandonedDisposition(ctx, tx, job.JobID)
	if err != nil || receipt.ID != id || receipt.RunID != job.RunID || receipt.FencingToken != job.FencingToken {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchAbandonedDisposition, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		// Read the immutable receipt to reconcile a late/unknown HTTP result.
		return refused, ErrCapacityDispatchAbandonedDisposition
	}
	return receipt, nil
}

// The original run must still be the exact running envelope run, untouched
// since its possible start: no result, no error and no finish time.
func checkCapacityDispatchAbandonedRun(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob) error {
	var namespace, name, status string
	var version sql.NullInt32
	var inputs, metadata, result []byte
	var started, finished sql.NullTime
	var runError sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT workflow_namespace,workflow_name,workflow_version,inputs,metadata,status,started_at,finished_at,result,error FROM public.workflow_runs WHERE id=$1 FOR UPDATE`, job.RunID).
		Scan(&namespace, &name, &version, &inputs, &metadata, &status, &started, &finished, &result, &runError); err != nil ||
		namespace != job.Workflow.Namespace || name != job.Workflow.Name || !version.Valid || int(version.Int32) != job.Workflow.Version ||
		status != "running" || !started.Valid || job.StartedAt == nil || !started.Time.Equal(*job.StartedAt) || finished.Valid || result != nil || runError.Valid {
		return ErrCapacityDispatchAbandonedDisposition
	}
	var i, m map[string]any
	if json.Unmarshal(inputs, &i) != nil || json.Unmarshal(metadata, &m) != nil {
		return ErrCapacityDispatchAbandonedDisposition
	}
	iSHA, mSHA, err := CapacityDispatchEnvelopeHashes(CapacityDispatchEnvelope{Inputs: i, Metadata: m})
	if err != nil || iSHA != job.InputsSHA256 || mSHA != job.MetadataSHA256 {
		return ErrCapacityDispatchAbandonedDisposition
	}
	return nil
}

func decodeCapacityDispatchAbandonedScan(raw []byte) (CapacityDispatchAbandonedEffectScan, error) {
	var scan CapacityDispatchAbandonedEffectScan
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&scan); err != nil || d.More() || scan.Schema != CapacityDispatchAbandonedScanSchema {
		return CapacityDispatchAbandonedEffectScan{}, ErrCapacityDispatchAbandonedDisposition
	}
	return scan, nil
}

func ReadCapacityDispatchAbandonedDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (CapacityDispatchAbandonedDisposition, error) {
	if db == nil || jobID == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchAbandonedDisposition{}, ErrCapacityDispatchAbandonedDisposition
	}
	return readCapacityDispatchAbandonedDisposition(ctx, db, jobID)
}

func readCapacityDispatchAbandonedDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (CapacityDispatchAbandonedDisposition, error) {
	var d CapacityDispatchAbandonedDisposition
	var scanRaw string
	var returned, acknowledged, runFinished sql.NullTime
	var linked uuid.NullUUID
	err := db.QueryRowContext(ctx, `SELECT d.id,d.job_id,d.run_id,d.realm,d.environment,d.domain,d.dimension,d.envelope_sha256,d.fencing_token,d.lease_owner,d.lease_expires_at,d.started_at,d.pending_wake_count,d.original_dispatch_sha256,d.original_run_sha256,d.executor_barrier,d.disposing_core_process_started_at,d.disposing_core_hostname,d.disposing_core_pid,d.disposing_core_source_commit,d.minimum_lease_age_seconds,d.recorded_at,d.issuer,d.reason,d.historical_return,d.run_status,d.run_error,d.provider_mutation_evidence::text,
 j.state,j.returned_at,j.finalization_ack_at,j.abandoned_disposition_id,w.status,w.finished_at,w.result IS NOT NULL
 FROM public.capacity_dispatch_abandoned_dispositions d
 JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id AND j.envelope_sha256=d.envelope_sha256 AND j.fencing_token=d.fencing_token AND j.lease_owner=d.lease_owner
 JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(
		&d.ID, &d.JobID, &d.RunID, &d.Realm, &d.Environment, &d.Domain, &d.Dimension, &d.EnvelopeSHA256, &d.FencingToken, &d.LeaseOwner,
		&d.LeaseExpiresAt, &d.StartedAt, &d.PendingWakeCount, &d.OriginalDispatchSHA256, &d.OriginalRunSHA256, &d.ExecutorBarrier,
		&d.CoreProcessStartedAt, &d.CoreHostname, &d.CorePID, &d.CoreSourceCommit, &d.MinimumLeaseAgeSeconds, &d.RecordedAt, &d.Issuer,
		&d.Reason, &d.HistoricalReturn, &d.RunStatus, &d.RunError, &scanRaw,
		&d.State, &returned, &acknowledged, &linked, &d.WorkflowRunStatus, &runFinished, &d.WorkflowRunResultPresent)
	if err != nil {
		return CapacityDispatchAbandonedDisposition{}, ErrCapacityDispatchAbandonedDisposition
	}
	if d.EffectScan, err = decodeCapacityDispatchAbandonedScan([]byte(scanRaw)); err != nil || !d.EffectScan.zero() ||
		d.State != "abandoned_disposed" || !linked.Valid || linked.UUID != d.ID || returned.Valid || acknowledged.Valid ||
		d.Reason != CapacityDispatchAbandonedReason || d.HistoricalReturn != "unknown" || d.ExecutorBarrier != CapacityDispatchAbandonedBarrier ||
		d.RunStatus != "failed" || d.RunError != CapacityDispatchAbandonedRunError || d.WorkflowRunStatus != d.RunStatus ||
		!runFinished.Valid || !runFinished.Time.Equal(d.RecordedAt) || d.WorkflowRunResultPresent ||
		!d.CoreProcessStartedAt.After(d.LeaseExpiresAt) || d.RecordedAt.Before(d.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) {
		return CapacityDispatchAbandonedDisposition{}, ErrCapacityDispatchAbandonedDisposition
	}
	d.WorkflowRunFinishedAt = &runFinished.Time
	return d, nil
}
