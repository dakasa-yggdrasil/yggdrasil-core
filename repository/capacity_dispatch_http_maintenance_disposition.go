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
)

const (
	CapacityDispatchHTTPMaintenanceReason     = "recorded_context_refused_http_maintenance_dispatch_disposed"
	CapacityDispatchHTTPMaintenanceScanSchema = "recorded_http_maintenance_dispatch_effect_scan_v1"
	capacityDispatchHTTPMaintenanceError      = "capacity dispatch original context refused"
)

var ErrCapacityDispatchHTTPMaintenanceDisposition = errors.New("recorded HTTP maintenance dispatch disposition refused")

// Closed CAS expectations. None is authority and Issuer is server-owned.
type CapacityDispatchHTTPMaintenanceDispositionRequest struct {
	CapacityDispatchUnknownMaintenanceDispositionRequest
}

type CapacityDispatchHTTPMaintenanceEffectScan struct {
	Schema                       string                                     `json:"schema"`
	Base                         CapacityDispatchFinalizationLostEffectScan `json:"base"`
	CurrentMembers               json.RawMessage                            `json:"current_members"`
	CurrentMembersSHA256         string                                     `json:"current_members_sha256"`
	CurrentMemberCount           int                                        `json:"current_member_count"`
	PolicyEpochValid             bool                                       `json:"policy_epoch_valid"`
	RefreshOnlyResult            bool                                       `json:"refresh_only_result"`
	InvalidMaintenanceCanaryRows int                                        `json:"invalid_maintenance_canary_rows"`
}

func (s CapacityDispatchHTTPMaintenanceEffectScan) tolerable() bool {
	base := s.Base
	if base.CanaryChallengesSinceStart != 1 || base.CanaryNoncesSinceStart != 1 || base.CanaryPossibleSendsSinceStart != 1 || base.CanaryReturnsSinceStart != 1 {
		return false
	}
	base.CanaryChallengesSinceStart, base.CanaryNoncesSinceStart, base.CanaryPossibleSendsSinceStart, base.CanaryReturnsSinceStart = 0, 0, 0, 0
	members, err := httpMaintenanceMembers(s.CurrentMembers)
	return s.Schema == CapacityDispatchHTTPMaintenanceScanSchema && s.PolicyEpochValid && s.RefreshOnlyResult && s.InvalidMaintenanceCanaryRows == 0 &&
		err == nil && s.CurrentMemberCount == 1 && len(members) == 1 &&
		capacityDispatchDigest(s.CurrentMembersSHA256) && base.tolerable()
}

// These are the exact stored-member projection fields from migration91. The
// projection proves neither a fresh provider read nor present business utility.
type httpMaintenanceMember struct {
	Slot               int    `json:"slot"`
	ResourceID         string `json:"resource_id"`
	PreregistrationID  string `json:"preregistration_id"`
	EnrollmentSHA256   string `json:"enrollment_sha256"`
	InstallationSHA256 string `json:"installation_sha256"`
	SlotSHA256         string `json:"slot_sha256"`
	PolicyID           string `json:"policy_id"`
	PolicyChecksum     string `json:"policy_checksum"`
}

func httpMaintenanceMembers(raw json.RawMessage) ([]httpMaintenanceMember, error) {
	var members []httpMaintenanceMember
	if capacity.DecodeNativeCapacity(raw, &members) != nil || len(members) != 1 {
		return nil, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	m := members[0]
	pre, preErr := uuid.Parse(m.PreregistrationID)
	policy, policyErr := uuid.Parse(m.PolicyID)
	if m.Slot != 1 || !capacityDispatchText(m.ResourceID, 256) || preErr != nil || pre == uuid.Nil || pre.String() != m.PreregistrationID ||
		policyErr != nil || policy == uuid.Nil || policy.String() != m.PolicyID || !capacityDispatchDigest(m.EnrollmentSHA256) ||
		!capacityDispatchDigest(m.InstallationSHA256) || !capacityDispatchDigest(m.SlotSHA256) || !capacityDispatchDigest(m.PolicyChecksum) {
		return nil, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	return members, nil
}

type CapacityDispatchHTTPMaintenanceDisposition struct {
	ID                        uuid.UUID                                 `json:"id"`
	JobID                     uuid.UUID                                 `json:"job_id"`
	RunID                     uuid.UUID                                 `json:"run_id"`
	OriginalDispatchUpdatedAt time.Time                                 `json:"original_dispatch_updated_at"`
	OriginalDispatchSHA256    string                                    `json:"original_dispatch_sha256"`
	OriginalRunSHA256         string                                    `json:"original_run_sha256"`
	OriginalReturnedAt        time.Time                                 `json:"original_returned_at"`
	CurrentMembersSHA256      string                                    `json:"current_members_sha256"`
	ExecutorBarrier           string                                    `json:"executor_barrier"`
	CoreProcessStartedAt      time.Time                                 `json:"disposing_core_process_started_at"`
	CoreHostname              string                                    `json:"disposing_core_hostname"`
	CorePID                   int                                       `json:"disposing_core_pid"`
	CoreSourceCommit          string                                    `json:"disposing_core_source_commit"`
	Issuer                    string                                    `json:"issuer"`
	Reason                    string                                    `json:"reason"`
	HistoricalReturn          string                                    `json:"historical_return"`
	RecordedAt                time.Time                                 `json:"recorded_at"`
	EffectScan                CapacityDispatchHTTPMaintenanceEffectScan `json:"provider_mutation_evidence"`
	State                     string                                    `json:"dispatch_state"`
}

func validCapacityDispatchHTTPMaintenanceRequest(r CapacityDispatchHTTPMaintenanceDispositionRequest) bool {
	return validCapacityDispatchUnknownMaintenanceRequest(r.CapacityDispatchUnknownMaintenanceDispositionRequest)
}

// This transaction does not run a workflow or update its historical return.
// It locks scope -> job -> run, proves the failed refresh and closed evidence,
// writes one immutable receipt and moves only the job to its distinct terminal.
func DisposeHTTPMaintenanceDispatch(ctx context.Context, db *sql.DB, r CapacityDispatchHTTPMaintenanceDispositionRequest, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (CapacityDispatchHTTPMaintenanceDisposition, error) {
	refused := CapacityDispatchHTTPMaintenanceDisposition{}
	if db == nil || ctx == nil || revalidate == nil || !validCapacityDispatchHTTPMaintenanceRequest(r) || !validCapacityDispatchExecutorBarrier(barrier) || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	defer tx.Rollback()
	// Whole-row timestamptz JSON must use the same representation at insert
	// and historical readback, irrespective of the connection's prior zone.
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil || !httpMaintenanceScope(initial) || !capacityDispatchAbandonedLockSafe(initial.Realm, initial.Environment, initial.Domain, initial.Dimension) {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(scope)); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	if err != nil || job.Realm != initial.Realm || job.Environment != initial.Environment || job.Domain != initial.Domain || job.Dimension != initial.Dimension ||
		job.Protocol != CapacityDispatchProtocol || job.State != "unknown" || job.StartedAt == nil || job.ReturnedAt == nil || job.LeaseExpiresAt == nil || job.FinalizationAckAt != nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken || job.LeaseOwner != r.ExpectedLeaseOwner ||
		job.PendingWakeCount != r.ExpectedPendingWakeCount || !job.ReturnedAt.Equal(r.ExpectedReturnedAt) {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	// Catalog publication does not take the capacity scope lock. Keep exact
	// pinned manifests and current membership rows locked through the commit.
	authorizationID := uuid.Nil
	if job.AuthorizationPolicy != nil {
		authorizationID = job.AuthorizationPolicy.ID
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM public.manifests WHERE id IN($1,$2,$3,$4) ORDER BY id FOR SHARE`, job.Policy.ID, job.Workflow.ID, job.RBAC.ID, authorizationID); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT namespace FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT slot FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY id FOR SHARE`, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	var now time.Time
	var runSHA string
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM public.workflow_runs w WHERE id=$1 FOR UPDATE`, job.RunID).Scan(&now, &runSHA); err != nil ||
		runSHA != r.ExpectedRunSHA256 || now.Before(job.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) || !barrier.ProcessStartedAt.After(*job.LeaseExpiresAt) || barrier.ProcessStartedAt.After(now) ||
		checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	var raw string
	var accepted, admission bool
	if err = tx.QueryRowContext(ctx, `WITH s AS MATERIALIZED (SELECT public.http_maintenance_dispatch_effect_scan($1) AS evidence) SELECT evidence::text,public.http_maintenance_dispatch_effect_scan_tolerable(evidence),public.http_maintenance_dispatch_admission_valid($1) FROM s`, job.JobID).Scan(&raw, &accepted, &admission); err != nil || !accepted || !admission {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	var scan CapacityDispatchHTTPMaintenanceEffectScan
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &scan) != nil || !scan.tolerable() || scan.CurrentMembersSHA256 != r.ExpectedMembersSHA256 ||
		httpMaintenancePolicyContinuityTx(ctx, tx, job, scan) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	id := uuid.New()
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_http_maintenance_dispositions(id,job_id,run_id,original_dispatch_sha256,original_dispatch_updated_at,original_run_sha256,original_returned_at,current_members_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,issuer,reason,historical_return,recorded_at,provider_mutation_evidence)
 SELECT $1,j.id,j.run_id,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),j.updated_at,$3,j.returned_at,$4,$5,$6,$7,$8,$9,$10,$11,'unknown',clock_timestamp(),$12::jsonb FROM public.capacity_dispatch_jobs j WHERE j.id=$2`,
		id, job.JobID, runSHA, r.ExpectedMembersSHA256, CapacityDispatchAbandonedBarrier, barrier.ProcessStartedAt, barrier.Hostname, barrier.PID, barrier.SourceCommit, r.Issuer, CapacityDispatchHTTPMaintenanceReason, raw); err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='http_maintenance_disposed',updated_at=clock_timestamp() WHERE id=$1 AND state='unknown' AND finalization_ack_at IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL AND abandoned_disposition_id IS NULL AND finalization_lost_disposition_id IS NULL AND unknown_maintenance_disposition_id IS NULL`, job.JobID)
	if err != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	receipt, err := readCapacityDispatchHTTPMaintenanceDisposition(ctx, tx, job.JobID)
	if err != nil || receipt.ID != id || receipt.OriginalRunSHA256 != runSHA {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchHTTPMaintenanceDisposition, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	return receipt, nil
}

func httpMaintenanceScope(job CapacityDispatchJob) bool {
	return job.Protocol == CapacityDispatchProtocol && job.Realm == "dakasa-production" && job.Environment == "production" && job.Domain == "notify" &&
		(job.Dimension == "original_notify_aws_vm_members" || job.Dimension == "original_notify_hetzner_vm_members")
}

// The SQL guard independently derives its stricter stored-lineage projection.
// Go also runs the complete, unchanged ADR94 validator under the same locks;
// no caller boolean or projected hash can replace the Guest production contract.
func httpMaintenancePolicyContinuityTx(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob, scan CapacityDispatchHTTPMaintenanceEffectScan) error {
	members, err := httpMaintenanceMembers(scan.CurrentMembers)
	if err != nil || !httpMaintenanceScope(job) {
		return ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	policy := model.Manifest{ID: job.Policy.ID, Kind: "capacity_policy"}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 AND version=$4 AND checksum=$5 AND active FOR SHARE`,
		job.Policy.ID, job.Policy.Namespace, job.Policy.Name, job.Policy.Version, job.Policy.Checksum).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Checksum, &raw); err != nil {
		return ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	policy.Spec = raw
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.Environment != job.Environment || p.Domain != job.Domain || p.Dimension != job.Dimension ||
		p.Workflow.Namespace != job.Workflow.Namespace || p.Workflow.Name != job.Workflow.Name || !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(p)) {
		return ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	for _, member := range members {
		if guestPolicyContinuityTx(ctx, tx, policy, p, member.PolicyID, member.PolicyChecksum) != nil {
			return ErrCapacityDispatchHTTPMaintenanceDisposition
		}
	}
	return nil
}

func ReadCapacityDispatchHTTPMaintenanceDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (CapacityDispatchHTTPMaintenanceDisposition, error) {
	if db == nil || ctx == nil || jobID == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	d, err := readCapacityDispatchHTTPMaintenanceDisposition(ctx, tx, jobID)
	if err != nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	if err = tx.Commit(); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	return d, nil
}

func readCapacityDispatchHTTPMaintenanceDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (CapacityDispatchHTTPMaintenanceDisposition, error) {
	var d CapacityDispatchHTTPMaintenanceDisposition
	var raw, jobSHA, runSHA, runStatus, runError, returnStatus, returnError, finalizationError string
	var returned, ack, started, expires, workflowStarted, workflowFinished sql.NullTime
	var pointersAbsent, retainedTolerable bool
	err := db.QueryRowContext(ctx, `SELECT d.id,d.job_id,d.run_id,d.original_dispatch_sha256,d.original_dispatch_updated_at,d.original_run_sha256,d.original_returned_at,d.current_members_sha256,d.executor_barrier,d.disposing_core_process_started_at,d.disposing_core_hostname,d.disposing_core_pid,d.disposing_core_source_commit,d.issuer,d.reason,d.historical_return,d.recorded_at,d.provider_mutation_evidence::text,j.state,j.returned_at,j.finalization_ack_at,
 encode(sha256(convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at))::text,'UTF8')),'hex'),
 encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),w.status,w.error,j.return_status,j.return_error,j.finalization_error,j.started_at,j.lease_expires_at,w.started_at,w.finished_at,
 num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0,
 public.http_maintenance_dispatch_effect_scan_tolerable(d.provider_mutation_evidence)
 FROM public.capacity_dispatch_http_maintenance_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(
		&d.ID, &d.JobID, &d.RunID, &d.OriginalDispatchSHA256, &d.OriginalDispatchUpdatedAt, &d.OriginalRunSHA256, &d.OriginalReturnedAt, &d.CurrentMembersSHA256, &d.ExecutorBarrier, &d.CoreProcessStartedAt, &d.CoreHostname, &d.CorePID, &d.CoreSourceCommit, &d.Issuer, &d.Reason, &d.HistoricalReturn, &d.RecordedAt, &raw, &d.State, &returned, &ack,
		&jobSHA, &runSHA, &runStatus, &runError, &returnStatus, &returnError, &finalizationError, &started, &expires, &workflowStarted, &workflowFinished, &pointersAbsent, &retainedTolerable)
	if err != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &d.EffectScan) != nil || !d.EffectScan.tolerable() || !retainedTolerable || d.EffectScan.CurrentMembersSHA256 != d.CurrentMembersSHA256 ||
		d.ID == uuid.Nil || d.JobID != jobID || d.RunID == uuid.Nil || !capacityDispatchDigest(d.OriginalDispatchSHA256) || !capacityDispatchDigest(d.OriginalRunSHA256) ||
		d.OriginalDispatchSHA256 != jobSHA || d.OriginalRunSHA256 != runSHA || d.OriginalDispatchUpdatedAt.IsZero() || d.OriginalDispatchUpdatedAt.After(d.RecordedAt) ||
		!validCapacityDispatchExecutorBarrier(CapacityDispatchExecutorBarrier{ProcessStartedAt: d.CoreProcessStartedAt, Hostname: d.CoreHostname, PID: d.CorePID, SourceCommit: d.CoreSourceCommit}) ||
		d.State != "http_maintenance_disposed" || !pointersAbsent || !returned.Valid || !returned.Time.Equal(d.OriginalReturnedAt) || ack.Valid ||
		!started.Valid || !expires.Valid || !workflowStarted.Valid || !workflowFinished.Valid || !started.Time.Before(returned.Time) || !returned.Time.Before(expires.Time) ||
		!workflowStarted.Time.Equal(started.Time) || !workflowFinished.Time.Equal(returned.Time) || d.RecordedAt.Before(expires.Time.Add(CapacityDispatchAbandonedMinimumAge)) ||
		!d.CoreProcessStartedAt.After(expires.Time) || d.CoreProcessStartedAt.After(d.RecordedAt) ||
		runStatus != "failed" || returnStatus != "failed" || runError != capacityDispatchHTTPMaintenanceError || returnError != runError || finalizationError != runError ||
		d.Reason != CapacityDispatchHTTPMaintenanceReason || d.HistoricalReturn != "unknown" || d.ExecutorBarrier != CapacityDispatchAbandonedBarrier {
		return CapacityDispatchHTTPMaintenanceDisposition{}, ErrCapacityDispatchHTTPMaintenanceDisposition
	}
	return d, nil
}
