package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const CapacityDispatchPrestartRejectionReason = "policy_superseded_before_start"

var ErrCapacityDispatchPrestartRejection = errors.New("capacity dispatch prestart rejection refused")

// All HTTP fields are compare-and-swap expectations, never execution authority.
// Issuer is supplied by the authenticated administrative boundary only.
type CapacityDispatchPrestartRejectionRequest struct {
	JobID                             uuid.UUID `json:"job_id"`
	ExpectedRunID                     uuid.UUID `json:"expected_run_id"`
	ExpectedEnvelopeSHA256            string    `json:"expected_envelope_sha256"`
	ExpectedFencingToken              int64     `json:"expected_fencing_token"`
	ExpectedSupersedingPolicyID       uuid.UUID `json:"expected_superseding_policy_id"`
	ExpectedSupersedingPolicyVersion  int       `json:"expected_superseding_policy_version"`
	ExpectedSupersedingPolicyChecksum string    `json:"expected_superseding_policy_checksum"`
	Issuer                            string    `json:"-"`
}

// This immutable administrative receipt proves only rejection before start.
// It is not a workflow return, capacity grant, or admission of a successor job.
type CapacityDispatchPrestartRejection struct {
	JobID                     uuid.UUID                   `json:"job_id"`
	RunID                     uuid.UUID                   `json:"run_id"`
	EnvelopeSHA256            string                      `json:"envelope_sha256"`
	FencingToken              int64                       `json:"fencing_token"`
	Reason                    string                      `json:"reason"`
	Issuer                    string                      `json:"issuer"`
	RecordedAt                time.Time                   `json:"recorded_at"`
	SupersededPolicyID        uuid.UUID                   `json:"superseded_policy_id"`
	SupersededPolicyChecksum  string                      `json:"superseded_policy_checksum"`
	SupersedingPolicyID       uuid.UUID                   `json:"superseding_policy_id"`
	SupersedingPolicyChecksum string                      `json:"superseding_policy_checksum"`
	State                     string                      `json:"state"`
	Realm                     string                      `json:"realm"`
	Environment               string                      `json:"environment"`
	Domain                    string                      `json:"domain"`
	Dimension                 string                      `json:"dimension"`
	LeaseOwner                *uuid.UUID                  `json:"lease_owner"`
	LeaseExpiresAt            *time.Time                  `json:"lease_expires_at"`
	StartedAt                 *time.Time                  `json:"started_at"`
	ReturnedAt                *time.Time                  `json:"returned_at"`
	FinalizationAckAt         *time.Time                  `json:"finalization_ack_at"`
	WorkflowRunStatus         string                      `json:"workflow_run_status"`
	WorkflowRunStartedAt      *time.Time                  `json:"workflow_run_started_at"`
	WorkflowRunFinishedAt     *time.Time                  `json:"workflow_run_finished_at"`
	WorkflowRunResultPresent  bool                        `json:"workflow_run_result_present"`
	WorkflowRunError          string                      `json:"workflow_run_error"`
	OriginalPolicy            CapacityDispatchManifestPin `json:"original_policy"`
}

func ReadCapacityDispatchForPrestartRejection(ctx context.Context, db *sql.DB, id uuid.UUID) (CapacityDispatchJob, error) {
	if db == nil || id == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchJob{}, ErrCapacityDispatchPrestartRejection
	}
	return readCapacityDispatchJob(ctx, db, id, false)
}

func ReadCapacityDispatchPrestartRejection(ctx context.Context, db *sql.DB, id uuid.UUID) (CapacityDispatchPrestartRejection, error) {
	if db == nil || id == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchPrestartRejection{}, ErrCapacityDispatchPrestartRejection
	}
	return readCapacityDispatchPrestartRejection(ctx, db, id)
}

func readCapacityDispatchPrestartRejection(ctx context.Context, db capacityDispatchQueryer, id uuid.UUID) (CapacityDispatchPrestartRejection, error) {
	var r CapacityDispatchPrestartRejection
	var owner uuid.NullUUID
	var lease, started, returned, acknowledged, runStarted, runFinished sql.NullTime
	var policyRaw []byte
	err := db.QueryRowContext(ctx, `SELECT r.job_id,r.run_id,r.envelope_sha256,r.fencing_token,r.reason,r.issuer,r.recorded_at,r.superseded_policy_id,r.superseded_policy_checksum,r.superseding_policy_id,r.superseding_policy_checksum,j.state,j.realm,j.environment,j.domain,j.dimension,j.lease_owner,j.lease_expires_at,j.started_at,j.returned_at,j.finalization_ack_at,w.status,w.started_at,w.finished_at,w.result IS NOT NULL,w.error,j.envelope::jsonb->'policy' FROM public.capacity_dispatch_prestart_rejections r JOIN public.capacity_dispatch_jobs j ON j.id=r.job_id AND j.run_id=r.run_id AND j.envelope_sha256=r.envelope_sha256 AND j.fencing_token=r.fencing_token JOIN public.workflow_runs w ON w.id=r.run_id WHERE r.job_id=$1`, id).Scan(
		&r.JobID, &r.RunID, &r.EnvelopeSHA256, &r.FencingToken, &r.Reason, &r.Issuer, &r.RecordedAt,
		&r.SupersededPolicyID, &r.SupersededPolicyChecksum, &r.SupersedingPolicyID, &r.SupersedingPolicyChecksum,
		&r.State, &r.Realm, &r.Environment, &r.Domain, &r.Dimension, &owner, &lease, &started, &returned, &acknowledged,
		&r.WorkflowRunStatus, &runStarted, &runFinished, &r.WorkflowRunResultPresent, &r.WorkflowRunError, &policyRaw)
	if err != nil || r.State != "prestart_rejected" || r.Reason != CapacityDispatchPrestartRejectionReason ||
		started.Valid || returned.Valid || acknowledged.Valid || r.WorkflowRunStatus != "cancelled" || runStarted.Valid ||
		!runFinished.Valid || !runFinished.Time.Equal(r.RecordedAt) || r.WorkflowRunResultPresent || r.WorkflowRunError != r.Reason ||
		(lease.Valid && r.RecordedAt.Before(lease.Time)) || owner.Valid != lease.Valid ||
		(!owner.Valid && r.FencingToken != 0) || (owner.Valid && (owner.UUID == uuid.Nil || r.FencingToken <= 0)) ||
		json.Unmarshal(policyRaw, &r.OriginalPolicy) != nil || !capacityDispatchPin(r.OriginalPolicy) ||
		r.OriginalPolicy.ID != r.SupersededPolicyID || r.OriginalPolicy.Checksum != r.SupersededPolicyChecksum || r.OriginalPolicy.Namespace != r.Realm {
		return CapacityDispatchPrestartRejection{}, ErrCapacityDispatchPrestartRejection
	}
	if owner.Valid {
		r.LeaseOwner = &owner.UUID
		r.LeaseExpiresAt = &lease.Time
	}
	r.WorkflowRunFinishedAt = &runFinished.Time
	return r, nil
}

// RejectCapacityDispatchBeforeStart is an explicit administrative transaction.
// Enqueue/boot never calls it. The service supplies a fully admitted CURRENT
// envelope and revalidates its server-owned principal/binding/graph before and
// after the write. No successor run/job is inserted here. SQL72 atomically
// appends the rejection receipt and cancels the original pending workflow run.
func RejectCapacityDispatchBeforeStart(ctx context.Context, db *sql.DB, r CapacityDispatchPrestartRejectionRequest, current CapacityDispatchEnvelope, revalidate func(context.Context, CapacityDispatchEnvelope) error) (CapacityDispatchPrestartRejection, error) {
	refused := CapacityDispatchPrestartRejection{}
	actor := strings.TrimPrefix(r.Issuer, "collaborator:")
	actorID, actorErr := uuid.Parse(actor)
	if db == nil || revalidate == nil || r.JobID == uuid.Nil || r.ExpectedRunID == uuid.Nil ||
		r.ExpectedSupersedingPolicyID == uuid.Nil || r.ExpectedSupersedingPolicyVersion < 1 ||
		r.ExpectedFencingToken < 0 || r.ExpectedFencingToken > 9007199254740991 ||
		!capacityDispatchDigest(r.ExpectedEnvelopeSHA256) || !capacityDispatchDigest(r.ExpectedSupersedingPolicyChecksum) ||
		actorErr != nil || actorID == uuid.Nil || r.Issuer != "collaborator:"+actorID.String() || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	if _, err := encodeCapacityDispatchEnvelope(current); err != nil || current.Policy.ID != r.ExpectedSupersedingPolicyID ||
		current.Policy.Version != r.ExpectedSupersedingPolicyVersion || current.Policy.Checksum != r.ExpectedSupersedingPolicyChecksum {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	defer tx.Rollback()
	// Freeze catalog writes before acquiring job/run locks. Row locks alone
	// cannot exclude a later inactive-version insertion during admission.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE public.manifests IN SHARE MODE`); err != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	// Same scope lock/order as Enqueue; Claim/Start serialize on the job row.
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, string(scope)); err != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	var now time.Time
	if err != nil || tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken ||
		job.Protocol != CapacityDispatchProtocol || job.State != "queued" || job.StartedAt != nil || job.ReturnedAt != nil || job.FinalizationAckAt != nil ||
		(job.LeaseExpiresAt != nil && now.Before(*job.LeaseExpiresAt)) ||
		job.Realm != current.Realm || job.Environment != current.Environment || job.Domain != current.Domain || job.Dimension != current.Dimension ||
		job.Policy.Namespace != current.Policy.Namespace || job.Policy.Name != current.Policy.Name ||
		job.Policy.ID == current.Policy.ID || current.Policy.Version <= job.Policy.Version {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	if err = checkCapacityDispatchRejectionPins(ctx, tx, job, current); err != nil {
		return refused, err
	}
	if err = checkCapacityDispatchPrestartRun(ctx, tx, job); err != nil {
		return refused, err
	}
	if err = revalidate(ctx, current); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='prestart_rejected',rejected_at=clock_timestamp(),rejection_reason=$2,rejection_issuer=$3,superseded_policy_id=$4,superseded_policy_checksum=$5,superseding_policy_id=$6,superseding_policy_checksum=$7,updated_at=clock_timestamp() WHERE id=$1 AND state='queued' AND started_at IS NULL AND returned_at IS NULL AND finalization_ack_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())`,
		job.JobID, CapacityDispatchPrestartRejectionReason, r.Issuer, job.Policy.ID, job.Policy.Checksum, current.Policy.ID, current.Policy.Checksum)
	if err != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	receipt, err := readCapacityDispatchPrestartRejection(ctx, tx, job.JobID)
	if err != nil || receipt.RunID != job.RunID || receipt.EnvelopeSHA256 != job.EnvelopeSHA256 || receipt.FencingToken != job.FencingToken {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	if err = revalidate(ctx, current); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchPrestartRejection
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchPrestartRejection, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		// Read the immutable receipt to reconcile a late/unknown HTTP result.
		// A caller must never infer rollback from a missing acknowledgment.
		return refused, ErrCapacityDispatchPrestartRejection
	}
	return receipt, nil
}

func checkCapacityDispatchRejectionPins(ctx context.Context, tx *sql.Tx, old CapacityDispatchJob, current CapacityDispatchEnvelope) error {
	var inactive bool
	if err := tx.QueryRowContext(ctx, `SELECT NOT active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 AND version=$4 AND checksum=$5 FOR SHARE`, old.Policy.ID, old.Policy.Namespace, old.Policy.Name, old.Policy.Version, old.Policy.Checksum).Scan(&inactive); err != nil || !inactive {
		return ErrCapacityDispatchPrestartRejection
	}
	pins := []struct {
		kind string
		pin  CapacityDispatchManifestPin
	}{{"capacity_policy", current.Policy}, {"workflow", current.Workflow}, {"rbac", current.RBAC}}
	if current.AuthorizationPolicy != nil {
		pins = append(pins, struct {
			kind string
			pin  CapacityDispatchManifestPin
		}{"policy", *current.AuthorizationPolicy})
	}
	for _, p := range pins {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind=$2 AND namespace=$3 AND name=$4 AND version=$5 AND checksum=$6 AND active FOR SHARE`, p.pin.ID, p.kind, p.pin.Namespace, p.pin.Name, p.pin.Version, p.pin.Checksum).Scan(&raw); err != nil {
			return ErrCapacityDispatchPrestartRejection
		}
		if p.kind == "capacity_policy" {
			var latest bool
			if tx.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND version>$3)`, p.pin.Namespace, p.pin.Name, p.pin.Version).Scan(&latest) != nil || !latest {
				return ErrCapacityDispatchPrestartRejection
			}
			var policy model.CapacityPolicySpec
			if json.Unmarshal(raw, &policy) != nil || !policy.ExecutionEnabled || policy.ControllerBinding == nil ||
				policy.Environment != current.Environment || policy.Domain != current.Domain || policy.Dimension != current.Dimension ||
				policy.Workflow.Namespace != current.Workflow.Namespace || policy.Workflow.Name != current.Workflow.Name ||
				policy.ControllerBinding.MachinePrincipalID != current.MachinePrincipalID {
				return ErrCapacityDispatchPrestartRejection
			}
		}
	}
	return nil
}

func checkCapacityDispatchPrestartRun(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob) error {
	var namespace, name, status string
	var version sql.NullInt32
	var inputs, metadata, result []byte
	var started, finished sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT workflow_namespace,workflow_name,workflow_version,inputs,metadata,status,started_at,finished_at,result FROM public.workflow_runs WHERE id=$1 FOR UPDATE`, job.RunID).Scan(&namespace, &name, &version, &inputs, &metadata, &status, &started, &finished, &result); err != nil ||
		namespace != job.Workflow.Namespace || name != job.Workflow.Name || !version.Valid || int(version.Int32) != job.Workflow.Version ||
		status != "pending" || started.Valid || finished.Valid || result != nil {
		return ErrCapacityDispatchPrestartRejection
	}
	var i, m map[string]any
	if json.Unmarshal(inputs, &i) != nil || json.Unmarshal(metadata, &m) != nil {
		return ErrCapacityDispatchPrestartRejection
	}
	iSHA, mSHA, err := CapacityDispatchEnvelopeHashes(CapacityDispatchEnvelope{Inputs: i, Metadata: m})
	if err != nil || iSHA != job.InputsSHA256 || mSHA != job.MetadataSHA256 {
		return ErrCapacityDispatchPrestartRejection
	}
	return nil
}
