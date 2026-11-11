package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const CapacityDispatchPreActionPlanState = "preaction_plan_disposed"
const CapacityDispatchPreActionPlanSchema = "unknown_preaction_failed_plan_disposition_v1"

type preActionPlanEffectScan struct {
	Schema                           string                                     `json:"schema"`
	Base                             CapacityDispatchFinalizationLostEffectScan `json:"base"`
	CurrentIntentMatchesAnchor       bool                                       `json:"current_intent_matches_anchor"`
	CurrentMembersMatchAnchor        bool                                       `json:"current_members_match_anchor"`
	OtherBusyDispatches              int64                                      `json:"other_busy_dispatches"`
	OtherBusyRuns                    int64                                      `json:"other_busy_runs"`
	AuthorityIssuesSinceStart        int64                                      `json:"authority_issues_since_start"`
	DisposalRowsSinceStart           int64                                      `json:"disposal_rows_since_start"`
	RetirementForwardsSinceStart     int64                                      `json:"retirement_forwards_since_start"`
	RetirementForwardReadsSinceStart int64                                      `json:"retirement_forward_reads_since_start"`
	UndisposedGrants                 int64                                      `json:"undisposed_grants"`
}

func preActionPlanEffectScanTolerable(raw []byte) bool {
	var fields map[string]json.RawMessage
	var scan preActionPlanEffectScan
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 11 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &scan) != nil {
		return false
	}
	for _, name := range []string{"schema", "base", "current_intent_matches_anchor", "current_members_match_anchor", "other_busy_dispatches", "other_busy_runs", "authority_issues_since_start", "disposal_rows_since_start", "retirement_forwards_since_start", "retirement_forward_reads_since_start", "undisposed_grants"} {
		value, exists := fields[name]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	// Check every inherited flat counter/flag too: a missing or JSON-null
	// zero must not become typed Go's default zero and pass the mirror.
	var baseFields, expectedBase map[string]json.RawMessage
	canonicalBase, err := json.Marshal(scan.Base)
	if err != nil || json.Unmarshal(fields["base"], &baseFields) != nil ||
		json.Unmarshal(canonicalBase, &expectedBase) != nil || len(baseFields) != len(expectedBase) {
		return false
	}
	for name := range expectedBase {
		value, exists := baseFields[name]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return scan.Schema == "preaction_failed_plan_effect_scan_v1" &&
		scan.CurrentIntentMatchesAnchor && scan.CurrentMembersMatchAnchor &&
		scan.OtherBusyDispatches == 0 && scan.OtherBusyRuns == 0 &&
		scan.AuthorityIssuesSinceStart == 0 && scan.DisposalRowsSinceStart == 0 &&
		scan.RetirementForwardsSinceStart == 0 && scan.RetirementForwardReadsSinceStart == 0 &&
		scan.UndisposedGrants == 0 && scan.Base.IntentsUpdatedSinceStart == 0 &&
		scan.Base.PureAssessmentIntentUpdates == 0 && scan.Base.tolerable()
}

// The failed plan's cause is not an eligibility category. The independently
// authenticated anchor and no-commit scan must prove the same absence of
// authority for every refusal stage, including a failure after a claim Commit.
func preActionFailedPlanResult(raw []byte, job CapacityDispatchJob, spec model.WorkflowManifestSpec, started, finished time.Time) bool {
	var result model.RunWorkflowResponse
	expectedMetadata := make(map[string]any, len(job.Metadata)+1)
	for key, value := range job.Metadata {
		expectedMetadata[key] = value
	}
	expectedMetadata["failed_step"] = "plan-original-guest"
	if json.Unmarshal(raw, &result) != nil || result.Status != "failed" ||
		result.Workflow != (model.ManifestReference{ID: job.Workflow.ID, Kind: "workflow", Namespace: job.Workflow.Namespace, Name: job.Workflow.Name, Version: job.Workflow.Version}) ||
		!reflect.DeepEqual(result.Metadata, expectedMetadata) || started.IsZero() || finished.Before(started) ||
		job.LeaseExpiresAt == nil || result.StartedAt.IsZero() || result.StartedAt.Before(started) ||
		!result.StartedAt.Before(*job.LeaseExpiresAt) || result.FinishedAt.Before(result.StartedAt) ||
		result.FinishedAt.After(finished) {
		return false
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(spec)
	if err != nil || len(ordered) != 7 || len(result.Steps) != len(ordered) || ordered[0].ID != "plan-original-guest" {
		return false
	}
	previous := result.StartedAt
	for i, step := range result.Steps {
		if step.ID != ordered[i].ID || step.Kind != "yggdrasil" ||
			step.Operation != manifestengine.NormalizeWorkflowStepOperation(ordered[i]) ||
			step.Capability != manifestengine.NormalizeWorkflowStepCapability(ordered[i]) ||
			step.IntegrationInstance != nil || step.IntegrationType != nil ||
			step.StartedAt.IsZero() || step.StartedAt.Before(previous) ||
			step.FinishedAt.Before(step.StartedAt) || step.FinishedAt.After(finished) {
			return false
		}
		previous = step.FinishedAt
		if i == 0 {
			if !step.FinishedAt.Equal(result.FinishedAt) {
				return false
			}
			stage, ok := step.Metadata["original_guest_reconcile_refusal_stage"].(string)
			if step.Operation != capacity.PlanOriginalGuestOperation || step.Status != "failed" || step.Attempts != 1 ||
				len(step.Metadata) != 1 || !ok || !capacityDispatchText(stage, 128) || strings.TrimSpace(stage) != stage {
				return false
			}
		} else if step.Status != "skipped" || step.Attempts != 0 || len(step.Metadata) != 0 ||
			step.Error != "workflow aborted after step \"plan-original-guest\" failed" {
			return false
		}
	}
	return true
}

// The caller already holds Enqueue's scope lock and active job row lock.
// Missing schema remains an ordinary UNKNOWN hold on historical databases.
// All writes below share the caller's transaction; Enqueue inserts the named
// distinct successor before Commit, as required by the deferred SQL guard.
func reconcilePreActionFailedPlanTx(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob, next CapacityDispatchEnvelope) (bool, error) {
	if tx == nil || job.State != "unknown" || job.StartedAt == nil || job.ReturnedAt == nil ||
		job.LeaseExpiresAt == nil || job.FinalizationAckAt != nil ||
		!installedProvisionTimeoutAuthorityEqual(job.CapacityDispatchEnvelope, next) {
		return false, nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT to_regclass('public.capacity_dispatch_preaction_plan_dispositions') IS NOT NULL").Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return false, err
	}
	// Scope lock precedes all row locks, exactly as the plan's mutation paths.
	// Holding manifest rows also excludes a publication changing our pins
	// while the receipt and successor are admitted.
	authorizationID := uuid.Nil
	if job.AuthorizationPolicy != nil {
		authorizationID = job.AuthorizationPolicy.ID
	}
	if _, err := tx.ExecContext(ctx, "SELECT id FROM public.manifests WHERE id IN($1,$2,$3,$4) ORDER BY id FOR SHARE", job.Policy.ID, job.Workflow.ID, job.RBAC.ID, authorizationID); err != nil {
		return false, err
	}
	var now time.Time
	var policy model.Manifest
	policy.ID, policy.Kind = job.Policy.ID, "capacity_policy"
	var active bool
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp(),namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE", job.Policy.ID).Scan(&now, &policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active); err != nil {
		return false, err
	}
	if !active || now.Before(*job.LeaseExpiresAt) || now.Before(*job.ReturnedAt) ||
		policy.Metadata.Namespace != job.Policy.Namespace || policy.Metadata.Name != job.Policy.Name ||
		policy.Version != job.Policy.Version || policy.Checksum != job.Policy.Checksum ||
		checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return false, nil
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.Environment != job.Environment || p.Domain != job.Domain || p.Dimension != job.Dimension {
		return false, nil
	}
	var spec model.WorkflowManifestSpec
	var specRaw []byte
	var wfNS, wfName, wfSHA string
	var wfVersion int
	var wfActive bool
	if err = tx.QueryRowContext(ctx, "SELECT namespace,name,version,checksum,active,spec FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE", job.Workflow.ID).Scan(&wfNS, &wfName, &wfVersion, &wfSHA, &wfActive, &specRaw); err != nil {
		return false, err
	}
	if !wfActive || wfNS != job.Workflow.Namespace || wfName != job.Workflow.Name || wfVersion != job.Workflow.Version ||
		wfSHA != job.Workflow.Checksum || json.Unmarshal(specRaw, &spec) != nil ||
		capacity.ValidateOriginalGuestReconcileGraph(spec, policy, p) != nil {
		return false, nil
	}
	var currentIntentWire []byte
	if err = tx.QueryRowContext(ctx, "SELECT intent::text FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE", job.Realm, job.Environment, job.Domain, job.Dimension).Scan(&currentIntentWire); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	var current model.CapacityIntent
	if json.Unmarshal(currentIntentWire, &current) != nil || !installedProvisionTimeoutCandidate(current, policy, p, now) {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, "SELECT slot FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE", job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT id FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY id FOR SHARE", job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
		return false, err
	}
	// The anchor is immutable evidence, not a snapshot manufactured at this
	// disposal. Multiple matching roots are an ambiguous history and HOLD.
	rows, err := tx.QueryContext(ctx, "SELECT d.job_id,d.original_intent_wire,d.members_wire FROM public.capacity_dispatch_installed_provision_timeout_dispositions d WHERE d.original_record->>'policy_id'=$1 AND d.original_record->>'policy_checksum'=$2 AND d.recorded_at<=$3 AND convert_from(d.original_intent_wire,'UTF8')::jsonb=$4::jsonb ORDER BY d.id LIMIT 2 FOR SHARE", policy.ID.String(), policy.Checksum, *job.StartedAt, currentIntentWire)
	if err != nil {
		return false, err
	}
	var anchorJobID uuid.UUID
	var intentWire, membersWire []byte
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&anchorJobID, &intentWire, &membersWire); err != nil {
			_ = rows.Close()
			return false, err
		}
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if rowErr != nil {
		return false, rowErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if count != 1 || anchorJobID == job.JobID {
		return false, nil
	}
	anchor, err := readInstalledProvisionTimeoutDisposition(ctx, tx, anchorJobID)
	if err != nil {
		if errors.Is(err, ErrCapacityConflict) || errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	anchorJob, err := readCapacityDispatchJob(ctx, tx, anchorJobID, false)
	if err != nil {
		return false, err
	}
	if anchor.ID == "" || anchor.RecordedAt.After(*job.StartedAt) ||
		!installedProvisionTimeoutAuthorityEqual(anchorJob.CapacityDispatchEnvelope, job.CapacityDispatchEnvelope) ||
		capacity.BusinessCreationSHA256(intentWire) != anchor.OriginalIntentSHA256 ||
		capacity.BusinessCreationSHA256(membersWire) != anchor.MembersSHA256 {
		return false, nil
	}
	var anchored model.CapacityIntent
	if json.Unmarshal(intentWire, &anchored) != nil || !reflect.DeepEqual(current, anchored) {
		return false, nil
	}
	if pending, err := countUnresolvedCapacityGrantsTx(ctx, tx, policy.Metadata.Namespace, p); err != nil || pending != 0 {
		return false, err
	}
	members, _, err := installedProvisionTimeoutMembersTx(ctx, tx, policy, p, current)
	if err != nil {
		if errors.Is(err, ErrCapacityConflict) || errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	memberBytes, err := json.Marshal(members)
	if err != nil {
		return false, err
	}
	if !reflect.DeepEqual(members, anchor.Members) || !bytes.Equal(memberBytes, membersWire) {
		return false, nil
	}
	var dispatchWire, runWire, result []byte
	var runStatus, returnStatus string
	var started, finished time.Time
	err = tx.QueryRowContext(ctx, "SELECT to_jsonb(j)::text,row_to_json(w)::text,w.result,w.status,COALESCE(j.return_status,''),w.started_at,w.finished_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1 AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.metadata->>'capacity_dispatch_job_id'=j.id::text FOR SHARE OF w", job.JobID).Scan(&dispatchWire, &runWire, &result, &runStatus, &returnStatus, &started, &finished)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if runStatus != "failed" || returnStatus != "failed" || !started.Equal(*job.StartedAt) ||
		!finished.Equal(*job.ReturnedAt) || !preActionFailedPlanResult(result, job, spec, started, finished) {
		return false, nil
	}
	var evidence string
	var accepted bool
	err = tx.QueryRowContext(ctx, "WITH s AS MATERIALIZED (SELECT public.preaction_failed_plan_effect_scan($1,$2) AS evidence) SELECT evidence::text,public.preaction_failed_plan_effect_scan_tolerable(evidence) FROM s", job.JobID, anchor.ID).Scan(&evidence, &accepted)
	if err != nil {
		return false, err
	}
	if !accepted || !preActionPlanEffectScanTolerable([]byte(evidence)) {
		return false, nil
	}
	r := model.CapacityDispatchPreActionPlanDisposition{
		Schema: CapacityDispatchPreActionPlanSchema, ID: uuid.NewString(), JobID: job.JobID.String(), RunID: job.RunID.String(),
		SuccessorJobID: next.JobID.String(), SuccessorRunID: next.RunID.String(), RootAnchorID: anchor.ID,
		PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, Generation: current.Generation, FencingToken: current.FencingToken,
		OriginalDispatchSHA256: capacity.BusinessCreationSHA256(dispatchWire), OriginalRunSHA256: capacity.BusinessCreationSHA256(runWire),
		OriginalIntentSHA256: capacity.BusinessCreationSHA256(intentWire), MembersSHA256: capacity.BusinessCreationSHA256(membersWire),
		EvidenceSHA256: capacity.BusinessCreationSHA256([]byte(evidence)), OriginalDeadline: *job.LeaseExpiresAt,
		OriginalReturnedAt: *job.ReturnedAt, RecordedAt: now.UTC(),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	var valid bool
	if err = tx.QueryRowContext(ctx, "SELECT public.preaction_failed_plan_valid($1::jsonb,$2,$3,$4,$5,$6)", string(raw), dispatchWire, runWire, intentWire, membersWire, []byte(evidence)).Scan(&valid); err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO public.capacity_dispatch_preaction_plan_dispositions(id,job_id,run_id,successor_job_id,successor_run_id,original_record,original_wire,original_dispatch_wire,original_run_wire,original_intent_wire,members_wire,evidence_wire,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13)", r.ID, job.JobID, job.RunID, next.JobID, next.RunID, string(raw), raw, dispatchWire, runWire, intentWire, membersWire, []byte(evidence), r.RecordedAt)
	if err != nil {
		return false, err
	}
	changed, err := tx.ExecContext(ctx, "UPDATE public.capacity_dispatch_jobs SET state=$2,updated_at=$3 WHERE id=$1 AND state='unknown' AND finalization_ack_at IS NULL", job.JobID, CapacityDispatchPreActionPlanState, r.RecordedAt)
	if err != nil {
		return false, err
	}
	if n, e := changed.RowsAffected(); e != nil {
		return false, e
	} else if n != 1 {
		return false, ErrCapacityConflict
	}
	return true, nil
}

// Historical validation authenticates the preserved originals and immutable
// receipt. It deliberately does not demand a frozen current intent or rerun a
// current effect scan after the distinct successor has legitimately progressed.
func ReadCapacityDispatchPreActionPlanDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (model.CapacityDispatchPreActionPlanDisposition, error) {
	var empty model.CapacityDispatchPreActionPlanDisposition
	if db == nil || jobID == uuid.Nil {
		return empty, ErrCapacityConflict
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return empty, err
	}
	var raw []byte
	var valid bool
	err = tx.QueryRowContext(ctx, "SELECT d.original_wire,public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at']) AND convert_from(d.original_run_wire,'UTF8')::jsonb=to_jsonb(w) FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1", jobID).Scan(&raw, &valid)
	if err != nil {
		return empty, err
	}
	var r model.CapacityDispatchPreActionPlanDisposition
	if !valid || json.Unmarshal(raw, &r) != nil || r.Schema != CapacityDispatchPreActionPlanSchema || r.JobID != jobID.String() {
		return empty, ErrCapacityConflict
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return empty, ErrCapacityConflict
	}
	return r, tx.Commit()
}
