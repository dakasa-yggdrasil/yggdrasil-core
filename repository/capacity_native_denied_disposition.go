package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Reviewed one-send/no-SDK-retry creator; this is not a general uncertainty
// clearance. A future creator needs independent review of its send semantics.
const nativeDeniedOriginalAWSCreator = "d6af60729dee334c2be9bee45a0ba2dd02b7ec51"

type nativeDeniedDispositionSnapshot struct {
	failedOriginalDispositionSnapshot
	request model.CapacityNativeDeniedReadRequest
}

type NativeDeniedDispositionOwner struct {
	db                     *sql.DB
	ctx                    context.Context
	deadline               time.Time
	started                time.Time
	issuer, grantID, jobID string
	candidate, snapshot    []byte
	used                   atomic.Bool
}

func (o *NativeDeniedDispositionOwner) Candidate() model.CapacityNativeDeniedCandidate {
	var c model.CapacityNativeDeniedCandidate
	if o != nil {
		_ = json.Unmarshal(o.candidate, &c)
	}
	return c
}
func nativeDeniedSnapshotBytes(s nativeDeniedDispositionSnapshot) ([]byte, error) {
	return json.Marshal(struct {
		Candidate                      model.CapacityOriginalCreateDispositionCandidate
		Request                        model.CapacityNativeDeniedReadRequest
		DispatchSHA, RunSHA, IntentSHA string
	}{s.candidate, s.request, s.dispatchSHA, s.runSHA, s.intentSHA})
}
func nativeDeniedOriginalSettlement(r capacityMutationRecord) bool {
	s := r.Settlement
	return s != nil && r.Grant.ExpectedResourceID == "" && r.Grant.ExpectedResourceCreatedAt == "" && r.Grant.State == "settled" && r.EventProvider == "aws" && r.Binding.OriginalProviderSourceCommit == nativeDeniedOriginalAWSCreator && s.Outcome == "uncertain" && s.TransportCompleted && s.GrantID == r.Grant.GrantID && s.AttemptID == r.AttemptID && s.RequestSHA256 == r.Grant.RequestSHA256 && s.ResourceID == "" && s.ResourceCreatedAt == "" && s.ActionID == "" && len(s.NextActionIDs) == 0 && len(s.AuxiliaryResources) == 0 && !s.AuxiliaryInventoryComplete && s.OriginalProviderCreateReturn == nil && s.OriginalProviderDestroyReturn == nil && s.ProviderStatusCode == 0 && s.ProviderErrorCode == ""
}
func (s CapacityStore) BeginNativeDeniedDisposition(ctx context.Context, grantID, jobID, issuer string) (*NativeDeniedDispositionOwner, error) {
	actor := strings.TrimPrefix(issuer, "collaborator:")
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(grantID) || !validCapacityExecutor(jobID) || !validCapacityExecutor(actor) || issuer != "collaborator:"+actor {
		return nil, ErrOriginalCreateDisposition
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, ErrOriginalCreateDisposition
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snap, err := loadNativeDeniedDispositionSnapshot(ctx, tx, grantID, jobID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(model.CapacityNativeDeniedCandidate{Original: snap.candidate, Request: snap.request})
	if err != nil {
		return nil, err
	}
	snapshot, err := nativeDeniedSnapshotBytes(snap)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeDeniedDispositionOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), issuer: issuer, grantID: grantID, jobID: jobID, candidate: raw, snapshot: snapshot}, nil
}
func loadNativeDeniedDispositionSnapshot(ctx context.Context, tx *sql.Tx, id, jobID string) (nativeDeniedDispositionSnapshot, error) {
	var out nativeDeniedDispositionSnapshot
	var ns, env, domain, dimension string
	var locator []byte
	if err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,grant_record FROM public.capacity_mutation_grants WHERE id=$1`, id).Scan(&ns, &env, &domain, &dimension, &locator); err != nil {
		return out, err
	}
	var initial capacityMutationRecord
	if json.Unmarshal(locator, &initial) != nil {
		return out, ErrOriginalCreateDisposition
	}
	scope := model.CapacityPolicySpec{Environment: env, Domain: domain, Dimension: dimension}
	if err := lockMutationScope(ctx, tx, ns, scope); err != nil {
		return out, err
	}
	if err := lockNativeMutationSlot(ctx, tx, initial.Binding, initial.Grant.Slot); err != nil {
		return out, err
	}
	var raw []byte
	var state, instance, scopeSHA, profile string
	var generation int64
	var slot int
	var pointer, terminalPointer, deniedPointer sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,integration_instance_id::text,scope_checksum,profile_name,slot,state,grant_record,original_disposition_id::text,failed_original_disposition_id::text,native_denied_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&ns, &env, &domain, &dimension, &generation, &instance, &scopeSHA, &profile, &slot, &state, &raw, &pointer, &terminalPointer, &deniedPointer); err != nil {
		return out, err
	}
	if !bytes.Equal(locator, raw) || (pointer.Valid || terminalPointer.Valid || deniedPointer.Valid) || json.Unmarshal(raw, &out.record) != nil {
		return out, ErrOriginalCreateDisposition
	}
	r := out.record
	g, b := r.Grant, r.Binding
	if r.Settlement == nil || r.Settlement.OriginalProviderCreateReturn != nil || r.Settlement.OriginalProviderDestroyReturn != nil || r.EventProvider != "aws" || b.OriginalProviderSourceCommit != nativeDeniedOriginalAWSCreator || state != "settled" || g.State != state || g.GrantID != id || g.CompensationOf != "" || g.Capability != b.EnsureCapability || g.BindingName != b.Name || g.IntegrationInstanceID != instance || b.IntegrationInstanceID != instance || g.ScopeChecksum != scopeSHA || b.ScopeChecksum != scopeSHA || g.ProfileName != profile || b.ProfileName != profile || g.Slot != slot || slot < 1 || slot > 8 || r.Generation != generation || !validCapacityExecutor(r.AttemptID) || !originalDispositionHex(g.RequestSHA256, 64) {
		return out, ErrOriginalCreateDisposition
	}
	settlement := r.Settlement
	if !nativeDeniedOriginalSettlement(r) {
		return out, ErrOriginalCreateDisposition
	}
	var preID string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1 FOR SHARE`, id).Scan(&preID); err != nil {
		return out, err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	pre := stored.pre
	if pre.OriginalCreateGrantID != id || pre.OriginalCreateRequestSHA256 != g.RequestSHA256 || pre.PolicyID != r.PolicyID.String() || pre.PolicyChecksum != r.PolicyChecksum || pre.WorkflowID != r.WorkflowID.String() || pre.Generation != r.Generation || pre.Fence != r.FencingToken || pre.LeaseOwner != r.LeaseOwner || pre.ExecutorID != r.ExecutorID || pre.Slot != slot || stored.binding.MutationBindingName != b.Name || stored.binding.CoreAuthoritySourceCommit != pre.CoreSourceCommit || !originalDispositionHex(pre.CoreSourceCommit, 40) || stored.binding.ProfileManifestSHA256 != pre.ProfileManifestSHA256 || capacity.GuestRetirementSHA(stored.binding.ProfileManifest) != pre.ProfileManifestSHA256 {
		return out, ErrOriginalCreateDisposition
	}
	var approved *model.CapacityMutationSpecV1
	for _, a := range b.Slots {
		if a.Slot == slot && a.DesiredSpecSHA256 == g.RequestSHA256 {
			approved = a.DesiredSpec
		}
	}
	if approved == nil || approved.BootstrapSHA256 != capacity.GuestProfileBootstrapSHA(stored.binding.ProfileManifest, slot) || !originalDispositionHex(approved.BootstrapSHA256, 64) {
		return out, ErrOriginalCreateDisposition
	}
	var policy model.Manifest
	policy.ID = r.PolicyID
	policy.Kind = "capacity_policy"
	var policySpec, workflowSpec, preWire, bindingWire []byte
	var workflowChecksum string
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, r.PolicyID).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Checksum, &policySpec); err != nil {
		return out, err
	}
	policy.Spec = append([]byte(nil), policySpec...)
	// Historical source is validated against its immutable original contract,
	// never against CurrentGuestCoreSource or a later policy/profile revision.
	if policy.Metadata.Namespace != ns || policy.Checksum != r.PolicyChecksum || json.Unmarshal(policySpec, &out.spec) != nil || out.spec.Environment != env || out.spec.Domain != domain || out.spec.Dimension != dimension || out.spec.GuestRetirementBinding == nil || !reflect.DeepEqual(*out.spec.GuestRetirementBinding, stored.binding) {
		return out, ErrOriginalCreateDisposition
	}
	if err = tx.QueryRowContext(ctx, `SELECT checksum,spec FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, r.WorkflowID).Scan(&workflowChecksum, &workflowSpec); err != nil {
		return out, err
	}
	if workflowChecksum != pre.WorkflowChecksum {
		return out, ErrOriginalCreateDisposition
	}
	if err = tx.QueryRowContext(ctx, `SELECT original_wire,binding_wire FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1`, preID).Scan(&preWire, &bindingWire); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&out.now); err != nil {
		return out, err
	}
	out.now = out.now.UTC()
	if !out.now.After(pre.OriginalDeadline) {
		return out, ErrOriginalCreateDisposition
	}
	out.intent, err = loadCapacityIntent(ctx, tx, ns, scope, true)
	if err != nil {
		return out, err
	}
	intent := out.intent
	if intent.PolicyID != r.PolicyID || intent.PolicyChecksum != r.PolicyChecksum || intent.Generation != r.Generation || intent.FencingToken < r.FencingToken || intent.FencingToken >= maxCapacityGeneration || intent.Decision.Reason != "protected_floor_recovery" || !pendingCapacityPhase(intent.Phase) || intent.Phase == "proposed" || intent.BaselineSnapshot.Units != 0 || intent.Assessment.Snapshot.Units != 0 || out.spec.Floor < 1 || intent.LeaseExpiresAt != nil && intent.LeaseExpiresAt.After(out.now) {
		return out, ErrOriginalCreateDisposition
	}
	// No witness may have been recorded. This branch proves an authorization
	// decision; it never manufactures an original successful provider return.
	if err = loadNativeDeniedDispatch(ctx, tx, jobID, ns, out.spec, r, pre, out.now, &out.failedOriginalDispositionSnapshot); err != nil {
		return out, err
	}
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$2) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$2::text) OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE (workflow_id=$3 OR (workflow_id IS NULL AND workflow_namespace=$9 AND workflow_name=$10 AND workflow_version=$11)) AND status IN('pending','running')) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=$4 AND j.environment=$5 AND j.domain=$6 AND j.dimension=$7 AND (j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL) AND j.id<>$8) OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=$4 AND environment=$5 AND domain=$6 AND dimension=$7 AND resource_id<>'')`, preID, id, r.WorkflowID, ns, env, domain, dimension, jobID, out.job.Workflow.Namespace, out.job.Workflow.Name, out.job.Workflow.Version).Scan(&blocked); err != nil {
		return out, err
	}
	if blocked {
		return out, ErrOriginalCreateDisposition
	}
	receipt := model.CapacityMutationReceipt{Grant: g, AttemptID: r.AttemptID, Outcome: settlement.Outcome, TransportCompleted: settlement.TransportCompleted, ResourceID: settlement.ResourceID, ResourceCreatedAt: settlement.ResourceCreatedAt, ActionID: settlement.ActionID, NextActionIDs: append([]string{}, settlement.NextActionIDs...), AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...), AuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete}
	out.candidate = model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: policy, Binding: b, Preregistration: pre, Receipt: receipt, Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete, Profile: b.ProfileName, Slot: g.Slot, GrantID: id, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, ExpectedResourceID: settlement.ResourceID, ExpectedResourceCreatedAt: settlement.ResourceCreatedAt, OriginalAdapterSourceCommit: b.OriginalProviderSourceCommit, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...)}, OriginalGrantSHA256: originalDispositionDigest(raw), OriginalPreregistrationSHA256: originalDispositionDigest(preWire), OriginalBindingSHA256: originalDispositionDigest(bindingWire), OriginalSettlementSHA256: originalDispositionJSONSHA(settlement), OriginalPolicySHA256: originalDispositionDigest(policySpec), OriginalWorkflowSHA256: originalDispositionDigest(workflowSpec), Generation: intent.Generation, FencingToken: intent.FencingToken, BeganAt: out.now}
	observed, err := time.Parse(time.RFC3339Nano, settlement.ObservedAt)
	if err != nil || observed.Before(r.CreatedAt.Add(-5*time.Second)) || !observed.Before(pre.OriginalDeadline) || !out.now.After(g.ExpiresAt) {
		return out, ErrOriginalCreateDisposition
	}
	out.request = model.CapacityNativeDeniedReadRequest{Schema: model.NativeDeniedReadRequestSchema, Profile: b.ProfileName, Slot: g.Slot, GrantID: id, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, ScopeChecksum: b.ScopeChecksum, OriginalAdapterSourceCommit: b.OriginalProviderSourceCommit, GrantCreatedAt: r.CreatedAt, SettlementObservedAt: observed, OriginalDeadline: pre.OriginalDeadline}
	out.intentSHA = originalDispositionJSONSHA(intent)
	return out, nil
}

func loadNativeDeniedDispatch(ctx context.Context, tx *sql.Tx, jobID, namespace string, p model.CapacityPolicySpec, original capacityMutationRecord, pre model.CapacityGuestOriginalProvisioningPreregistration, now time.Time, out *failedOriginalDispositionSnapshot) error {
	scope, _ := json.Marshal([]string{namespace, p.Environment, p.Domain, p.Dimension})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(scope)); err != nil {
		return err
	}
	job, err := readCapacityDispatchJob(ctx, tx, uuid.MustParse(jobID), true)
	_, ackLaneOK := nativeDeniedDispatchSchema(job)
	if err != nil || !ackLaneOK || job.Protocol != CapacityDispatchProtocol || job.Realm != namespace || job.Environment != p.Environment || job.Domain != p.Domain || job.Dimension != p.Dimension || job.Policy.ID != original.PolicyID || job.Policy.Checksum != original.PolicyChecksum || job.Workflow.ID != original.WorkflowID || job.Workflow.Checksum != pre.WorkflowChecksum || job.LeaseOwner == uuid.Nil || job.FencingToken < 1 || job.StartedAt == nil || job.ReturnedAt == nil || job.LeaseExpiresAt == nil || now.Before(*job.LeaseExpiresAt) || job.ReturnedAt.Before(*job.StartedAt) || pre.ReservedAt.Before(*job.StartedAt) || pre.ReservedAt.After(*job.ReturnedAt) {
		return ErrOriginalCreateDisposition
	}
	var dispatchRaw, runRaw []byte
	var pointer sql.NullString
	var returnStatus sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT to_jsonb(j)::text,native_denied_disposition_id::text,return_status FROM public.capacity_dispatch_jobs j WHERE id=$1`, jobID).Scan(&dispatchRaw, &pointer, &returnStatus); err != nil || pointer.Valid || job.State == "returned" && (!returnStatus.Valid || returnStatus.String != "failed") {
		return ErrOriginalCreateDisposition
	}
	// The owning InsertWorkflowRunTx stores the immutable selector but omits
	// workflow_id. Preserve that historical NULL; the envelope and complete
	// returned Workflow identity remain mandatory below.
	var workflowID sql.NullString
	var status string
	var started, finished sql.NullTime
	var resultRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT workflow_id::text,status,started_at,finished_at,result,to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1 FOR UPDATE`, job.RunID).Scan(&workflowID, &status, &started, &finished, &resultRaw, &runRaw); err != nil || workflowID.Valid && workflowID.String != original.WorkflowID.String() || status != "failed" || !started.Valid || !finished.Valid || !started.Time.Equal(*job.StartedAt) || !finished.Time.Equal(*job.ReturnedAt) || finished.Time.Before(started.Time) {
		return ErrOriginalCreateDisposition
	}
	var result model.RunWorkflowResponse
	if json.Unmarshal(resultRaw, &result) != nil || result.Status != "failed" || result.Workflow.ID != job.Workflow.ID || result.Workflow.Namespace != job.Workflow.Namespace || result.Workflow.Name != job.Workflow.Name || result.Workflow.Version != job.Workflow.Version {
		return ErrOriginalCreateDisposition
	}
	plan, failed := false, false
	for _, step := range result.Steps {
		if step.ID == "plan-original-guest" && step.Status == "succeeded" {
			raw, _ := json.Marshal(step.Metadata)
			var m struct {
				Generation int64  `json:"generation"`
				Fence      int64  `json:"fencing_token"`
				Owner      string `json:"lease_owner"`
			}
			if json.Unmarshal(raw, &m) == nil && m.Generation == original.Generation && m.Fence == original.FencingToken && m.Owner == original.LeaseOwner {
				plan = true
			}
		}
		if step.ID == pre.OriginalWorkflowStepID && step.Status == "failed" && step.Metadata["original_guest_refusal_predicate"] == "original-guest-step-25" {
			failed = true
		}
	}
	if !plan || !failed {
		return ErrOriginalCreateDisposition
	}
	out.job = job
	out.dispatchSHA = originalDispositionDigest(dispatchRaw)
	out.runSHA = originalDispositionDigest(runRaw)
	return nil
}

// Complete repeats the original closed snapshot under the same locks. The
// native decision is obtained outside SQL; only an exactly matching owner may
// append it and advance the accounting fence once.
func (s CapacityStore) CompleteNativeDeniedDisposition(ctx context.Context, o *NativeDeniedDispositionOwner, observation model.CapacityNativeDeniedObservation) (model.CapacityNativeDeniedDisposition, error) {
	var result model.CapacityNativeDeniedDisposition
	if o == nil || o.db != s.DB || ctx == nil || ctx.Err() != nil || o.ctx.Err() != nil || !o.used.CompareAndSwap(false, true) {
		return result, ErrOriginalCreateDisposition
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(o.deadline) || !time.Now().Before(o.deadline) {
		return result, ErrOriginalCreateDisposition
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	snap, err := loadNativeDeniedDispositionSnapshot(ctx, tx, o.grantID, o.jobID)
	if err != nil {
		return result, err
	}
	old := o.Candidate()
	snap.candidate.BeganAt = old.Original.BeganAt
	fresh, err := nativeDeniedSnapshotBytes(snap)
	if err != nil || !bytes.Equal(fresh, o.snapshot) {
		return result, ErrOriginalCreateDisposition
	}
	if err = validateNativeDeniedObservation(old, observation, o.started, snap.now, time.Duration(snap.spec.MaxEvidenceAgeSeconds)*time.Second); err != nil {
		return result, err
	}
	c := old.Original
	result = model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedDispositionSchema, ID: uuid.NewString(), GrantID: o.grantID, PreregistrationID: c.Preregistration.PreregistrationID, JobID: o.jobID, RunID: snap.job.RunID.String(), Issuer: o.issuer,
		OriginalGrantSHA256: c.OriginalGrantSHA256, OriginalPreregistrationSHA256: c.OriginalPreregistrationSHA256, OriginalSettlementSHA256: c.OriginalSettlementSHA256, OriginalBindingSHA256: c.OriginalBindingSHA256, OriginalPolicySHA256: c.OriginalPolicySHA256, OriginalWorkflowSHA256: c.OriginalWorkflowSHA256, OriginalDispatchSHA256: snap.dispatchSHA, OriginalRunSHA256: snap.runSHA,
		OriginalGeneration: snap.record.Generation, OriginalFencingToken: snap.record.FencingToken, ClosedGeneration: snap.intent.Generation, ClosedFencingToken: snap.intent.FencingToken + 1, OriginalDeadline: c.Preregistration.OriginalDeadline, HistoricalCoreSourceCommit: c.Preregistration.CoreSourceCommit,
		Observation: observation, ObservationSHA256: originalDispositionJSONSHA(observation), RecordedAt: snap.now, OriginalUncertainAndNullIdentitiesUnchanged: true, OriginalUnknownACKPreserved: true, WitnessEnrollmentInstallationAbsent: true}
	if snap.job.State == "returned" {
		ack := snap.job.FinalizationAckAt.UTC()
		result.Schema = model.NativeDeniedReturnedACKDispositionSchema
		result.OriginalUnknownACKPreserved = false
		result.OriginalDispatchState = "returned"
		result.OriginalFinalizationACKAt = &ack
		result.OriginalFailedWorkflowACKPreserved = true
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 2<<20 {
		return result, ErrOriginalCreateDisposition
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_denied_dispositions(id,grant_id,preregistration_id,job_id,run_id,original_grant_sha256,original_preregistration_sha256,original_dispatch_sha256,original_run_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15)`, result.ID, result.GrantID, result.PreregistrationID, result.JobID, result.RunID, result.OriginalGrantSHA256, result.OriginalPreregistrationSHA256, result.OriginalDispatchSHA256, result.OriginalRunSHA256, originalDispositionDigest(raw), raw, string(raw), result.RecordedAt, result.ClosedGeneration, result.ClosedFencingToken)
	if err != nil {
		return result, err
	}
	n, err := tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET native_denied_disposition_id=$2 WHERE id=$1 AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL`, result.GrantID, result.ID)
	if err != nil {
		return result, err
	}
	count, err := n.RowsAffected()
	if err != nil || count != 1 {
		return result, ErrOriginalCreateDisposition
	}
	n, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='native_denied_disposed',native_denied_disposition_id=$2,updated_at=$3 WHERE id=$1 AND state=$4 AND native_denied_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND finalization_ack_at IS NOT DISTINCT FROM $5::timestamptz`, result.JobID, result.ID, result.RecordedAt, snap.job.State, snap.job.FinalizationAckAt)
	if err != nil {
		return result, err
	}
	count, err = n.RowsAffected()
	if err != nil || count != 1 {
		return result, ErrOriginalCreateDisposition
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','settled','compensating') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL`, snap.intent.Namespace, snap.spec.Environment, snap.spec.Domain, snap.spec.Dimension).Scan(&pending); err != nil || pending != 0 {
		return result, ErrOriginalCreateDisposition
	}
	next := snap.intent
	next.Phase = "reconciled_failed_floor"
	next.FloorDegraded = true
	next.RecoveryOnly = false
	next.Decision.ExecutionPermitted = false
	next.FencingToken = result.ClosedFencingToken
	next.LeaseOwner = ""
	next.LeaseExecutorID = ""
	next.LeaseExpiresAt = nil
	next.UpdatedAt = snap.now
	next.Decision.Clock.LastActionAt = snap.now
	next.Decision.Clock.UpSince = time.Time{}
	next.Decision.Clock.DownSince = time.Time{}
	body, err := json.Marshal(next)
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, next.Namespace, next.Environment, next.Domain, next.Dimension, string(body), snap.now); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, "native-denied-disposition:"+result.ID, snap.now); err != nil {
		return result, err
	}
	if ctx.Err() != nil || o.ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return result, ErrOriginalCreateDisposition
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityNativeDeniedDisposition{}, err
	}
	if ctx.Err() != nil || o.ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return model.CapacityNativeDeniedDisposition{}, ErrOriginalCreateDisposition
	}
	return result, nil
}
func (s CapacityStore) ReadNativeDeniedDisposition(ctx context.Context, grantID string) (model.CapacityNativeDeniedDisposition, error) {
	var v model.CapacityNativeDeniedDisposition
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(grantID) {
		return v, ErrOriginalCreateDisposition
	}
	var raw []byte
	var digest string
	var acknowledged sql.NullTime
	err := s.DB.QueryRowContext(ctx, `SELECT d.original_wire,d.disposition_sha256,j.finalization_ack_at FROM public.capacity_native_denied_dispositions d JOIN public.capacity_mutation_grants g ON(g.native_denied_disposition_id,g.id)=(d.id,d.grant_id) JOIN public.capacity_dispatch_jobs j ON(j.native_denied_disposition_id,j.id)=(d.id,d.job_id) WHERE g.id=$1 AND j.state='native_denied_disposed'`, grantID).Scan(&raw, &digest, &acknowledged)
	var ack *time.Time
	if acknowledged.Valid {
		ack = &acknowledged.Time
	}
	if err != nil || originalDispositionDigest(raw) != digest || capacity.DecodeGuestLifecycle(raw, &v) != nil || !nativeDeniedDispositionACKMatches(v, ack) || v.GrantID != grantID || !v.OriginalUncertainAndNullIdentitiesUnchanged || !v.WitnessEnrollmentInstallationAbsent || v.ServingOrBusinessOrSavingsAuthority {
		return model.CapacityNativeDeniedDisposition{}, ErrOriginalCreateDisposition
	}
	return v, nil
}
