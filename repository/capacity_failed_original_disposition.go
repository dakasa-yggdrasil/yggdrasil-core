package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const failedOriginalHetznerCreator = "6026f78572a0ebfbf1b50984c2d47ff28bdc714d"

type failedOriginalDispositionSnapshot struct {
	originalDispositionSnapshot
	witnessSHA  string
	dispatchSHA string
	runSHA      string
	job         CapacityDispatchJob
}

// This owner is created only by the private database admission. It never
// authorizes a provider mutation, starts a workflow or renews an old deadline.
type FailedOriginalDispositionOwner struct {
	db        *sql.DB
	ctx       context.Context
	deadline  time.Time
	started   time.Time
	issuer    string
	grantID   string
	jobID     string
	candidate []byte
	snapshot  []byte
	used      atomic.Bool
}

func (o *FailedOriginalDispositionOwner) Candidate() model.CapacityOriginalCreateDispositionCandidate {
	var c model.CapacityOriginalCreateDispositionCandidate
	if o != nil {
		_ = json.Unmarshal(o.candidate, &c)
	}
	return c
}
func failedOriginalSnapshotBytes(s failedOriginalDispositionSnapshot) ([]byte, error) {
	return json.Marshal(struct {
		Candidate                                  model.CapacityOriginalCreateDispositionCandidate
		WitnessSHA, DispatchSHA, RunSHA, IntentSHA string
	}{s.candidate, s.witnessSHA, s.dispatchSHA, s.runSHA, s.intentSHA})
}

func (s CapacityStore) BeginFailedOriginalDisposition(ctx context.Context, grantID, jobID, issuer string) (*FailedOriginalDispositionOwner, error) {
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
	snap, err := loadFailedOriginalDispositionSnapshot(ctx, tx, grantID, jobID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap.candidate)
	if err != nil {
		return nil, err
	}
	snapshot, err := failedOriginalSnapshotBytes(snap)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &FailedOriginalDispositionOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), issuer: issuer, grantID: grantID, jobID: jobID, candidate: raw, snapshot: snapshot}, nil
}

func loadFailedOriginalDispositionSnapshot(ctx context.Context, tx *sql.Tx, id, jobID string) (failedOriginalDispositionSnapshot, error) {
	var out failedOriginalDispositionSnapshot
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
	var pointer, terminalPointer sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,integration_instance_id::text,scope_checksum,profile_name,slot,state,grant_record,original_disposition_id::text,failed_original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&ns, &env, &domain, &dimension, &generation, &instance, &scopeSHA, &profile, &slot, &state, &raw, &pointer, &terminalPointer); err != nil {
		return out, err
	}
	if !bytes.Equal(locator, raw) || (pointer.Valid || terminalPointer.Valid) || json.Unmarshal(raw, &out.record) != nil {
		return out, ErrOriginalCreateDisposition
	}
	r := out.record
	g, b := r.Grant, r.Binding
	if r.Settlement == nil || r.Settlement.OriginalProviderCreateReturn == nil || state != "settled" || g.State != state || g.GrantID != id || g.CompensationOf != "" || g.Capability != b.EnsureCapability || g.BindingName != b.Name || g.IntegrationInstanceID != instance || b.IntegrationInstanceID != instance || g.ScopeChecksum != scopeSHA || b.ScopeChecksum != scopeSHA || g.ProfileName != profile || b.ProfileName != profile || g.Slot != slot || slot < 1 || slot > 8 || r.Generation != generation || !validCapacityExecutor(r.AttemptID) || !originalDispositionHex(g.RequestSHA256, 64) {
		return out, ErrOriginalCreateDisposition
	}
	settlement := r.Settlement
	original := settlement.OriginalProviderCreateReturn
	if settlement.Outcome != "accepted" || !settlement.TransportCompleted || len(settlement.AuxiliaryResources) > 16 || settlement.GrantID != id || settlement.AttemptID != r.AttemptID || settlement.RequestSHA256 != g.RequestSHA256 || settlement.ResourceID == "" || settlement.ResourceCreatedAt == "" || settlement.ActionID == "" || original.GrantID != id || original.AttemptID != r.AttemptID || original.RequestSHA256 != g.RequestSHA256 || original.ResourceID != settlement.ResourceID || original.ResourceCreatedAt != settlement.ResourceCreatedAt || original.ActionID != settlement.ActionID || !slices.Equal(original.NextActionIDs, settlement.NextActionIDs) || original.AdapterSourceCommit != b.OriginalProviderSourceCommit || !originalDispositionHex(original.AdapterSourceCommit, 40) || original.Provider != r.EventProvider || (original.Provider != "aws" && original.Provider != "hetzner") {
		return out, ErrOriginalCreateDisposition
	}
	// Witnessed terminal accounting starts with the exact known H creator and
	// its complete original auxiliary list. AWS unknown-AUX uses its separate
	// existing disposition and cannot select this witnessed branch.
	if original.Provider != "hetzner" || original.AdapterSourceCommit != failedOriginalHetznerCreator || !settlement.AuxiliaryInventoryComplete {
		return out, ErrOriginalCreateDisposition
	}
	if len(settlement.AuxiliaryResources) == 0 {
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
	// Absence is rechecked while holding the same scope lock used by every
	// witness/registration and while the immutable original deadline is closed.
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		return out, err
	}
	w := stored.witness
	returned, returnErr := capacity.ValidateOriginalHetznerCreateReturn(b, g, r.AttemptID, *settlement, pre.ReservedAt, w.ObservedAt)
	if returnErr != nil || !returned.Equal(w.OriginalCreateReturnedAt) {
		return out, ErrOriginalCreateDisposition
	}
	if err = tx.QueryRowContext(ctx, `SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1 FOR SHARE`, preID).Scan(&out.witnessSHA); err != nil || !originalDispositionHex(out.witnessSHA, 64) || w.Schema != capacity.GuestCreateWitnessSchema || w.PreregistrationID != preID || w.BindingName != pre.BindingName || w.PreregistrationNonceSHA256 != pre.NonceSHA256 || w.OriginalCreateGrantID != id || w.OriginalCreateAttemptID != r.AttemptID || w.OriginalCreateRequestSHA256 != g.RequestSHA256 || w.OriginalCreateSettlementSHA256 != capacity.GuestRetirementSHA(*settlement) || w.ProfileManifestSHA256 != pre.ProfileManifestSHA256 || w.CoreSourceCommit != pre.CoreSourceCommit || !w.OriginalDeadline.Equal(pre.OriginalDeadline) || w.Tuple.Provider != original.Provider || w.Tuple.InstanceID != b.IntegrationInstanceID || w.Tuple.InstanceChecksum != b.IntegrationChecksum || w.Tuple.TypeID != b.IntegrationTypeID || w.Tuple.TypeChecksum != b.IntegrationTypeChecksum || w.Tuple.ScopeChecksum != b.ScopeChecksum || w.Tuple.Profile != b.ProfileName || w.Tuple.Slot != slot || w.Tuple.ResourceID != settlement.ResourceID || w.Tuple.CreatedAt != settlement.ResourceCreatedAt || w.ObservedAt.Before(w.OriginalCreateReturnedAt) || !w.ObservedAt.Before(pre.OriginalDeadline) || capacity.ValidateGuestProviderNativeIdentity(w.ProviderNativeIdentity, w.Tuple, original.AdapterSourceCommit, w.ObservedAt) != nil {
		return out, ErrOriginalCreateDisposition
	}
	if err = loadFailedOriginalDispatch(ctx, tx, jobID, ns, out.spec, r, pre, out.now, &out); err != nil {
		return out, err
	}
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$2) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$2::text) OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE (workflow_id=$3 OR (workflow_id IS NULL AND workflow_namespace=$9 AND workflow_name=$10 AND workflow_version=$11)) AND status IN('pending','running')) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=$4 AND j.environment=$5 AND j.domain=$6 AND j.dimension=$7 AND (j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL) AND j.id<>$8) OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=$4 AND environment=$5 AND domain=$6 AND dimension=$7 AND resource_id<>'')`, preID, id, r.WorkflowID, ns, env, domain, dimension, jobID, out.job.Workflow.Namespace, out.job.Workflow.Name, out.job.Workflow.Version).Scan(&blocked); err != nil {
		return out, err
	}
	if blocked {
		return out, ErrOriginalCreateDisposition
	}
	receipt := model.CapacityMutationReceipt{Grant: g, AttemptID: r.AttemptID, Outcome: settlement.Outcome, TransportCompleted: settlement.TransportCompleted, ResourceID: settlement.ResourceID, ResourceCreatedAt: settlement.ResourceCreatedAt, ActionID: settlement.ActionID, NextActionIDs: append([]string{}, settlement.NextActionIDs...), AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...), AuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete}
	out.candidate = model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: policy, Binding: b, Preregistration: pre, Receipt: receipt, Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete, Profile: b.ProfileName, Slot: g.Slot, GrantID: id, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, ExpectedResourceID: settlement.ResourceID, ExpectedResourceCreatedAt: settlement.ResourceCreatedAt, OriginalAdapterSourceCommit: original.AdapterSourceCommit, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...)}, OriginalGrantSHA256: originalDispositionDigest(raw), OriginalPreregistrationSHA256: originalDispositionDigest(preWire), OriginalBindingSHA256: originalDispositionDigest(bindingWire), OriginalSettlementSHA256: originalDispositionJSONSHA(settlement), OriginalPolicySHA256: originalDispositionDigest(policySpec), OriginalWorkflowSHA256: originalDispositionDigest(workflowSpec), Generation: intent.Generation, FencingToken: intent.FencingToken, BeganAt: out.now}
	out.intentSHA = originalDispositionJSONSHA(intent)
	return out, nil
}

// The dispatch scope lock follows the existing mutation/slot lock order. A
// finished failed run, not the caller's labels, selects the administrative lane.
func loadFailedOriginalDispatch(ctx context.Context, tx *sql.Tx, jobID, namespace string, p model.CapacityPolicySpec, original capacityMutationRecord, pre model.CapacityGuestOriginalProvisioningPreregistration, now time.Time, out *failedOriginalDispositionSnapshot) error {
	scope, _ := json.Marshal([]string{namespace, p.Environment, p.Domain, p.Dimension})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(scope)); err != nil {
		return err
	}
	job, err := readCapacityDispatchJob(ctx, tx, uuid.MustParse(jobID), true)
	if err != nil || job.State != "unknown" || job.Protocol != CapacityDispatchProtocol || job.Realm != namespace || job.Environment != p.Environment || job.Domain != p.Domain || job.Dimension != p.Dimension || job.Policy.ID != original.PolicyID || job.Policy.Checksum != original.PolicyChecksum || job.Workflow.ID != original.WorkflowID || job.Workflow.Checksum != pre.WorkflowChecksum || job.LeaseOwner == uuid.Nil || job.FencingToken < 1 || job.StartedAt == nil || job.ReturnedAt == nil || job.FinalizationAckAt != nil || job.LeaseExpiresAt == nil || now.Before(*job.LeaseExpiresAt) || job.ReturnedAt.Before(*job.StartedAt) || pre.ReservedAt.Before(*job.StartedAt) || pre.ReservedAt.After(*job.ReturnedAt) {
		return ErrOriginalCreateDisposition
	}
	var dispatchRaw, runRaw []byte
	var pointer sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT to_jsonb(j)::text,failed_original_disposition_id::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, jobID).Scan(&dispatchRaw, &pointer); err != nil || pointer.Valid {
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
		if step.ID == pre.OriginalWorkflowStepID && step.Status == "failed" && step.Metadata["original_guest_refusal_predicate"] == "original-guest-step-29" {
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

// No provider operation occurs here. The new terminal state is distinct from
// a normal return/ACK; every original byte and the unknown ACK stay unchanged.
func (s CapacityStore) CompleteFailedOriginalDisposition(ctx context.Context, owner *FailedOriginalDispositionOwner, observation model.CapacityOriginalCreateDispositionObservation) (model.CapacityFailedOriginalDisposition, error) {
	var result model.CapacityFailedOriginalDisposition
	if owner == nil || owner.db != s.DB || ctx == nil || ctx.Err() != nil || owner.ctx.Err() != nil || !owner.used.CompareAndSwap(false, true) {
		return result, ErrOriginalCreateDisposition
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(owner.deadline) || !time.Now().Before(owner.deadline) {
		return result, ErrOriginalCreateDisposition
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	snap, err := loadFailedOriginalDispositionSnapshot(ctx, tx, owner.grantID, owner.jobID)
	if err != nil {
		return result, err
	}
	old := owner.Candidate()
	snap.candidate.BeganAt = old.BeganAt
	fresh, err := failedOriginalSnapshotBytes(snap)
	if err != nil || !bytes.Equal(fresh, owner.snapshot) {
		return result, ErrOriginalCreateDisposition
	}
	if err = validateOriginalDispositionObservation(old, observation, owner.started, snap.now, time.Duration(snap.spec.MaxEvidenceAgeSeconds)*time.Second); err != nil {
		return result, err
	}
	result = model.CapacityFailedOriginalDisposition{
		Schema: model.FailedOriginalDispositionSchema, ID: uuid.NewString(), GrantID: owner.grantID, PreregistrationID: old.Preregistration.PreregistrationID, JobID: owner.jobID, RunID: snap.job.RunID.String(), Issuer: owner.issuer,
		OriginalGrantSHA256: old.OriginalGrantSHA256, OriginalPreregistrationSHA256: old.OriginalPreregistrationSHA256, OriginalWitnessSHA256: snap.witnessSHA, OriginalDispatchSHA256: snap.dispatchSHA, OriginalRunSHA256: snap.runSHA, OriginalBindingSHA256: old.OriginalBindingSHA256, OriginalSettlementSHA256: old.OriginalSettlementSHA256, OriginalPolicySHA256: old.OriginalPolicySHA256, OriginalWorkflowSHA256: old.OriginalWorkflowSHA256,
		OriginalGeneration: snap.record.Generation, OriginalFencingToken: snap.record.FencingToken, ClosedGeneration: snap.intent.Generation, ClosedFencingToken: snap.intent.FencingToken + 1, OriginalDeadline: old.Preregistration.OriginalDeadline, RecordedAt: snap.now, HistoricalCoreSourceCommit: old.Preregistration.CoreSourceCommit,
		Observation: observation, ObservationSHA256: originalDispositionJSONSHA(observation), OriginalAcceptedUnchanged: true, OriginalWitnessPreserved: true, OriginalUnknownACKPreserved: true, HistoricalWriterStartState: "unknown", ServingOrBusinessOrSavingsAuthority: false,
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 2<<20 {
		return result, ErrOriginalCreateDisposition
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_failed_original_dispositions(id,grant_id,preregistration_id,job_id,run_id,original_grant_sha256,original_preregistration_sha256,original_witness_sha256,original_dispatch_sha256,original_run_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16)`, result.ID, result.GrantID, result.PreregistrationID, result.JobID, result.RunID, result.OriginalGrantSHA256, result.OriginalPreregistrationSHA256, result.OriginalWitnessSHA256, result.OriginalDispatchSHA256, result.OriginalRunSHA256, originalDispositionDigest(raw), raw, string(raw), result.RecordedAt, result.ClosedGeneration, result.ClosedFencingToken)
	if err != nil {
		return result, err
	}
	n, err := tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET failed_original_disposition_id=$2 WHERE id=$1 AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL`, result.GrantID, result.ID)
	if err != nil {
		return result, err
	}
	count, err := n.RowsAffected()
	if err != nil || count != 1 {
		return result, ErrOriginalCreateDisposition
	}
	n, err = tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='failed_disposed',failed_original_disposition_id=$2,updated_at=$3 WHERE id=$1 AND state='unknown' AND failed_original_disposition_id IS NULL AND finalization_ack_at IS NULL`, result.JobID, result.ID, result.RecordedAt)
	if err != nil {
		return result, err
	}
	count, err = n.RowsAffected()
	if err != nil || count != 1 {
		return result, ErrOriginalCreateDisposition
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','settled','compensating') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL`, snap.intent.Namespace, snap.spec.Environment, snap.spec.Domain, snap.spec.Dimension).Scan(&pending); err != nil || pending != 0 {
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, "failed-original-disposition:"+result.ID, snap.now); err != nil {
		return result, err
	}
	if ctx.Err() != nil || owner.ctx.Err() != nil || !time.Now().Before(owner.deadline) {
		return result, ErrOriginalCreateDisposition
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityFailedOriginalDisposition{}, err
	}
	if ctx.Err() != nil || owner.ctx.Err() != nil || !time.Now().Before(owner.deadline) {
		return model.CapacityFailedOriginalDisposition{}, ErrOriginalCreateDisposition
	}
	return result, nil
}

func (s CapacityStore) ReadFailedOriginalDisposition(ctx context.Context, grantID string) (model.CapacityFailedOriginalDisposition, error) {
	var result model.CapacityFailedOriginalDisposition
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(grantID) {
		return result, ErrOriginalCreateDisposition
	}
	var raw []byte
	var digest string
	err := s.DB.QueryRowContext(ctx, `SELECT d.original_wire,d.disposition_sha256 FROM public.capacity_failed_original_dispositions d JOIN public.capacity_mutation_grants g ON (g.failed_original_disposition_id,g.id)=(d.id,d.grant_id) JOIN public.capacity_dispatch_jobs j ON (j.failed_original_disposition_id,j.id)=(d.id,d.job_id) WHERE g.id=$1 AND j.state='failed_disposed' AND j.finalization_ack_at IS NULL`, grantID).Scan(&raw, &digest)
	if err != nil || originalDispositionDigest(raw) != digest || capacity.DecodeGuestLifecycle(raw, &result) != nil || result.Schema != model.FailedOriginalDispositionSchema || result.GrantID != grantID || !result.OriginalAcceptedUnchanged || !result.OriginalWitnessPreserved || !result.OriginalUnknownACKPreserved || result.HistoricalWriterStartState != "unknown" || result.ServingOrBusinessOrSavingsAuthority {
		return model.CapacityFailedOriginalDisposition{}, ErrOriginalCreateDisposition
	}
	return result, nil
}
