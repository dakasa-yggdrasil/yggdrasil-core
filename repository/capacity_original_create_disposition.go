package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only Begin constructs an owner. Candidate copies cannot supply authority or
// extend the original source request. Every completion attempt consumes it.
type OriginalCreateDispositionOwner struct {
	db        *sql.DB
	ctx       context.Context
	deadline  time.Time
	started   time.Time
	issuer    string
	grantID   string
	candidate []byte
	intentSHA string
	used      atomic.Bool
}

func (o *OriginalCreateDispositionOwner) Candidate() model.CapacityOriginalCreateDispositionCandidate {
	var c model.CapacityOriginalCreateDispositionCandidate
	if o != nil {
		_ = json.Unmarshal(o.candidate, &c)
	}
	return c
}

type originalDispositionSnapshot struct {
	candidate model.CapacityOriginalCreateDispositionCandidate
	record    capacityMutationRecord
	spec      model.CapacityPolicySpec
	intent    model.CapacityIntent
	intentSHA string
	now       time.Time
}

// No provider request or grant mutation occurs at Begin. The authenticated
// bridge alone converts Candidate.Request to one readonly adapter invocation.
func (s CapacityStore) BeginOriginalCreateDisposition(ctx context.Context, grantID, issuer string) (*OriginalCreateDispositionOwner, error) {
	if s.DB == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(grantID) || issuer == "" || len(issuer) > 256 {
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
	snap, err := loadOriginalCreateDispositionSnapshot(ctx, tx, grantID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(snap.candidate)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &OriginalCreateDispositionOwner{db: s.DB, ctx: ctx, deadline: deadline, started: time.Now().UTC(), issuer: issuer, grantID: grantID, candidate: raw, intentSHA: snap.intentSHA}, nil
}

func loadOriginalCreateDispositionSnapshot(ctx context.Context, tx *sql.Tx, id string) (originalDispositionSnapshot, error) {
	var out originalDispositionSnapshot
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
	var pointer sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,generation,integration_instance_id::text,scope_checksum,profile_name,slot,state,grant_record,original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&ns, &env, &domain, &dimension, &generation, &instance, &scopeSHA, &profile, &slot, &state, &raw, &pointer); err != nil {
		return out, err
	}
	if !bytes.Equal(locator, raw) || pointer.Valid || json.Unmarshal(raw, &out.record) != nil {
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
	unknownAWS := !settlement.AuxiliaryInventoryComplete && len(settlement.AuxiliaryResources) == 0 && original.Provider == "aws" && (original.AdapterSourceCommit == originalDispositionAWSOriginalSource || original.AdapterSourceCommit == originalDispositionAWS1653OriginalSource) && original.Schema == "aws_original_run_instances_return_v1" && original.ResponseStatus == 200 && validCapacityExecutor(settlement.ActionID)
	if !settlement.AuxiliaryInventoryComplete && !unknownAWS || settlement.AuxiliaryInventoryComplete && len(settlement.AuxiliaryResources) == 0 {
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
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=$1) OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$2) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record->'grant'->>'compensation_of'=$2::text) OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE workflow_id=$3 AND status IN('pending','running')) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE w.workflow_id=$3 AND (j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL)) OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=$4 AND environment=$5 AND domain=$6 AND dimension=$7 AND resource_id<>'')`, preID, id, r.WorkflowID, ns, env, domain, dimension).Scan(&blocked); err != nil {
		return out, err
	}
	if blocked {
		return out, ErrOriginalCreateDisposition
	}
	receipt := model.CapacityMutationReceipt{Grant: g, AttemptID: r.AttemptID, Outcome: settlement.Outcome, TransportCompleted: settlement.TransportCompleted, ResourceID: settlement.ResourceID, ResourceCreatedAt: settlement.ResourceCreatedAt, ActionID: settlement.ActionID, NextActionIDs: append([]string{}, settlement.NextActionIDs...), AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...), AuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete}
	out.candidate = model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: policy, Binding: b, Preregistration: pre, Receipt: receipt, Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: settlement.AuxiliaryInventoryComplete, Profile: b.ProfileName, Slot: g.Slot, GrantID: id, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, ExpectedResourceID: settlement.ResourceID, ExpectedResourceCreatedAt: settlement.ResourceCreatedAt, OriginalAdapterSourceCommit: original.AdapterSourceCommit, AuxiliaryResources: append([]model.CapacityMutationAuxiliaryResource{}, settlement.AuxiliaryResources...)}, OriginalGrantSHA256: originalDispositionDigest(raw), OriginalPreregistrationSHA256: originalDispositionDigest(preWire), OriginalBindingSHA256: originalDispositionDigest(bindingWire), OriginalSettlementSHA256: originalDispositionJSONSHA(settlement), OriginalPolicySHA256: originalDispositionDigest(policySpec), OriginalWorkflowSHA256: originalDispositionDigest(workflowSpec), Generation: intent.Generation, FencingToken: intent.FencingToken, BeganAt: out.now}
	if unknownAWS {
		out.candidate.Request.OriginalCreateActionID = settlement.ActionID
	}
	out.intentSHA = originalDispositionJSONSHA(intent)
	return out, nil
}

// Complete does no WAN work. Every eligibility predicate is rechecked after
// the separately authenticated source observer has closed its original GETs.
func (s CapacityStore) CompleteOriginalCreateDisposition(ctx context.Context, o *OriginalCreateDispositionOwner, observation model.CapacityOriginalCreateDispositionObservation) (model.CapacityOriginalCreateDisposition, error) {
	var result model.CapacityOriginalCreateDisposition
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
	snap, err := loadOriginalCreateDispositionSnapshot(ctx, tx, o.grantID)
	if err != nil {
		return result, err
	}
	old := o.Candidate()
	current := snap.candidate
	current.BeganAt = old.BeganAt
	fresh, encodeErr := json.Marshal(current)
	if encodeErr != nil || !bytes.Equal(fresh, o.candidate) || snap.intentSHA != o.intentSHA {
		return result, ErrOriginalCreateDisposition
	}
	age := time.Duration(snap.spec.MaxEvidenceAgeSeconds) * time.Second
	if err = validateOriginalDispositionObservation(old, observation, o.started, snap.now, age); err != nil {
		return result, err
	}
	r, pre := snap.record, old.Preregistration
	result = model.CapacityOriginalCreateDisposition{OriginalAuxiliaryInventoryComplete: r.Settlement.AuxiliaryInventoryComplete, Schema: model.OriginalCreateDispositionSchema, ID: uuid.NewString(), GrantID: o.grantID, PreregistrationID: pre.PreregistrationID, Issuer: o.issuer, OriginalGrantSHA256: old.OriginalGrantSHA256, OriginalPreregistrationSHA256: old.OriginalPreregistrationSHA256, OriginalBindingSHA256: old.OriginalBindingSHA256, OriginalSettlementSHA256: old.OriginalSettlementSHA256, OriginalPolicySHA256: old.OriginalPolicySHA256, OriginalWorkflowSHA256: old.OriginalWorkflowSHA256, PolicyID: pre.PolicyID, OriginalGeneration: r.Generation, OriginalFencingToken: r.FencingToken, ClosedGeneration: snap.intent.Generation, ClosedFencingToken: snap.intent.FencingToken + 1, OriginalDeadline: pre.OriginalDeadline, Observation: observation, ObservationSHA256: originalDispositionJSONSHA(observation), RecordedAt: snap.now, OriginalAcceptedUnchanged: true, OriginalWitnessEnrollmentInstallationAbsent: true, HistoricalCoreSourceCommit: pre.CoreSourceCommit}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 2<<20 {
		return result, ErrOriginalCreateDisposition
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_original_create_dispositions(id,grant_id,preregistration_id,original_grant_sha256,original_preregistration_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)`, result.ID, result.GrantID, result.PreregistrationID, result.OriginalGrantSHA256, result.OriginalPreregistrationSHA256, originalDispositionDigest(raw), raw, string(raw), result.RecordedAt, result.ClosedGeneration, result.ClosedFencingToken)
	if err != nil {
		return result, err
	}
	affected, err := tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET original_disposition_id=$2 WHERE id=$1 AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL`, result.GrantID, result.ID)
	if err != nil {
		return result, err
	}
	n, err := affected.RowsAffected()
	if err != nil || n != 1 {
		return result, ErrOriginalCreateDisposition
	}
	// Every other unresolved original still blocks closure. Only a validated
	// one-way FK pointer removes this exact grant from current authority counts.
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state IN('issued','redeemed','settled','compensating') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL`, snap.intent.Namespace, snap.spec.Environment, snap.spec.Domain, snap.spec.Dimension).Scan(&pending); err != nil {
		return result, err
	}
	if pending != 0 {
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
	// Baseline and assessment remain historical; this is no fresh health claim.
	body, err := json.Marshal(next)
	if err != nil {
		return result, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, next.Namespace, next.Environment, next.Domain, next.Dimension, string(body), snap.now)
	if err != nil {
		return result, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, next.Phase, "original-create-disposition:"+result.ID, snap.now)
	if err != nil {
		return result, err
	}
	if o.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return result, ErrOriginalCreateDisposition
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityOriginalCreateDisposition{}, err
	}
	// A committed record survives an uncertain/late HTTP acknowledgment. It
	// is recovered only through ReadOriginalCreateDisposition, never replay.
	if o.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(o.deadline) {
		return model.CapacityOriginalCreateDisposition{}, ErrOriginalCreateDisposition
	}
	return result, nil
}

// A lost completion acknowledgment is inspected by exact grant ID, without
// rerunning the source observer or acquiring another original provider grant.
func (s CapacityStore) ReadOriginalCreateDisposition(ctx context.Context, grantID string) (model.CapacityOriginalCreateDisposition, error) {
	var out model.CapacityOriginalCreateDisposition
	if s.DB == nil || !validCapacityExecutor(grantID) {
		return out, ErrOriginalCreateDisposition
	}
	var raw []byte
	var digest string
	err := s.DB.QueryRowContext(ctx, `SELECT d.original_wire,d.disposition_sha256 FROM public.capacity_original_create_dispositions d JOIN public.capacity_mutation_grants g ON (g.original_disposition_id,g.id)=(d.id,d.grant_id) WHERE g.id=$1`, grantID).Scan(&raw, &digest)
	if err != nil {
		return out, err
	}
	if originalDispositionDigest(raw) != digest || capacity.DecodeGuestLifecycle(raw, &out) != nil || out.GrantID != grantID || out.Schema != model.OriginalCreateDispositionSchema {
		return out, ErrOriginalCreateDisposition
	}
	return out, nil
}
