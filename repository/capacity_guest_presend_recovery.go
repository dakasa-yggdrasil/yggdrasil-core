package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This private context exists only inside the current canonical plan. It is
// revalidated under the ordinary intent lock before BOTH recovery transitions;
// neither wire inputs nor a caller's no-mutation boolean can construct it.
type guestPresendRecovery struct {
	source       CapacityStore
	policy       model.Manifest
	assessment   model.CapacityAssessment
	preID, jobID string
	recovered    *model.CapacityIntent
}

type guestPresendCandidate struct {
	policy   model.Manifest
	pre      model.CapacityGuestOriginalProvisioningPreregistration
	jobID    string
	inflight int
}

// TryRecoverOriginalGuestPresend closes only an expired, never-redeemed
// original CREATE whose owning canonical invocation returned FAILED and was
// acknowledged. It does not resend, expire a live permission, adopt a resource,
// or certify Guest readiness. The invoking workflow UUID remains unchanged.
func (s CapacityStore) TryRecoverOriginalGuestPresend(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (bool, error) {
	if s.OriginalRunID == uuid.Nil {
		return false, nil
	}
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return false, err
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return false, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return false, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Live leases and unrelated states retain the ordinary pending HOLD.
	if !guestPresendIntentCandidate(&old, p) || len(p.Profiles) != 1 || p.Profiles[0].Provider != "hetzner" || old.LeaseExpiresAt == nil || old.LeaseExpiresAt.After(now) {
		return false, nil
	}
	// Discover applicability before checking an unchanged baseline. Installed
	// and cleanup lanes can legitimately have a changed native membership;
	// without an issued permission this hook must leave their old path intact.
	var issued bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND state='issued' AND NOT(grant_record?'authority_kind'))`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, old.Generation).Scan(&issued); err != nil {
		return false, err
	}
	if !issued {
		return false, nil
	}
	candidate, err := s.guestPresendCandidateTx(ctx, tx, policy, p, assessment, &old, now.UTC())
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = tx.Rollback(); err != nil {
		return false, err
	}
	guard := &guestPresendRecovery{source: s, policy: policy, assessment: assessment, preID: candidate.pre.PreregistrationID, jobID: candidate.jobID}
	recovery := s
	// The current B policy's private source pointer must not masquerade as
	// the historical A policy. Its full current authentication stays in guard.
	recovery.guestReconcile, recovery.guestPresendRecovery = nil, guard
	recovered, err := recovery.Recover(ctx, candidate.policy, old.Generation, assessment)
	if err != nil {
		return false, err
	}
	guard.recovered = &recovered
	zero := 0
	proof := model.CapacityTransitionProof{ReceiptRef: "original-guest-expired-presend:" + candidate.pre.PreregistrationID + ":" + candidate.jobID, ObservedAt: assessment.Snapshot.ObservedAt, Healthy: true, Inflight: &candidate.inflight, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", NoMutationVerified: true, Assessment: assessment}
	_, err = recovery.Reconcile(ctx, candidate.policy, recovered.Generation, recovered.FencingToken, recovered.LeaseOwner, "aborted", proof)
	return err == nil, err
}

func (g *guestPresendRecovery) guardTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, old *model.CapacityIntent, now time.Time) error {
	p, err := parseCapacityPolicy(g.policy)
	if err != nil {
		return err
	}
	candidate, err := g.source.guestPresendCandidateTx(ctx, tx, g.policy, p, g.assessment, old, now)
	if err != nil || candidate.policy.ID != policy.ID || candidate.policy.Checksum != policy.Checksum || candidate.pre.PreregistrationID != g.preID || candidate.jobID != g.jobID || old == nil || old.LeaseExpiresAt == nil {
		return ErrCapacityConflict
	}
	if g.recovered == nil {
		if old.LeaseExpiresAt.After(now) {
			return ErrCapacityLease
		}
	} else if !old.RecoveryOnly || old.FencingToken != g.recovered.FencingToken || old.LeaseOwner != g.recovered.LeaseOwner || old.LeaseExecutorID != g.source.ExecutorID || !old.LeaseExpiresAt.After(now) {
		return ErrCapacityLease
	}
	return nil
}

func guestPresendIntentCandidate(old *model.CapacityIntent, p model.CapacityPolicySpec) bool {
	return old != nil && old.Phase == "preparing" && !old.FloorDegraded && old.OriginalNotifyWindow == nil && old.InstalledGuestReconcile == nil && old.InstalledReadinessHandoff == nil && old.FailedInstalledDisposal == nil && old.FailedUnwitnessedExpansionCleanupID == "" && old.FailedExpansionTerminalReconcile == nil && old.WitnessedUnenrolledExpansionCleanupID == "" && old.WitnessedExpansionTerminalReconcile == nil && old.Decision.Action == "expand" && old.Decision.Units == old.BaselineSnapshot.Units+1 && old.BaselineSnapshot.Units >= p.Floor && old.Decision.Units <= p.Ceiling && old.Decision.Profile == old.BaselineSnapshot.Profile
}

func (s CapacityStore) guestPresendCandidateTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, assessment model.CapacityAssessment, old *model.CapacityIntent, now time.Time) (guestPresendCandidate, error) {
	var out guestPresendCandidate
	if !s.ExecutionEnabled || !p.ExecutionEnabled || !guestPresendIntentCandidate(old, p) || old.PolicyName != policy.Metadata.Name || old.Generation < 1 || old.FencingToken < 1 || old.FencingToken >= maxCapacityGeneration || !guestReconcileLive(ctx) {
		return out, ErrCapacityConflict
	}
	if err := s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return out, err
	}
	if s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || s.guestReconcile.mode != "" || s.guestReconcile.requestID != "" || s.OriginalRunID == uuid.Nil || s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil) != nil {
		return out, ErrCapacityConflict
	}
	var currentLive bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE run_id=$1 AND state='started' AND lease_expires_at>$2 AND returned_at IS NULL AND finalization_ack_at IS NULL)`, s.OriginalRunID, now).Scan(&currentLive); err != nil || !currentLive {
		return out, ErrCapacityLease
	}
	if err := guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return out, err
	}
	cs, err := guestContractSetTx(ctx, tx, policy, p)
	if err != nil {
		return out, err
	}
	views := make([]model.CapacityPolicySpec, len(cs))
	for i, c := range cs {
		views[i] = c.spec
	}
	var snapshot model.CapacitySnapshot
	if p.GuestContractSuccessor != nil {
		snapshot, _, err = capacity.GuestContractReconcileSnapshot(policy, p, views, s.guestReconcile.inventories, now)
	} else {
		snapshot, err = capacity.GuestReconcileSnapshot(policy, p, s.guestReconcile.inventory, now)
	}
	if err != nil || !reflect.DeepEqual(snapshot, assessment.Snapshot) || capacity.ValidateAssessment(p, assessment, now) != nil || capacity.GuestReconcileMemberCoverage(p, s.guestReconcile.reporting, snapshot.Units, now) != nil || !sameCapacityResources(old.BaselineSnapshot, snapshot) || old.BaselineSnapshot.ResourceVersion != snapshot.ResourceVersion || old.BaselineSnapshot.Units != snapshot.Units || old.BaselineSnapshot.Profile != snapshot.Profile {
		return out, ErrCapacityConflict
	}
	// Do not invent zero business work. The pinned signal reports handlers
	// per native member; retain a conservative whole-fleet upper observation.
	if len(assessment.Evidence) != 1 || assessment.Evidence[0].Name != "original-guest-handlers-per-member" || assessment.Evidence[0].Unit != "handlers_per_member" || assessment.Evidence[0].RangeMax == nil {
		return out, ErrCapacityConflict
	}
	work := math.Ceil(*assessment.Evidence[0].RangeMax * float64(snapshot.Units))
	if math.IsNaN(work) || math.IsInf(work, 0) || work < 0 || work > math.MaxInt32 {
		return out, ErrCapacityConflict
	}
	out.inflight = int(work)
	out.policy = model.Manifest{ID: old.PolicyID, Kind: "capacity_policy", Metadata: policy.Metadata}
	if err = tx.QueryRowContext(ctx, `SELECT version,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, old.PolicyID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&out.policy.Version, &out.policy.Checksum, &out.policy.Spec); err != nil {
		return out, err
	}
	prior, err := parseCapacityPolicy(out.policy)
	if err != nil || out.policy.Checksum != old.PolicyChecksum || out.policy.Version > policy.Version || !validCapacityBaseline(prior, *old) || len(prior.Profiles) != 1 || prior.Profiles[0].Provider != "hetzner" {
		return out, ErrCapacityConflict
	}
	priorContracts, err := guestContractSetAtPolicyTx(ctx, tx, out.policy, prior, false)
	if err != nil || len(priorContracts) != len(cs) {
		return out, ErrCapacityConflict
	}
	for i := range cs {
		if cs[i].digest != priorContracts[i].digest || !reflect.DeepEqual(cs[i].spec.MutationBindings, priorContracts[i].spec.MutationBindings) {
			return out, ErrCapacityConflict
		}
	}
	var raw []byte
	var consistent bool
	err = tx.QueryRowContext(ctx, `SELECT grant_record,NOT(grant_record?'authority_kind') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL AND id::text=grant_record#>>'{grant,grant_id}' AND generation=(grant_record->>'generation')::bigint AND state=grant_record#>>'{grant,state}' AND expires_at=(grant_record#>>'{grant,expires_at}')::timestamptz AND integration_instance_id::text=grant_record#>>'{binding,integration_instance_id}' AND scope_checksum=grant_record#>>'{binding,scope_checksum}' AND profile_name=grant_record#>>'{binding,profile_name}' AND slot=(grant_record#>>'{grant,slot}')::int FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$5 AND state='issued' ORDER BY id LIMIT 1 FOR UPDATE`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, old.Generation).Scan(&raw, &consistent)
	if err != nil {
		return out, err
	}
	var r capacityMutationRecord
	if !consistent || capacity.DecodeGuestLifecycle(raw, &r) != nil || r.PolicyID != old.PolicyID || r.PolicyChecksum != old.PolicyChecksum || r.WorkflowID != s.WorkflowID || r.Generation != old.Generation || r.FencingToken < 1 || r.Grant.State != "issued" || r.EventProvider != "hetzner" || r.Grant.Capability != r.Binding.EnsureCapability || r.Grant.BindingName != r.Binding.Name || r.Grant.IntegrationInstanceID != r.Binding.IntegrationInstanceID || r.Grant.ScopeChecksum != r.Binding.ScopeChecksum || r.Grant.ProfileName != r.Binding.ProfileName || r.Grant.CompensationOf != "" || r.Grant.Slot != old.Decision.Units || r.Grant.Slot <= r.Binding.ProtectedSlots || r.Grant.ExpiresAt.IsZero() || r.Grant.ExpiresAt.After(now) || r.CreatedAt.IsZero() || r.AttemptID != "" || r.SettlementTokenSHA256 != "" || r.Settlement != nil || r.Proof != nil || r.CompensationDrainProof != nil || r.FailedUnwitnessedExpansionCleanupID != "" || r.WitnessedUnenrolledExpansionCleanupID != "" || !reflect.DeepEqual(r.Binding, prior.MutationBindings[0]) || !validCapacityExecutor(r.ExecutorID) || !validCapacityExecutor(r.LeaseOwner) {
		return out, ErrCapacityConflict
	}
	if !old.RecoveryOnly {
		if old.FencingToken != r.FencingToken || old.LeaseOwner != r.LeaseOwner || old.LeaseExecutorID != r.ExecutorID {
			return out, ErrCapacityConflict
		}
	} else if old.FencingToken <= r.FencingToken || old.Decision.ExecutionPermitted || !validCapacityExecutor(old.LeaseOwner) || !validCapacityExecutor(old.LeaseExecutorID) {
		// An interrupted read-only recovery may be reacquired only after its
		// own lease expires. Original ownership still comes from pre/grant/run.
		return out, ErrCapacityConflict
	}
	approved := false
	for _, slot := range r.Binding.Slots {
		approved = approved || slot.Slot == r.Grant.Slot && slot.DesiredSpec != nil && slot.DesiredSpecSHA256 == r.Grant.RequestSHA256
	}
	if !approved {
		return out, ErrCapacityConflict
	}
	var preID string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, r.Grant.GrantID).Scan(&preID); err != nil {
		return out, err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, preID)
	if err != nil {
		return out, err
	}
	out.pre = stored.pre
	pre := out.pre
	if !reflect.DeepEqual(stored.binding, *prior.GuestRetirementBinding) || pre.BindingName != stored.member.Name || pre.PolicyID != r.PolicyID.String() || pre.PolicyChecksum != r.PolicyChecksum || pre.WorkflowID != s.WorkflowID.String() || pre.WorkflowChecksum != s.guestReconcile.workflow.Checksum || pre.Generation != r.Generation || pre.Fence != r.FencingToken || pre.LeaseOwner != r.LeaseOwner || pre.ExecutorID != r.ExecutorID || pre.Slot != r.Grant.Slot || pre.OriginalCreateRequestSHA256 != r.Grant.RequestSHA256 || pre.OriginalCreateGrantID != r.Grant.GrantID || pre.OriginalWorkflowStepID != prior.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID || pre.OriginalWorkflowStepTimeoutSeconds != 600 || pre.CoreSourceCommit != prior.GuestRetirementBinding.CoreAuthoritySourceCommit || pre.OriginalDeadline.After(now) || !r.CreatedAt.Equal(pre.ReservedAt) || !pre.ReservedAt.Before(pre.OriginalDeadline) {
		return out, ErrCapacityConflict
	}
	reads := s.guestReconcile.inventories
	if p.GuestContractSuccessor == nil {
		reads = []capacity.GuestContractInventory{{Inventory: s.guestReconcile.inventory}}
	}
	for _, read := range reads {
		started, e := time.Parse(time.RFC3339Nano, read.Inventory.ObservationStartedAt)
		if e != nil || started.Before(pre.OriginalDeadline) || started.Before(r.Grant.ExpiresAt) {
			return out, ErrCapacityConflict
		}
		// Healthy here means observed running, unlocked baseline VMs. It
		// neither substitutes for signed Guest readiness nor certifies canary.
		for _, member := range read.Inventory.Members {
			if member.Server.Status != "running" || member.Server.Locked {
				return out, ErrCapacityConflict
			}
		}
	}
	var blocked bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND id<>$5 AND state IN('issued','redeemed','settled','compensating')) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation=$6 AND id<>$5 AND state IN('confirmed','compensated')) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$7) OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$7) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=$7) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$7) OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$5) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=$5::text) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE realm=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND run_id<>$8 AND (state IN('queued','started','unknown') OR state='returned' AND finalization_ack_at IS NULL))`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, r.Grant.GrantID, old.Generation, preID, s.OriginalRunID).Scan(&blocked); err != nil || blocked {
		return out, ErrCapacityConflict
	}
	for _, c := range cs {
		var occupied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND resource_id<>'') OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND id<>$5 AND state IN('issued','redeemed','settled','compensating'))`, c.spec.MutationBindings[0].IntegrationInstanceID, c.spec.MutationBindings[0].ScopeChecksum, c.spec.MutationBindings[0].ProfileName, pre.Slot, r.Grant.GrantID).Scan(&occupied); err != nil || occupied {
			return out, ErrCapacityConflict
		}
	}
	out.jobID, err = s.guestPresendFailedRunTx(ctx, tx, out.policy, prior, pre, now)
	return out, err
}

func (s CapacityStore) guestPresendFailedRunTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration, now time.Time) (string, error) {
	// The plan precedes preregistration: its preregistration_id is EMPTY on
	// this real failure. Its immutable capacity owner/G/F/slot identifies the
	// later CREATE; dispatch ownership is a distinct UUID and is never equated.
	rows, err := tx.QueryContext(ctx, `SELECT j.id::text,w.result,w.inputs,w.metadata FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE (w.workflow_id IS NULL OR w.workflow_id=$1) AND w.status='failed' AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at AND w.finished_at=j.returned_at AND w.started_at=j.started_at AND w.workflow_namespace=$8 AND w.workflow_name=$9 AND w.workflow_version=$10 AND j.lease_expires_at<=$2 AND w.metadata->>'capacity_dispatch_job_id'=j.id::text AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.result#>>'{steps,0,id}'='plan-original-guest' AND w.result#>>'{steps,0,metadata,mode}'='provision' AND w.result#>>'{steps,0,metadata,generation}'=$3::text AND w.result#>>'{steps,0,metadata,fencing_token}'=$4::text AND w.result#>>'{steps,0,metadata,lease_owner}'=$5 AND w.result#>>'{steps,0,metadata,slot}'=$6::text AND w.id<>$7 LIMIT 2`, s.WorkflowID, now, pre.Generation, pre.Fence, pre.LeaseOwner, pre.Slot, s.OriginalRunID, s.guestReconcile.workflow.Metadata.Namespace, s.guestReconcile.workflow.Metadata.Name, s.guestReconcile.workflow.Version)
	if err != nil {
		return "", err
	}
	type returned struct {
		id                    string
		raw, inputs, metadata []byte
	}
	var all []returned
	for rows.Next() {
		var r returned
		if err = rows.Scan(&r.id, &r.raw, &r.inputs, &r.metadata); err != nil {
			rows.Close()
			return "", err
		}
		all = append(all, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(all) != 1 {
		return "", ErrCapacityConflict
	}
	j, err := readCapacityDispatchJob(ctx, tx, uuid.MustParse(all[0].id), true)
	wf := s.guestReconcile.workflow
	if err != nil || j.Policy != guestPresendManifestPin(policy) || j.Workflow != guestPresendManifestPin(wf) || j.Realm != policy.Metadata.Namespace || j.Environment != p.Environment || j.Domain != p.Domain || j.Dimension != p.Dimension || j.State != "returned" || j.FencingToken < 1 || j.LeaseOwner == uuid.Nil || j.StartedAt == nil || j.ReturnedAt == nil || j.FinalizationAckAt == nil || j.FinalizationAckAt.Before(*j.ReturnedAt) || j.LeaseExpiresAt == nil || j.LeaseExpiresAt.After(now) || pre.ReservedAt.Before(*j.StartedAt) || pre.ReservedAt.After(*j.ReturnedAt) || j.Metadata["capacity_dispatch_job_id"] != j.JobID.String() || j.Metadata["triggered_by"] != "workflow_scheduler" {
		return "", ErrCapacityConflict
	}
	var inputs, metadata map[string]any
	if json.Unmarshal(all[0].inputs, &inputs) != nil || json.Unmarshal(all[0].metadata, &metadata) != nil {
		return "", ErrCapacityConflict
	}
	iSHA, mSHA, e := CapacityDispatchEnvelopeHashes(CapacityDispatchEnvelope{Inputs: inputs, Metadata: metadata})
	if e != nil || iSHA != j.InputsSHA256 || mSHA != j.MetadataSHA256 {
		return "", ErrCapacityConflict
	}
	var result model.RunWorkflowResponse
	if json.Unmarshal(all[0].raw, &result) != nil || result.Status != "failed" || result.Workflow != (model.ManifestReference{ID: wf.ID, Kind: "workflow", Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name, Version: wf.Version}) || len(result.Steps) != 7 {
		return "", ErrCapacityConflict
	}
	seen := map[string]bool{}
	graph, err := capacity.OriginalGuestReconcileGraph(policy, p)
	if err != nil {
		return "", err
	}
	operations := map[string]string{}
	for _, step := range graph {
		operations[step.ID] = step.Use.Operation
	}
	for _, step := range result.Steps {
		if seen[step.ID] || operations[step.ID] == "" || step.Operation != operations[step.ID] {
			return "", ErrCapacityConflict
		}
		seen[step.ID] = true
		switch step.ID {
		case "plan-original-guest":
			if step.Operation != capacity.PlanOriginalGuestOperation || step.Status != "succeeded" || step.FinishedAt.After(pre.ReservedAt) || step.Metadata["preregistration_id"] != "" {
				return "", ErrCapacityConflict
			}
		case pre.OriginalWorkflowStepID:
			if step.Operation != capacity.ProvisionOriginalGuestOperation || step.Status != "failed" || step.Metadata["original_guest_refusal_predicate"] != "original-guest-step-25" || step.StartedAt.After(pre.ReservedAt) || step.FinishedAt.Before(pre.ReservedAt) {
				return "", ErrCapacityConflict
			}
		default:
			if step.Status != "skipped" {
				return "", ErrCapacityConflict
			}
		}
	}
	if !seen["plan-original-guest"] || !seen[pre.OriginalWorkflowStepID] {
		return "", ErrCapacityConflict
	}
	return all[0].id, nil
}

func guestPresendManifestPin(m model.Manifest) CapacityDispatchManifestPin {
	return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
}
