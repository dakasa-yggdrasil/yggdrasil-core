package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const CapacityDispatchInstalledProvisionTimeoutState = "installed_timeout_disposed"
const CapacityDispatchInstalledProvisionTimeoutSchema = "unknown_installed_provision_timeout_disposition_v1"

// This is deliberately narrower than a failed installed readiness run. The
// provider step closed successfully; the failed completion reached only its
// read-only assessment. No canary, retirement or provider retry is inferred.
func installedProvisionTimeoutResult(raw []byte, pre model.CapacityGuestOriginalProvisioningPreregistration, old model.CapacityIntent, workflow CapacityDispatchManifestPin, spec model.WorkflowManifestSpec) bool {
	if !originalInstalledFailureResult(raw, pre, workflow.ID) {
		return false
	}
	var r model.RunWorkflowResponse
	if json.Unmarshal(raw, &r) != nil || r.Workflow != (model.ManifestReference{ID: workflow.ID, Kind: "workflow", Namespace: workflow.Namespace, Name: workflow.Name, Version: workflow.Version}) {
		return false
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(spec)
	if err != nil || len(ordered) != 7 || len(r.Steps) != len(ordered) {
		return false
	}
	by := map[string]model.WorkflowRunStepResult{}
	for i, step := range r.Steps {
		if _, duplicate := by[step.ID]; duplicate {
			return false
		}
		if step.ID != ordered[i].ID || step.Kind != "yggdrasil" || step.Operation != manifestengine.NormalizeWorkflowStepOperation(ordered[i]) || step.Capability != manifestengine.NormalizeWorkflowStepCapability(ordered[i]) || step.StartedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) {
			return false
		}
		if step.Status == "skipped" {
			if step.Attempts != 0 || len(step.Metadata) != 0 {
				return false
			}
		} else if step.Attempts != 1 {
			return false
		}
		by[step.ID] = step
	}
	complete := by["complete-original-provision"]
	if len(complete.Metadata) != 1 || complete.Metadata["original_guest_reconcile_refusal_stage"] != "source_assessment" || complete.Operation != capacity.CompleteOriginalGuestOperation || complete.Error != "original Guest reconciliation held" {
		return false
	}
	provision := by["provision-original-notify"]
	if !provision.FinishedAt.Before(pre.OriginalDeadline) || complete.StartedAt.Before(provision.FinishedAt) || by["plan-original-guest"].FinishedAt.After(provision.StartedAt) {
		return false
	}
	var plan struct {
		Mode       string `json:"mode"`
		Slot       int    `json:"slot"`
		Generation int64  `json:"generation"`
		Fence      int64  `json:"fencing_token"`
		Owner      string `json:"lease_owner"`
	}
	wire, err := json.Marshal(by["plan-original-guest"].Metadata)
	return err == nil && json.Unmarshal(wire, &plan) == nil && plan.Mode == "provision" && plan.Slot == pre.Slot && plan.Generation == old.Generation && plan.Fence == old.FencingToken && plan.Owner == old.LeaseOwner && by["plan-original-guest"].Operation == capacity.PlanOriginalGuestOperation && by["provision-original-notify"].Operation == capacity.ProvisionOriginalGuestOperation
}

func installedProvisionTimeoutCandidate(old model.CapacityIntent, policy model.Manifest, p model.CapacityPolicySpec, now time.Time) bool {
	n := old.Decision.Units
	return p.ExecutionEnabled && p.GuestRetirementBinding != nil && p.GuestNotifyReconcileBinding != nil && capacity.ValidateGuestNotifyReconcileBinding(p) == nil && old.PolicyID == policy.ID && old.PolicyChecksum == policy.Checksum && old.Phase == "preparing" && !old.RecoveryOnly && !old.FloorDegraded && old.InstalledGuestReconcile == nil && old.FailedInstalledDisposal == nil && old.FailedServingDisposal == nil && old.FailedExpansionTerminalReconcile == nil && old.FailedUnwitnessedExpansionCleanupID == "" && old.RetirementForward == nil && old.OriginalNotifyWindow == nil && old.Generation > 0 && old.FencingToken > 0 && old.FencingToken < maxCapacityGeneration && validCapacityExecutor(old.LeaseOwner) && validCapacityExecutor(old.LeaseExecutorID) && old.LeaseExpiresAt != nil && !old.LeaseExpiresAt.After(now) && old.Decision.Action == "expand" && n >= 2 && n <= 8 && n <= p.Ceiling && old.BaselineSnapshot.Units == n-1 && old.Assessment.Snapshot.Units >= n-1 && old.Assessment.Snapshot.Units <= n
}

// Only recorded physical identity is admitted here. Fresh provider inventory,
// coverage and canaries remain mandatory in the distinct readiness workflow.
func installedProvisionTimeoutMembersTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent) ([]model.CapacityInstalledProvisionTimeoutMember, *guestOriginalStored, error) {
	if p.GuestRetirementBinding == nil || len(p.MutationBindings) != 1 {
		return nil, nil, ErrCapacityConflict
	}
	b := p.MutationBindings[0]
	var occupied, foreign int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE resource_id<>'' AND slot_record->'tombstone'='false'::jsonb),count(*) FILTER(WHERE slot_record ? 'authority_kind' OR resource_id<>'' AND slot_record->'tombstone'='false'::jsonb AND (integration_instance_id<>$5 OR scope_checksum<>$6 OR profile_name<>$7 OR slot<1 OR slot>$8 OR slot_record->>'resource_id' IS DISTINCT FROM resource_id)) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, old.Decision.Units).Scan(&occupied, &foreign)
	if err != nil {
		return nil, nil, err
	}
	if occupied != old.Decision.Units || foreign != 0 {
		return nil, nil, ErrCapacityConflict
	}
	members := []model.CapacityInstalledProvisionTimeoutMember{}
	var selected *guestOriginalStored
	for _, member := range p.GuestRetirementBinding.Members {
		slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, member.Slot)
		if err != nil {
			return nil, nil, err
		}
		if !exists || slot.Tombstone || slot.ResourceID == "" {
			continue
		}
		if member.Slot < 1 || member.Slot > old.Decision.Units || slot.BindingName != b.Name || slot.ProfileName != b.ProfileName {
			return nil, nil, ErrCapacityConflict
		}
		receipt, err := guestNotifyMemberReceiptTx(ctx, tx, policy, p, member, slot)
		if err != nil {
			return nil, nil, err
		}
		stored, err := loadGuestOriginalTx(ctx, tx, receipt.PreregistrationID)
		if err != nil {
			return nil, nil, err
		}
		if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return nil, nil, err
		}
		installation, err := loadGuestInstallationTx(ctx, tx, stored, receipt)
		if err != nil {
			return nil, nil, err
		}
		var state string
		var valid bool
		var grantWire []byte
		if err = tx.QueryRowContext(ctx, `SELECT state,NOT(grant_record ? 'authority_kind'),grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, stored.pre.OriginalCreateGrantID).Scan(&state, &valid, &grantWire); err != nil || state != "confirmed" || !valid {
			return nil, nil, ErrCapacityConflict
		}
		var original capacityMutationRecord
		if json.Unmarshal(grantWire, &original) != nil || original.Settlement == nil || original.Grant.State != "confirmed" || original.Grant.Capability != b.EnsureCapability || original.Grant.CompensationOf != "" || original.Grant.GrantID != stored.pre.OriginalCreateGrantID || original.Grant.RequestSHA256 != stored.pre.OriginalCreateRequestSHA256 || slot.DesiredSpecSHA256 != stored.pre.OriginalCreateRequestSHA256 || !reflect.DeepEqual(original.Binding, b) || original.Generation != stored.pre.Generation || original.FencingToken != stored.pre.Fence || original.LeaseOwner != stored.pre.LeaseOwner || original.ExecutorID != stored.pre.ExecutorID || original.PolicyID.String() != stored.pre.PolicyID || original.PolicyChecksum != stored.pre.PolicyChecksum || original.WorkflowID.String() != stored.pre.WorkflowID || original.AttemptID != stored.witness.OriginalCreateAttemptID || capacity.GuestRetirementSHA(*original.Settlement) != stored.witness.OriginalCreateSettlementSHA256 {
			return nil, nil, ErrCapacityConflict
		}
		validateReturn := capacity.ValidateOriginalHetznerCreateReturn
		if receipt.Enrollment.Statement.Tuple.Provider == "aws" {
			validateReturn = capacity.ValidateOriginalAWSCreateReturn
		} else if receipt.Enrollment.Statement.Tuple.Provider != "hetzner" {
			return nil, nil, ErrCapacityConflict
		}
		returned, e := validateReturn(original.Binding, original.Grant, original.AttemptID, *original.Settlement, stored.pre.ReservedAt, stored.witness.ObservedAt)
		if e != nil || !returned.Equal(stored.witness.OriginalCreateReturnedAt) || !returned.Before(stored.pre.OriginalDeadline) {
			return nil, nil, ErrCapacityConflict
		}
		members = append(members, model.CapacityInstalledProvisionTimeoutMember{Slot: member.Slot, PreregistrationID: stored.pre.PreregistrationID, CreateGrantID: stored.pre.OriginalCreateGrantID, Tuple: receipt.Enrollment.Statement.Tuple, RequestSHA256: stored.pre.OriginalCreateRequestSHA256, PreregistrationSHA256: capacity.GuestRetirementSHA(stored.pre), WitnessSHA256: capacity.GuestRetirementSHA(stored.witness), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), InstallationSHA256: capacity.GuestRetirementSHA(installation), ReceiptSHA256: capacity.GuestRetirementSHA(receipt)})
		if stored.pre.Generation == old.Generation && stored.pre.Fence == old.FencingToken {
			if selected != nil || member.Slot != old.Decision.Units || stored.pre.LeaseOwner != old.LeaseOwner || stored.pre.ExecutorID != old.LeaseExecutorID || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum {
				return nil, nil, ErrCapacityConflict
			}
			copy := stored
			selected = &copy
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Slot < members[j].Slot })
	if len(members) != old.Decision.Units || selected == nil {
		return nil, nil, ErrCapacityConflict
	}
	for i, member := range members {
		if member.Slot != i+1 {
			return nil, nil, ErrCapacityConflict
		}
	}
	return members, selected, nil
}

// Called only under Enqueue's existing dimension lock and in that SAME
// transaction, before the pending-wake saturation test. Missing migration98
// remains ordinary old coalescing for historical schema fixtures.
func reconcileInstalledProvisionTimeoutTx(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob, next CapacityDispatchEnvelope) (bool, error) {
	if job.State != "unknown" || !installedProvisionTimeoutAuthorityEqual(job.CapacityDispatchEnvelope, next) || job.StartedAt == nil || job.ReturnedAt == nil || job.FinalizationAckAt != nil || job.LeaseExpiresAt == nil {
		return false, nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_dispatch_installed_provision_timeout_dispositions') IS NOT NULL`).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return false, err
	}
	var now time.Time
	var policy model.Manifest
	policy.ID, policy.Kind = job.Policy.ID, "capacity_policy"
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp(),namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, job.Policy.ID).Scan(&now, &policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec, &active); err != nil {
		return false, err
	}
	if !active || policy.Metadata.Namespace != job.Realm || policy.Metadata.Namespace != job.Policy.Namespace || policy.Metadata.Name != job.Policy.Name || policy.Version != job.Policy.Version || policy.Checksum != job.Policy.Checksum || now.Before(*job.LeaseExpiresAt) || job.ReturnedAt.Before(*job.LeaseExpiresAt) || checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return false, nil
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.Environment != job.Environment || p.Domain != job.Domain || p.Dimension != job.Dimension {
		return false, nil
	}
	var workflowRaw []byte
	var workflowChecksum, workflowNamespace, workflowName string
	var workflowVersion int
	var workflowActive bool
	if err = tx.QueryRowContext(ctx, `SELECT spec,checksum,active,namespace,name,version FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, job.Workflow.ID).Scan(&workflowRaw, &workflowChecksum, &workflowActive, &workflowNamespace, &workflowName, &workflowVersion); err != nil {
		return false, err
	}
	var workflowSpec model.WorkflowManifestSpec
	if !workflowActive || workflowNamespace != job.Workflow.Namespace || workflowName != job.Workflow.Name || workflowVersion != job.Workflow.Version || workflowChecksum != job.Workflow.Checksum || json.Unmarshal(workflowRaw, &workflowSpec) != nil || capacity.ValidateOriginalGuestReconcileGraph(workflowSpec, policy, p) != nil {
		return false, nil
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !installedProvisionTimeoutCandidate(old, policy, p, now) {
		return false, nil
	}
	if pending, err := countUnresolvedCapacityGrantsTx(ctx, tx, policy.Metadata.Namespace, p); err != nil || pending != 0 {
		return false, err
	}
	members, selected, err := installedProvisionTimeoutMembersTx(ctx, tx, policy, p, old)
	if err != nil {
		if errors.Is(err, ErrCapacityConflict) || errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	pre := selected.pre
	if pre.ReservedAt.Before(*job.StartedAt) || !pre.ReservedAt.Before(pre.OriginalDeadline) || pre.OriginalDeadline.After(*job.LeaseExpiresAt) || now.Before(pre.OriginalDeadline) {
		return false, nil
	}
	var dispatchWire, runWire, result, intentWire []byte
	var status, returnedStatus, returnError string
	var finished time.Time
	err = tx.QueryRowContext(ctx, `SELECT to_jsonb(j)::text,row_to_json(w)::text,w.result,w.status,COALESCE(j.return_status,''),COALESCE(j.return_error,''),w.finished_at,it.intent::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id JOIN public.capacity_intents it ON it.namespace=j.realm AND it.environment=j.environment AND it.domain=j.domain AND it.dimension=j.dimension WHERE j.id=$1 AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.metadata->>'capacity_dispatch_job_id'=j.id::text FOR SHARE OF w`, job.JobID).Scan(&dispatchWire, &runWire, &result, &status, &returnedStatus, &returnError, &finished, &intentWire)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status != "failed" || returnedStatus != "failed" || returnError != "capacity dispatch original deadline exceeded" || !finished.Equal(*job.ReturnedAt) || !installedProvisionTimeoutResult(result, pre, old, job.Workflow, workflowSpec) {
		return false, nil
	}
	var effects bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges WHERE policy_id=$1 AND generation=$2 AND fence=$3 AND lease_owner=$4 AND executor_id=$5) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=ANY($6::uuid[])) OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE namespace=$7 AND environment=$8 AND domain=$9 AND dimension=$10 AND generation=$2 AND NOT(grant_record ? 'authority_kind') AND id<>$11)`, policy.ID, old.Generation, old.FencingToken, old.LeaseOwner, old.LeaseExecutorID, installedProvisionTimeoutIDs(members), policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, pre.OriginalCreateGrantID).Scan(&effects)
	if err != nil {
		return false, err
	}
	if effects {
		return false, nil
	}
	memberWire, err := json.Marshal(members)
	if err != nil {
		return false, err
	}
	r := model.CapacityInstalledProvisionTimeoutDisposition{Schema: CapacityDispatchInstalledProvisionTimeoutSchema, ID: uuid.NewString(), JobID: job.JobID.String(), RunID: job.RunID.String(), PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, Generation: old.Generation, FencingToken: old.FencingToken, LeaseOwner: old.LeaseOwner, ExecutorID: old.LeaseExecutorID, PreregistrationID: pre.PreregistrationID, CreateGrantID: pre.OriginalCreateGrantID, OriginalDispatchSHA256: capacity.BusinessCreationSHA256(dispatchWire), OriginalRunSHA256: capacity.BusinessCreationSHA256(runWire), OriginalIntentSHA256: capacity.BusinessCreationSHA256(intentWire), MembersSHA256: capacity.BusinessCreationSHA256(memberWire), OriginalDeadline: *job.LeaseExpiresAt, OriginalIntentLeaseExpiresAt: *old.LeaseExpiresAt, OriginalReturnedAt: *job.ReturnedAt, RecordedAt: now.UTC(), Members: members}
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_installed_provision_timeout_dispositions(id,job_id,run_id,original_record,original_wire,original_dispatch_wire,original_run_wire,original_intent_wire,members_wire,recorded_at)VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10)`, r.ID, job.JobID, job.RunID, string(raw), raw, dispatchWire, runWire, intentWire, memberWire, r.RecordedAt)
	if err != nil {
		return false, err
	}
	changed, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state=$2,updated_at=$3 WHERE id=$1 AND state='unknown' AND finalization_ack_at IS NULL`, job.JobID, CapacityDispatchInstalledProvisionTimeoutState, r.RecordedAt)
	if err != nil {
		return false, err
	}
	count, err := changed.RowsAffected()
	if err != nil || count != 1 {
		return false, ErrCapacityDispatchClaim
	}
	return true, nil
}

func installedProvisionTimeoutAuthorityEqual(old, next CapacityDispatchEnvelope) bool {
	stableMetadata := func(m map[string]any) map[string]any {
		v := map[string]any{}
		for k, x := range m {
			if k != "scheduled_for" && k != "capacity_dispatch_job_id" {
				v[k] = x
			}
		}
		return v
	}
	return old.JobID != next.JobID && old.RunID != next.RunID && old.SourceTick != next.SourceTick && old.Protocol == next.Protocol && old.Realm == next.Realm && old.Environment == next.Environment && old.Domain == next.Domain && old.Dimension == next.Dimension && old.Policy == next.Policy && old.Workflow == next.Workflow && old.RBAC == next.RBAC && reflect.DeepEqual(old.AuthorizationPolicy, next.AuthorizationPolicy) && old.MachinePrincipalID == next.MachinePrincipalID && old.PrincipalSHA256 == next.PrincipalSHA256 && old.BindingSHA256 == next.BindingSHA256 && old.InputsSHA256 == next.InputsSHA256 && old.Metadata["triggered_by"] == "workflow_scheduler" && next.Metadata["triggered_by"] == "workflow_scheduler" && old.Metadata["capacity_dispatch_job_id"] == old.JobID.String() && next.Metadata["capacity_dispatch_job_id"] == next.JobID.String() && reflect.DeepEqual(stableMetadata(old.Metadata), stableMetadata(next.Metadata))
}

func installedProvisionTimeoutIDs(members []model.CapacityInstalledProvisionTimeoutMember) string {
	ids := "{"
	for i, m := range members {
		if i > 0 {
			ids += ","
		}
		ids += m.PreregistrationID
	}
	return ids + "}"
}

func ReadCapacityDispatchInstalledProvisionTimeoutDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (model.CapacityInstalledProvisionTimeoutDisposition, error) {
	if db == nil || jobID == uuid.Nil {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, ErrCapacityConflict
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, err
	}
	r, err := readInstalledProvisionTimeoutDisposition(ctx, tx, jobID)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}

func readInstalledProvisionTimeoutDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (model.CapacityInstalledProvisionTimeoutDisposition, error) {
	var r model.CapacityInstalledProvisionTimeoutDisposition
	var raw []byte
	var valid bool
	err := db.QueryRowContext(ctx, `SELECT d.original_wire,public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND (to_jsonb(j)-'state'-'updated_at')=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-'state'-'updated_at') AND w.status='failed' AND convert_from(d.original_run_wire,'UTF8')::jsonb=to_jsonb(w) FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(&raw, &valid)
	if err != nil {
		return r, err
	}
	if !valid || json.Unmarshal(raw, &r) != nil || r.Schema != CapacityDispatchInstalledProvisionTimeoutSchema || r.JobID != jobID.String() {
		return r, ErrCapacityConflict
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, raw) {
		return r, ErrCapacityConflict
	}
	return r, nil
}

// The old ACK-qualified query remains untouched. Only this separately linked
// terminal receipt can select a historically unknown provisioning original.
func installedProvisionTimeoutOriginTx(ctx context.Context, tx *sql.Tx, pre model.CapacityGuestOriginalProvisioningPreregistration, old model.CapacityIntent, workflow uuid.UUID) (model.CapacityInstalledProvisionTimeoutDisposition, []byte, []byte, error) {
	var job uuid.UUID
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.capacity_dispatch_installed_provision_timeout_dispositions') IS NOT NULL`).Scan(&exists); err != nil {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, nil, nil, err
	}
	if !exists {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, nil, nil, sql.ErrNoRows
	}
	var runWire, result []byte
	err := tx.QueryRowContext(ctx, `SELECT d.job_id,d.original_run_wire,w.result FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.original_record->>'preregistration_id'=$1 AND (d.original_record->>'generation')::bigint=$2 AND (d.original_record->>'fencing_token')::bigint=$3 AND j.envelope::jsonb#>>'{workflow,id}'=$4`, pre.PreregistrationID, pre.Generation, pre.Fence, workflow.String()).Scan(&job, &runWire, &result)
	if err != nil {
		return model.CapacityInstalledProvisionTimeoutDisposition{}, nil, nil, err
	}
	r, err := readInstalledProvisionTimeoutDisposition(ctx, tx, job)
	if err != nil {
		return r, nil, nil, err
	}
	if r.PolicyID != old.PolicyID.String() || r.PolicyChecksum != old.PolicyChecksum || r.Generation != old.Generation || r.PreregistrationID != pre.PreregistrationID || r.CreateGrantID != pre.OriginalCreateGrantID || r.OriginalRunSHA256 != capacity.BusinessCreationSHA256(runWire) {
		return r, nil, nil, ErrCapacityConflict
	}
	return r, runWire, result, nil
}

func installedProvisionTimeoutMembersEqual(r model.CapacityInstalledProvisionTimeoutDisposition, members []GuestNotifyFloorMember) bool {
	if len(r.Members) != len(members) {
		return false
	}
	for i, m := range members {
		if m.Slot != r.Members[i].Slot || m.PreregistrationID != r.Members[i].PreregistrationID {
			return false
		}
	}
	return true
}

func installedProvisionTimeoutRecordedMembersEqual(a, b []model.CapacityInstalledProvisionTimeoutMember) bool {
	return reflect.DeepEqual(a, b)
}
