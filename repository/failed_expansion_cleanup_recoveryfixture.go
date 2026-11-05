//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// These explicitly declared disposable PostgreSQL operands are neither live
// provider execution nor Guest/native/business evidence. Every production FK,
// trigger, source graph and claim/lease operation remains enabled.
type FailedExpansionCleanupRecoveryFixture struct {
	DB                   *sql.DB
	Policy, Workflow     model.Manifest
	Spec                 model.CapacityPolicySpec
	Intent               model.CapacityIntent
	AdmissionSourceStore CapacityStore
	GrantID, JobID       string
	Pre                  model.CapacityGuestOriginalProvisioningPreregistration
	private              *failedServingFixture
	t                    *testing.T
	store                CapacityStore
	runStarted           bool
	rbac                 CapacityDispatchManifestPin
}

func NewFailedExpansionCleanupRecoveryFixture(tb testing.TB) *FailedExpansionCleanupRecoveryFixture {
	t, ok := tb.(*testing.T)
	if !ok {
		tb.Fatal("concrete disposable test required")
	}
	t.Helper()
	// The original93 survivor fixture is preserved; the NEW cleanup integration
	// explicitly applies94 afterwards instead of relabelling historical evidence.
	base := newFailedServingFixtureHistory(t, "aws", true)
	if err := goose.UpTo(base.db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 94); err != nil {
		t.Fatal("new explicit schema94", err)
	}
	var version int64
	if err := base.db.QueryRow(`SELECT max(version_id) FROM public.goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 94 {
		t.Fatal("exact94 required", version, err)
	}
	f := &FailedExpansionCleanupRecoveryFixture{DB: base.db, Policy: base.policy, Workflow: base.workflow, Spec: base.p, private: base, t: t, store: base.store}
	f.AdmissionSourceStore = base.store
	b := base.p.MutationBindings[0]
	if len(b.Slots) < 2 || b.Slots[1].Slot != 2 || b.Slots[1].DesiredSpec == nil || b.Slots[1].Slot <= b.ProtectedSlots {
		t.Fatal("declared unprotected tail2 required")
	}
	pre := base.pre
	pre.PreregistrationID = uuid.NewString()
	pre.OriginalCreateGrantID = uuid.NewString()
	pre.Slot = 2
	pre.BindingName = base.p.GuestRetirementBinding.Members[1].Name
	pre.NonceSHA256 = capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
	pre.OriginalCreateRequestSHA256 = b.Slots[1].DesiredSpecSHA256
	pre.Generation++
	pre.Fence++
	pre.LeaseOwner = uuid.NewString()
	pre.ExecutorID = uuid.NewString()
	f.Pre = pre
	f.GrantID = pre.OriginalCreateGrantID
	attempt := uuid.NewString()
	resource := "i-0123456789abcdef2"
	birth := pre.ReservedAt.Add(time.Second).UTC().Format(time.RFC3339Nano)
	sdk := &model.CapacityOriginalProviderCreateReturn{Schema: "aws_original_run_instances_return_v1", Provider: "aws", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: f.GrantID, AttemptID: attempt, RequestSHA256: pre.OriginalCreateRequestSHA256, ResourceID: resource, ResourceCreatedAt: birth, ActionID: "declared-aws-accepted-request", NextActionIDs: []string{}, CalledAt: pre.ReservedAt.Format(time.RFC3339Nano), ReturnedAt: pre.ReservedAt.Add(2 * time.Second).Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 200, ResponseBodySHA256: strings.Repeat("a", 64), ResponseBytes: 219}
	grant := model.CapacityMutationGrant{GrantID: f.GrantID, BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, ExpiresAt: pre.OriginalDeadline, State: "settled"}
	r := capacityMutationRecord{Grant: grant, Binding: b, PolicyID: f.Policy.ID, PolicyChecksum: f.Policy.Checksum, WorkflowID: f.Workflow.ID, Generation: pre.Generation, FencingToken: pre.Fence, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, CreatedAt: pre.ReservedAt, AttemptID: attempt, Settlement: &model.CapacityMutationSettleRequest{GrantID: f.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: resource, ResourceCreatedAt: birth, ActionID: sdk.ActionID, NextActionIDs: []string{}, OriginalProviderCreateReturn: sdk, ObservedAt: sdk.ReturnedAt}, EventProvider: "aws", EventResource: "ec2_instance"}
	raw := failedServingWire(t, r)
	base.exec(t, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,2,'settled',$10::jsonb,$11)`, f.GrantID, f.Policy.Metadata.Namespace, f.Spec.Environment, f.Spec.Domain, f.Spec.Dimension, pre.Generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, string(raw), grant.ExpiresAt)
	preRaw := failedServingWire(t, pre)
	base.exec(t, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, f.GrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(preRaw), pre.OriginalDeadline, pre.ReservedAt, preRaw, failedServingWire(t, *f.Spec.GuestRetirementBinding))
	intent := base.intent
	intent.Generation = pre.Generation
	intent.FencingToken = pre.Fence
	intent.Phase = "preparing"
	intent.LeaseOwner = pre.LeaseOwner
	intent.LeaseExecutorID = pre.ExecutorID
	intent.LeaseExpiresAt = &pre.OriginalDeadline
	intent.BaselineSnapshot = intent.Assessment.Snapshot
	intent.Decision.Action = "prepare"
	intent.Decision.Reason = "scale_up"
	intent.Decision.Units = 2
	intent.Decision.ExecutionPermitted = true
	intent.UpdatedAt = pre.ReservedAt
	base.exec(t, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, f.Policy.Metadata.Namespace, string(failedServingWire(t, intent)))
	f.Intent = intent
	// The failed original ACK is declared BEFORE its first insert, with distinct
	// dispatch/capacity fences and exact actual run-return ordering, like production.
	start := pre.ReservedAt.Add(-time.Second)
	finish := pre.ReservedAt.Add(3 * time.Second)
	ack := finish.Add(time.Millisecond)
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.Policy.Metadata.Namespace, Environment: f.Spec.Environment, Domain: f.Spec.Domain, Dimension: f.Spec.Dimension, SourceTick: start.Truncate(time.Second).Format(time.RFC3339), Policy: pin(f.Policy), Workflow: pin(f.Workflow), RBAC: CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.Policy.Metadata.Namespace, Name: "failed-serving-unit-rbac", Version: 1, Checksum: strings.Repeat("d", 64)}, MachinePrincipalID: "capacity-controller", PrincipalSHA256: strings.Repeat("e", 64), BindingSHA256: strings.Repeat("f", 64)}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.Policy.Metadata.Namespace, "name": f.Policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.Workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"steps": []any{map[string]any{"status": "succeeded", "metadata": map[string]any{"generation": pre.Generation, "fencing_token": pre.Fence, "lease_owner": pre.LeaseOwner}}, map[string]any{"status": "failed", "metadata": map[string]any{"original_guest_refusal_predicate": "original-guest-step-25"}}}}
	base.exec(t, `INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,result,error,inputs,metadata) VALUES($1,'failed',$2,$3,$4,$5,$6,$7::jsonb,'declared unavailable original Describe after accepted SDK',$8::jsonb,$9::jsonb)`, e.RunID, f.Workflow.Metadata.Namespace, f.Workflow.Metadata.Name, f.Workflow.Version, start, finish, string(failedServingWire(t, result)), string(failedServingWire(t, e.Inputs)), string(failedServingWire(t, e.Metadata)))
	envelope := failedServingWire(t, e)
	base.exec(t, `INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_ack_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'returned',$11,1,$12,$13,$14,'failed','declared unavailable original Describe',$15)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, envelope, capacityDispatchSHA(envelope), uuid.New(), pre.OriginalDeadline, start, finish, ack)
	f.JobID = e.JobID.String()
	return f
}

func (f *FailedExpansionCleanupRecoveryFixture) step(operation string) model.WorkflowStepSpec {
	for _, s := range f.private.steps {
		if s.Use.Operation == operation {
			return s
		}
	}
	f.t.Fatal("registered step absent", operation)
	return model.WorkflowStepSpec{}
}
func (f *FailedExpansionCleanupRecoveryFixture) PlanStore() CapacityStore {
	if !f.runStarted {
		f.startSuccessorDispatch()
		f.runStarted = true
	}
	return f.store.WithOriginalGuestReconcile(f.Workflow, f.step(capacity.PlanOriginalGuestOperation), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
}
func (f *FailedExpansionCleanupRecoveryFixture) RetirementStore() CapacityStore {
	return f.store.WithOriginalGuestNotifyCanary(f.step(capacity.RetireOriginalGuestOperation), capacity.CurrentGuestCoreSource())
}
func (f *FailedExpansionCleanupRecoveryFixture) FinishStore() CapacityStore {
	return f.store.WithOriginalGuestNotifyCanary(f.step("capacity.finish_original_guest_retirement"), capacity.CurrentGuestCoreSource())
}
func (f *FailedExpansionCleanupRecoveryFixture) startSuccessorDispatch() {
	t := f.t
	pin := func(m model.Manifest) CapacityDispatchManifestPin {
		return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
	}
	rbac := CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.Policy.Metadata.Namespace, Name: "failed-serving-unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-cleanup-rbac"))}
	if f.rbac.ID != uuid.Nil {
		rbac = f.rbac
	} else {
		f.private.exec(t, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)`, rbac.ID, rbac.Namespace, rbac.Name, rbac.Checksum)
		f.rbac = rbac
	}
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: f.Policy.Metadata.Namespace, Environment: f.Spec.Environment, Domain: f.Spec.Domain, Dimension: f.Spec.Dimension, SourceTick: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Policy: pin(f.Policy), Workflow: pin(f.Workflow), RBAC: rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("declared-cleanup-principal")), BindingSHA256: capacityDispatchSHA([]byte("declared-cleanup-binding"))}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": f.Policy.Metadata.Namespace, "name": f.Policy.Metadata.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": f.Workflow.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
	var err error
	e.InputsSHA256, e.MetadataSHA256, err = CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, _, err = EnqueueCapacityDispatch(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	j, err := ClaimCapacityDispatch(context.Background(), f.DB, e.Realm, e.Environment, uuid.New(), time.Duration(f.Spec.LeaseSeconds)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = StartCapacityDispatch(context.Background(), f.DB, j); err != nil {
		t.Fatal(err)
	}
	f.store.OriginalRunID = e.RunID
}
