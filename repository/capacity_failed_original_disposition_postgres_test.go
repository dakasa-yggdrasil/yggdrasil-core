package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type failedOriginalFixture struct {
	dispositionPGFixture
	jobID            uuid.UUID
	runID            uuid.UUID
	witness          model.CapacityGuestOriginalCreateWitness
	originalDispatch string
	originalRun      string
}

// DECLARED original histories in an explicitly isolated local database. No
// provider, Guest, native runtime or production authority is exercised here.
func failedOriginalPGFixture(t *testing.T, db *sql.DB) failedOriginalFixture {
	t.Helper()
	f := originalDispositionPGFixture(t, db)
	f.record.EventProvider = "hetzner"
	f.record.Binding.OriginalProviderSourceCommit = failedOriginalHetznerCreator
	f.record.Binding.EnsureCapability = "ensure_server"
	f.record.Binding.DestroyCapability = "delete_server"
	f.record.Binding.Slots[0].DesiredSpec.Capability = "ensure_server"
	requestSHA := originalDispositionJSONSHA(f.record.Binding.Slots[0].DesiredSpec)
	f.record.Binding.Slots[0].DesiredSpecSHA256 = requestSHA
	f.record.Grant.Capability, f.record.Grant.RequestSHA256 = "ensure_server", requestSHA
	f.pre.OriginalCreateRequestSHA256 = requestSHA
	f.record.Settlement.RequestSHA256 = requestSHA
	o := f.record.Settlement.OriginalProviderCreateReturn
	o.Schema, o.Provider, o.AdapterSourceCommit = "hetzner_original_create_return_v1", "hetzner", failedOriginalHetznerCreator
	o.RequestSHA256, o.ResourceID, o.ResponseStatus = requestSHA, "172099513", 201
	f.record.Settlement.ResourceID = o.ResourceID
	f.record.Settlement.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "server_disk", ID: o.ResourceID, RequiresAbsence: true}, {Kind: "volume", ID: "2012345", RequiresAbsence: true}, {Kind: "network", ID: "shared-original-network", RequiresAbsence: false}}
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		t.Fatal("fixture policy")
	}
	p.Profiles[0].Provider = "hetzner"
	policyRaw, _ := json.Marshal(p)
	f.policy.Spec = policyRaw
	start := f.pre.ReservedAt.Add(-time.Second)
	finish := f.pre.OriginalDeadline.Add(time.Second)
	jobID, runID := uuid.New(), uuid.New()
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: jobID, RunID: runID, Realm: f.policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: start.Format(time.RFC3339Nano), Policy: CapacityDispatchManifestPin{ID: f.policy.ID, Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name, Version: 1, Checksum: f.policy.Checksum}, Workflow: CapacityDispatchManifestPin{ID: f.record.WorkflowID, Namespace: f.policy.Metadata.Namespace, Name: "original", Version: 1, Checksum: f.pre.WorkflowChecksum}, RBAC: CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "isolated-rbac", Version: 1, Checksum: strings.Repeat("9", 64)}, MachinePrincipalID: "isolated-terminal-test", PrincipalSHA256: strings.Repeat("8", 64), BindingSHA256: strings.Repeat("7", 64), Inputs: map[string]any{}, Metadata: map[string]any{}}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Policy.Namespace, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, _ = CapacityDispatchEnvelopeHashes(e)
	envelope, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	result := capacityDispatchResponse(e, "failed")
	result.StartedAt, result.FinishedAt = start, finish
	result.Steps = []model.WorkflowRunStepResult{{ID: "plan-original-guest", Status: "succeeded", Metadata: map[string]any{"generation": f.record.Generation, "fencing_token": f.record.FencingToken, "lease_owner": f.record.LeaseOwner}}, {ID: f.pre.OriginalWorkflowStepID, Status: "failed", Error: "original Guest reconciliation held", Metadata: map[string]any{"original_guest_refusal_predicate": "original-guest-step-29"}}}
	resultRaw, _ := json.Marshal(result)
	inputsRaw, _ := json.Marshal(e.Inputs)
	metadataRaw, _ := json.Marshal(e.Metadata)
	observed := f.pre.ReservedAt.Add(3 * time.Second)
	w := model.CapacityGuestOriginalCreateWitness{Schema: capacity.GuestCreateWitnessSchema, BindingName: f.pre.BindingName, PreregistrationID: f.pre.PreregistrationID, PreregistrationNonceSHA256: f.pre.NonceSHA256, OriginalCreateGrantID: f.pre.OriginalCreateGrantID, OriginalCreateAttemptID: f.record.AttemptID, OriginalCreateRequestSHA256: requestSHA, OriginalCreateSettlementSHA256: capacity.GuestRetirementSHA(*f.record.Settlement), ProfileManifestSHA256: f.pre.ProfileManifestSHA256, BootstrapSHA256: f.binding.ProfileManifest.BootstrapSHA256, CoreSourceCommit: f.pre.CoreSourceCommit, OriginalDeadline: f.pre.OriginalDeadline, OriginalCreateReturnedAt: f.pre.ReservedAt.Add(2 * time.Second), ObservedAt: observed, Tuple: model.CapacityGuestNativeTuple{Provider: "hetzner", InstanceID: f.record.Binding.IntegrationInstanceID, InstanceChecksum: f.record.Binding.IntegrationChecksum, TypeID: f.record.Binding.IntegrationTypeID, TypeChecksum: f.record.Binding.IntegrationTypeChecksum, ScopeChecksum: f.record.Binding.ScopeChecksum, Profile: f.record.Binding.ProfileName, Slot: 1, ResourceID: o.ResourceID, CreatedAt: o.ResourceCreatedAt}}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: capacity.GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: o.ResourceID, ResourceCreatedAt: o.ResourceCreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "12345", Hostname: "isolated-original", ObservedAt: observed, AdapterSourceCommit: failedOriginalHetznerCreator}
	witnessRaw, _ := json.Marshal(w)
	grantRaw, _ := json.Marshal(f.record)
	preRaw, _ := json.Marshal(f.pre)
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`UPDATE public.manifests SET spec=$2::jsonb WHERE id=$1`, f.policy.ID, string(policyRaw))
	must(`UPDATE public.capacity_mutation_grants SET grant_record=$2::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, string(grantRaw))
	must(`UPDATE public.capacity_vm_provisioning_preregistrations SET preregistration_record=$2::jsonb,original_wire=$3 WHERE id=$1`, f.pre.PreregistrationID, string(preRaw), preRaw)
	must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_wire,witness_sha256,original_record,original_create_attempt_id,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, f.pre.PreregistrationID, witnessRaw, capacity.GuestRetirementSHA(w), string(witnessRaw), f.record.AttemptID, observed)
	// The owning insertWorkflowRun stores the selector and omits workflow_id.
	// Keep the actual historical NULL instead of improving the old row.
	must(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,result,error,inputs,metadata) VALUES($1,'failed',$2,'original',1,$3,$4,$5::jsonb,'original deadline elapsed',$6::jsonb,$7::jsonb)`, runID, f.policy.Metadata.Namespace, start, finish, string(resultRaw), string(inputsRaw), string(metadataRaw))
	// A DECLARED original tuple exercises the real database guards. This
	// fixture supplies no native execution and never fabricates a late ACK.
	must(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed','original deadline elapsed','original deadline elapsed')`, jobID, runID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.pre.OriginalDeadline, start, finish)
	var rawGrant, rawDispatch, rawRun string
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&rawGrant); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, jobID).Scan(&rawDispatch); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, runID).Scan(&rawRun); err != nil {
		t.Fatal(err)
	}
	f.rawGrant = rawGrant
	return failedOriginalFixture{f, jobID, runID, w, rawDispatch, rawRun}
}

func (f failedOriginalFixture) absent(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	o := f.native(t, c)
	o.Provider, o.ResourceState, o.InventoryBasis = "hetzner", "absent", "original_accepted_auxiliary_inventory_v1"
	o.NativeReads[0].ResourceKind = "server"
	for i := range o.NativeReads {
		o.NativeReads[i].Status = 404
	}
	return o
}

func TestFailedOriginalDispositionPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := failedOriginalPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuer := "collaborator:" + uuid.NewString()
	owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), issuer)
	if err != nil {
		t.Fatal("Begin", err)
	}
	c := owner.Candidate()
	c.Request.ExpectedResourceID = "forged"
	if owner.Candidate().Request.ExpectedResourceID == "forged" {
		t.Fatal("candidate aliases authority")
	}
	observation := f.absent(t, owner.Candidate())
	result, err := f.store.CompleteFailedOriginalDisposition(ctx, owner, observation)
	if err != nil {
		t.Fatal("Complete", err)
	}
	read, err := f.store.ReadFailedOriginalDisposition(ctx, result.GrantID)
	if err != nil || originalDispositionJSONSHA(read) != originalDispositionJSONSHA(result) {
		t.Fatal("lost response read", err)
	}
	var grant, run, witness, state string
	var ack sql.NullTime
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, result.GrantID).Scan(&grant); err != nil || grant != f.rawGrant {
		t.Fatal("accepted original changed", err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&run); err != nil || run != f.originalRun {
		t.Fatal("failed original run rewritten", err)
	}
	if err = db.QueryRow(`SELECT witness_sha256 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, f.pre.PreregistrationID).Scan(&witness); err != nil || witness != capacity.GuestRetirementSHA(f.witness) {
		t.Fatal("witness rewritten", err)
	}
	if err = db.QueryRow(`SELECT state,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); err != nil || state != "failed_disposed" || ack.Valid {
		t.Fatal("unknown ACK fabricated", err)
	}
	if !result.OriginalAcceptedUnchanged || !result.OriginalWitnessPreserved || !result.OriginalUnknownACKPreserved || result.HistoricalWriterStartState != "unknown" || result.ServingOrBusinessOrSavingsAuthority {
		t.Fatal("terminal failure relabelled as success")
	}
	if _, err = f.store.CompleteFailedOriginalDisposition(ctx, owner, observation); err == nil {
		t.Fatal("owner replay")
	}
	if _, err = f.store.BeginFailedOriginalDisposition(ctx, result.GrantID, f.jobID.String(), issuer); err == nil {
		t.Fatal("closed original reopened")
	}
	var policy model.CapacityPolicySpec
	_ = json.Unmarshal(f.policy.Spec, &policy)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, test := range []struct {
		gen, fence int64
		allowed    bool
	}{{1, 3, false}, {2, 2, false}, {2, 3, true}} {
		err = requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, policy, f.record.Binding, 1, test.gen, test.fence)
		if (err == nil) != test.allowed {
			t.Fatal("successor reused old generation/fence", test, err)
		}
	}
}

func TestFailedOriginalDispositionPostgresRechecks(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"enrollment", "installation", "running_run", "live_lease", "witness_changed", "native_present", "missing_auxiliary", "late_observation", "wrong_job"} {
		t.Run(name, func(t *testing.T) {
			f := failedOriginalPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			job := f.jobID.String()
			if name == "wrong_job" {
				job = uuid.NewString()
			}
			owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, job, "collaborator:"+uuid.NewString())
			if name == "wrong_job" {
				if err == nil {
					t.Fatal("foreign job admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("Begin", err)
			}
			o := f.absent(t, owner.Candidate())
			var query string
			switch name {
			case "enrollment":
				query = `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id) VALUES($1)`
			case "installation":
				query = `INSERT INTO public.capacity_guest_original_installations(preregistration_id) VALUES($1)`
			case "witness_changed":
				query = `UPDATE public.capacity_guest_original_create_witnesses SET witness_sha256=repeat('f',64) WHERE preregistration_id=$1`
			case "running_run":
				if _, err = db.Exec(`UPDATE public.workflow_runs SET status='running' WHERE id=$1`, f.runID); err != nil {
					t.Fatal(err)
				}
			case "live_lease": // The immutable original lease cannot be renewed; a live conflicting run is held instead.
				if _, err = db.Exec(`INSERT INTO public.workflow_runs(id,workflow_id,status) VALUES($1,$2,'running')`, uuid.New(), f.record.WorkflowID); err != nil {
					t.Fatal(err)
				}
			case "native_present":
				o.ResourceState = "running"
				o.ResourceAbsenceComplete = false
			case "missing_auxiliary":
				o.AuxiliaryResources = o.AuxiliaryResources[:len(o.AuxiliaryResources)-1]
			case "late_observation":
				o.ObservedAt = time.Now().Add(-time.Hour)
			}
			if query != "" {
				if _, err = db.Exec(query, f.pre.PreregistrationID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = f.store.CompleteFailedOriginalDisposition(ctx, owner, o); err == nil {
				t.Fatal("open/changed boundary accepted")
			}
			var n int
			if err = db.QueryRow(`SELECT count(*) FROM public.capacity_failed_original_dispositions WHERE grant_id=$1`, f.pre.OriginalCreateGrantID).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial terminal record survived", err)
			}
		})
	}
}

func TestFailedOriginalDispositionNullableWorkflowIdentity(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"original_null", "matching_nonnull", "foreign_nonnull", "missing_result_workflow", "wrong_result_id", "wrong_result_namespace", "wrong_result_name", "wrong_result_version", "nullable_live_workflow"} {
		t.Run(name, func(t *testing.T) {
			f := failedOriginalPGFixture(t, db)
			var query string
			var args []any
			switch name {
			case "matching_nonnull":
				query, args = `UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`, []any{f.runID, f.record.WorkflowID}
			case "foreign_nonnull":
				query, args = `UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`, []any{f.runID, uuid.New()}
			case "missing_result_workflow":
				query, args = `UPDATE public.workflow_runs SET result=result-'workflow' WHERE id=$1`, []any{f.runID}
			case "wrong_result_id":
				query, args = `UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,id}',to_jsonb($2::text)) WHERE id=$1`, []any{f.runID, uuid.NewString()}
			case "wrong_result_namespace", "wrong_result_name":
				field := strings.TrimPrefix(name, "wrong_result_")
				query, args = `UPDATE public.workflow_runs SET result=jsonb_set(result,ARRAY['workflow',$2::text],to_jsonb('foreign'::text)) WHERE id=$1`, []any{f.runID, field}
			case "wrong_result_version":
				query, args = `UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,version}','2'::jsonb) WHERE id=$1`, []any{f.runID}
			case "nullable_live_workflow":
				query, args = `INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version) SELECT $2,'running',workflow_namespace,workflow_name,workflow_version FROM public.workflow_runs WHERE id=$1`, []any{f.runID, uuid.New()}
			}
			if query != "" {
				if _, err := db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
			positive := name == "original_null" || name == "matching_nonnull"
			if !positive {
				if err == nil {
					t.Fatal("nullable identity widened to a foreign or active original")
				}
				return
			}
			if err != nil {
				t.Fatal("legitimate nullable identity refused", err)
			}
			if _, err = f.store.CompleteFailedOriginalDisposition(ctx, owner, f.absent(t, owner.Candidate())); err != nil {
				t.Fatal("legitimate nullable identity did not close", err)
			}
			var column sql.NullString
			if err = db.QueryRow(`SELECT workflow_id::text FROM public.workflow_runs WHERE id=$1`, f.runID).Scan(&column); err != nil || (name == "original_null" && column.Valid) || (name == "matching_nonnull" && (!column.Valid || column.String != f.record.WorkflowID.String())) {
				t.Fatal("historical workflow_id changed", err)
			}
		})
	}
}
