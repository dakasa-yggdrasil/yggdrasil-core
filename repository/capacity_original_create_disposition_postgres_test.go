package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Deliberately does not read DB_URL: these tests may only touch an explicitly
// named isolated Unix-socket database. They create no provider/API authority.
func originalDispositionPG(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ORIGINAL_CREATE_DISPOSITION_PG_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_ORIGINAL_CREATE_DISPOSITION_PG") == "true" {
			t.Fatal("isolated disposition PG DSN required")
		}
		t.Skip("explicit isolated disposition PG only")
	}
	if !strings.Contains(dsn, "host=/") || !strings.Contains(dsn, "dbname=original_disposition_test_") {
		t.Fatal("refuse non-isolated/network database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { _ = db.Close() })
	var name string
	var local bool
	if err = db.QueryRow(`SELECT current_database(),inet_server_addr() IS NULL`).Scan(&name, &local); err != nil || !local || !strings.HasPrefix(name, "original_disposition_test_") {
		t.Fatal("isolated DB identity", name, local, err)
	}
	// An empty dedicated test DB receives only the schema necessary to exercise
	// real Begin/Complete and migration71. Ordinary CI DBs are not modified.
	var exists bool
	if err = db.QueryRow(`SELECT to_regclass('public.capacity_original_create_dispositions') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		ddl := `CREATE TABLE public.manifests(id uuid PRIMARY KEY,kind text,namespace text,name text,version int NOT NULL DEFAULT 1,checksum text,spec jsonb,active boolean);
 CREATE TABLE public.capacity_mutation_grants(id uuid PRIMARY KEY,namespace text,environment text,domain text,dimension text,generation bigint,integration_instance_id uuid,scope_checksum text,profile_name text,slot int,state text,grant_record jsonb,expires_at timestamptz,updated_at timestamptz DEFAULT clock_timestamp());
 CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot) WHERE state IN('issued','redeemed','settled');
 CREATE TABLE public.capacity_vm_provisioning_preregistrations(id uuid PRIMARY KEY,create_grant_id uuid UNIQUE REFERENCES public.capacity_mutation_grants(id),nonce_sha256 text,profile_manifest_sha256 text,preregistration_record jsonb,original_deadline timestamptz,created_at timestamptz,original_wire bytea,binding_wire bytea);
 CREATE TABLE public.capacity_guest_original_create_witnesses(preregistration_id uuid PRIMARY KEY REFERENCES public.capacity_vm_provisioning_preregistrations(id), original_wire bytea,witness_sha256 text,original_record jsonb,original_create_attempt_id uuid,recorded_at timestamptz);
 CREATE TABLE public.capacity_vm_original_enrollments(preregistration_id uuid PRIMARY KEY REFERENCES public.capacity_vm_provisioning_preregistrations(id));
 CREATE TABLE public.capacity_guest_original_installations(preregistration_id uuid PRIMARY KEY REFERENCES public.capacity_vm_provisioning_preregistrations(id));
 CREATE TABLE public.capacity_factory_original_grant_bindings(grant_id uuid PRIMARY KEY);
 CREATE TABLE public.workflow_runs(id uuid PRIMARY KEY,workflow_id uuid,status text,workflow_namespace text,workflow_name text,workflow_version int,started_at timestamptz,finished_at timestamptz,result jsonb,error text,inputs jsonb,metadata jsonb,created_at timestamptz DEFAULT clock_timestamp(),updated_at timestamptz DEFAULT clock_timestamp());

 CREATE TABLE public.capacity_vm_retirement_intents(id uuid PRIMARY KEY,preregistration_id uuid);
 CREATE TABLE public.capacity_resource_slots(integration_instance_id uuid,scope_checksum text,profile_name text,slot int,namespace text,environment text,domain text,dimension text,resource_id text,slot_record jsonb,revision bigint DEFAULT 1,updated_at timestamptz DEFAULT clock_timestamp(),PRIMARY KEY(integration_instance_id,scope_checksum,profile_name,slot));
 CREATE TABLE public.capacity_intents(namespace text,environment text,domain text,dimension text,intent jsonb,updated_at timestamptz,PRIMARY KEY(namespace,environment,domain,dimension));
 CREATE TABLE public.capacity_intent_events(id bigserial PRIMARY KEY,namespace text,environment text,domain text,dimension text,generation bigint,fencing_token bigint,phase text,receipt_ref text,recorded_at timestamptz);`
		if _, err = db.Exec(ddl); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "00071_original_create_dispositions.sql"))
		if err != nil {
			t.Fatal(err)
		}
		up := strings.Split(string(raw), "-- +goose Down")[0]
		if _, err = db.Exec(up); err != nil {
			t.Fatal("migration71", err)
		}
		for _, name := range []string{"00061_capacity_dispatch_jobs.sql", "00072_capacity_dispatch_prestart_rejection.sql", "00073_failed_original_guest_dispositions.sql", "00074_native_authorization_denied_dispositions.sql"} {
			wire, readErr := os.ReadFile(filepath.Join("..", "db", "migrations", name))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, execErr := db.Exec(strings.Split(string(wire), "-- +goose Down")[0]); execErr != nil {
				t.Fatal(name, execErr)
			}
		}
	}
	var deniedExists bool
	if err = db.QueryRow(`SELECT to_regclass('public.capacity_native_denied_dispositions') IS NOT NULL`).Scan(&deniedExists); err != nil {
		t.Fatal(err)
	}
	if !deniedExists {
		wire, e := os.ReadFile(filepath.Join("..", "db", "migrations", "00074_native_authorization_denied_dispositions.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(strings.Split(string(wire), "-- +goose Down")[0]); e != nil {
			t.Fatal("migration74", e)
		}
	}
	return db
}

type dispositionPGFixture struct {
	db       *sql.DB
	store    CapacityStore
	record   capacityMutationRecord
	pre      model.CapacityGuestOriginalProvisioningPreregistration
	binding  model.CapacityGuestRetirementBinding
	policy   model.Manifest
	intent   model.CapacityIntent
	rawGrant string
	ctx      context.Context
}

func originalDispositionPGFixture(t *testing.T, db *sql.DB) dispositionPGFixture {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	grantID, preID, policyID, wfID, instance, attempt := uuid.NewString(), uuid.NewString(), uuid.New(), uuid.New(), uuid.NewString(), uuid.NewString()
	ns := "disposition-" + uuid.NewString()
	profile := model.CapacityGuestProtectedProfileManifest{Schema: "original_guest_protected_profile_v1", Profile: "original", MutationBinding: "original", BootstrapSHA256: strings.Repeat("a", 64), OriginalProvisioningBudgetSeconds: 60, OriginalProvisioningStepID: "provision-original", Writers: []model.CapacityGuestProtectedWriterDefinition{}}
	desired := model.CapacityMutationSpecV1{SchemaVersion: "1", Capability: "ensure_ec2_instance", IntegrationInstanceID: instance, ScopeChecksum: strings.Repeat("b", 64), ProfileName: "original", Slot: 1, BootstrapSHA256: profile.BootstrapSHA256}
	requestSHA := originalDispositionJSONSHA(desired)
	binding := model.CapacityMutationBinding{OriginalProviderSourceCommit: strings.Repeat("c", 40), Name: "original", IntegrationInstanceID: instance, ScopeChecksum: desired.ScopeChecksum, ProfileName: "original", EnsureCapability: "ensure_ec2_instance", DestroyCapability: "terminate_ec2_instance", ProtectedSlots: 2, MaxSlots: 2, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpecSHA256: requestSHA, DesiredSpec: &desired}}}
	guest := model.CapacityGuestRetirementBinding{MutationBindingName: binding.Name, CoreAuthoritySourceCommit: strings.Repeat("d", 40), ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), Members: []model.CapacityGuestRetirementMemberBinding{{Name: "original-member", Slot: 1}}}
	p := model.CapacityPolicySpec{Environment: "isolated", Domain: "notify", Dimension: "original", Floor: 2, Ceiling: 2, MaxEvidenceAgeSeconds: 30, GuestRetirementBinding: &guest, Profiles: []model.CapacityProfile{{Name: "original", Provider: "aws"}}}
	policyRaw, _ := json.Marshal(p)
	policy := model.Manifest{ID: policyID, Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: ns, Name: "original"}, Checksum: strings.Repeat("e", 64), Spec: policyRaw}
	wfSHA := strings.Repeat("f", 64)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: preID, BindingName: "original-member", OriginalCreateGrantID: grantID, OriginalCreateRequestSHA256: requestSHA, NonceSHA256: originalDispositionDigest([]byte(preID)), ProfileManifestSHA256: guest.ProfileManifestSHA256, PolicyID: policyID.String(), PolicyChecksum: policy.Checksum, WorkflowID: wfID.String(), WorkflowChecksum: wfSHA, OriginalWorkflowStepID: profile.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 60, OriginalWorkflowContextDeadline: at.Add(time.Minute), CoreSourceCommit: guest.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), Slot: 1, OriginalDeadline: at.Add(time.Minute), ReservedAt: at}
	created := at.Add(time.Second).Format(time.RFC3339Nano)
	g := model.CapacityMutationGrant{GrantID: grantID, BindingName: binding.Name, IntegrationInstanceID: instance, ScopeChecksum: binding.ScopeChecksum, ProfileName: binding.ProfileName, Slot: 1, Capability: binding.EnsureCapability, RequestSHA256: requestSHA, State: "settled", ExpiresAt: pre.OriginalDeadline}
	original := &model.CapacityOriginalProviderCreateReturn{Schema: "aws_original_run_instances_return_v1", Provider: "aws", AdapterSourceCommit: binding.OriginalProviderSourceCommit, GrantID: grantID, AttemptID: attempt, RequestSHA256: requestSHA, ResourceID: "i-" + preID, ResourceCreatedAt: created, ActionID: "request-" + attempt, NextActionIDs: []string{}, CalledAt: at.Format(time.RFC3339Nano), ReturnedAt: at.Add(2 * time.Second).Format(time.RFC3339Nano), ContextDeadline: pre.OriginalDeadline.Format(time.RFC3339Nano), ResponseStatus: 200, ResponseBodySHA256: strings.Repeat("1", 64), ResponseBytes: 100}
	settlement := &model.CapacityMutationSettleRequest{OriginalProviderCreateReturn: original, GrantID: grantID, AttemptID: attempt, RequestSHA256: requestSHA, Outcome: "accepted", TransportCompleted: true, ResourceID: original.ResourceID, ResourceCreatedAt: created, ActionID: original.ActionID, NextActionIDs: []string{}, ObservedAt: at.Add(2 * time.Second).Format(time.RFC3339Nano), AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-" + preID, RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-" + preID, RequiresAbsence: true}}, AuxiliaryInventoryComplete: true}
	record := capacityMutationRecord{Grant: g, Binding: binding, PolicyID: policyID, PolicyChecksum: policy.Checksum, WorkflowID: wfID, Generation: 1, FencingToken: 1, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, CreatedAt: at, AttemptID: attempt, Settlement: settlement, EventProvider: "aws"}
	snapshot := model.CapacitySnapshot{Units: 0, Profile: "original", ObservedAt: at}
	intent := model.CapacityIntent{Namespace: ns, PolicyName: "original", PolicyID: policyID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 1, FencingToken: 1, Phase: "preparing", LeaseOwner: pre.LeaseOwner, LeaseExecutorID: pre.ExecutorID, LeaseExpiresAt: &pre.OriginalDeadline, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, Decision: model.CapacityDecision{Reason: "protected_floor_recovery", Profile: "original", Units: 2, Floor: 2, ExecutionPermitted: true}}
	must := func(q string, a ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO public.manifests(id,kind,namespace,name,checksum,spec,active) VALUES($1,'capacity_policy',$2,'original',$3,$4::jsonb,false)`, policyID, ns, policy.Checksum, string(policyRaw))
	must(`INSERT INTO public.manifests(id,kind,namespace,name,checksum,spec,active) VALUES($1,'workflow',$2,'original',$3,'{}'::jsonb,true)`, wfID, ns, wfSHA)
	raw, _ := json.Marshal(record)
	must(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,1,'settled',$9::jsonb,$10)`, grantID, ns, p.Environment, p.Domain, p.Dimension, instance, binding.ScopeChecksum, binding.ProfileName, string(raw), g.ExpiresAt)
	preRaw, _ := json.Marshal(pre)
	bindingRaw, _ := json.Marshal(guest)
	must(`INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, preID, grantID, pre.NonceSHA256, pre.ProfileManifestSHA256, string(preRaw), pre.OriginalDeadline, pre.ReservedAt, preRaw, bindingRaw)
	intentRaw, _ := json.Marshal(intent)
	must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, ns, p.Environment, p.Domain, p.Dimension, string(intentRaw), at)
	var rawGrant string
	if err := db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, grantID).Scan(&rawGrant); err != nil {
		t.Fatal(err)
	}
	return dispositionPGFixture{db: db, store: CapacityStore{DB: db}, record: record, pre: pre, binding: guest, policy: policy, intent: intent, rawGrant: rawGrant, ctx: ctx}
}
func (f dispositionPGFixture) native(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	_, o, _ := originalDispositionObservationFixture(t)
	now := time.Now().UTC()
	o.ObservationStartedAt = now
	o.ObservedAt = now.Add(30 * time.Millisecond)
	r := c.Request
	o.Profile = r.Profile
	o.Slot = r.Slot
	o.GrantID = r.GrantID
	o.AttemptID = r.AttemptID
	o.RequestSHA256 = r.RequestSHA256
	o.ResourceID = r.ExpectedResourceID
	o.ResourceCreatedAt = r.ExpectedResourceCreatedAt
	o.OriginalAdapterSourceCommit = r.OriginalAdapterSourceCommit
	o.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{}
	o.NativeReads = nil
	list := []struct{ kind, id string }{{"aws_ec2_instance", r.ExpectedResourceID}}
	for _, a := range r.AuxiliaryResources {
		if a.RequiresAbsence {
			list = append(list, struct{ kind, id string }{a.Kind, a.ID})
		}
	}
	for i, a := range list {
		raw := []byte("<original-closed-native-read/>")
		called := now.Add(time.Duration(i) * 5 * time.Millisecond)
		returned := called.Add(time.Millisecond)
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: "DescribeExactOriginal", ResourceKind: a.kind, ResourceID: a.id, Status: 200, ResponseSHA256: originalDispositionDigest(raw), ResponseBytes: int64(len(raw)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(raw), ResponseRepresentation: "raw_http_body_v1", CalledAt: called, ReturnedAt: returned})
		if i > 0 {
			o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: a.kind, ID: a.id, Absent: true, ObservedAt: returned.Format(time.RFC3339Nano)})
		}
	}
	return o
}
func TestOriginalDispositionPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := originalDispositionPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-test-operator")
	if err != nil {
		t.Fatal("Begin", err)
	}
	candidate := owner.Candidate()
	candidate.Request.ExpectedResourceID = "forged-copy"
	if owner.Candidate().Request.ExpectedResourceID == candidate.Request.ExpectedResourceID {
		t.Fatal("private candidate aliased")
	}
	if _, err = db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,2,integration_instance_id,scope_checksum,profile_name,slot,'issued','{}',clock_timestamp()+interval '1 minute' FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID, uuid.NewString()); err == nil {
		t.Fatal("undisposed original slot was reusable")
	}
	result, err := f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate()))
	if err != nil {
		t.Fatal("Complete", err)
	}
	read, err := f.store.ReadOriginalCreateDisposition(ctx, result.GrantID)
	if err != nil || originalDispositionJSONSHA(read) != originalDispositionJSONSHA(result) {
		t.Fatal("lost-ack readonly", err)
	}
	var state, raw, pointer string
	if err = db.QueryRow(`SELECT state,grant_record::text,original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1`, result.GrantID).Scan(&state, &raw, &pointer); err != nil || state != "settled" || raw != f.rawGrant || pointer != result.ID {
		t.Fatal("owning original changed", err)
	}
	var intentRaw []byte
	if err = db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&intentRaw); err != nil {
		t.Fatal(err)
	}
	var next model.CapacityIntent
	_ = json.Unmarshal(intentRaw, &next)
	if next.Phase != "reconciled_failed_floor" || !next.FloorDegraded || next.Decision.ExecutionPermitted || next.FencingToken != 2 || next.LeaseOwner != "" || next.LeaseExpiresAt != nil || !next.Assessment.Snapshot.ObservedAt.Equal(f.intent.Assessment.Snapshot.ObservedAt) {
		t.Fatal("false current/health or reopened epoch", next)
	}
	for _, q := range []string{`UPDATE public.capacity_mutation_grants SET original_disposition_id=NULL WHERE id=$1`, `UPDATE public.capacity_mutation_grants SET state='expired' WHERE id=$1`, `UPDATE public.capacity_mutation_grants SET grant_record='{}'::jsonb WHERE id=$1`} {
		if _, err = db.Exec(q, result.GrantID); err == nil {
			t.Fatal("one-way original rewritten")
		}
	}
	for _, q := range []string{`DELETE FROM public.capacity_original_create_dispositions WHERE grant_id=$1`, `UPDATE public.capacity_original_create_dispositions SET disposition_record='{}'::jsonb WHERE grant_id=$1`} {
		if _, err = db.Exec(q, result.GrantID); err == nil {
			t.Fatal("immutable disposition rewritten")
		}
	}
	if _, err = f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate())); err == nil {
		t.Fatal("owner replay")
	}
	if _, err = f.store.BeginOriginalCreateDisposition(ctx, result.GrantID, "isolated-test-operator"); err == nil {
		t.Fatal("disposed original reopened")
	}
	// The retained settled original no longer conflicts with a distinct SQL
	// authority row. Production IssueMutation additionally guards new gen/fence.
	if _, err = db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,2,integration_instance_id,scope_checksum,profile_name,slot,'issued','{}',clock_timestamp()+interval '1 minute' FROM public.capacity_mutation_grants WHERE id=$1`, result.GrantID, uuid.NewString()); err != nil {
		t.Fatal("partial unique index still reserves disposed original", err)
	}
}
func TestOriginalDispositionPostgresRejectsOpenBoundaries(t *testing.T) {
	db := originalDispositionPG(t)
	for _, test := range []struct{ name, q string }{
		{"witness", `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id) VALUES($1)`},
		{"enrollment", `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id) VALUES($1)`},
		{"installation", `INSERT INTO public.capacity_guest_original_installations(preregistration_id) VALUES($1)`},
		{"running_workflow", `INSERT INTO public.workflow_runs(id,workflow_id,status) SELECT gen_random_uuid(),($2::jsonb->>'workflow_id')::uuid,'running' WHERE $1::uuid IS NOT NULL`},
		{"live_original_deadline", `UPDATE public.capacity_vm_provisioning_preregistrations SET original_deadline=clock_timestamp()+interval '1 minute' WHERE id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := originalDispositionPGFixture(t, db)
			raw, _ := json.Marshal(f.record)
			args := []any{f.pre.PreregistrationID}
			if strings.Contains(test.q, "$2") {
				args = append(args, string(raw))
			}
			if _, err := db.Exec(test.q, args...); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "test-operator"); err == nil {
				t.Fatal("open original accepted")
			}
		})
	}
}
func TestOriginalDispositionPostgresRechecksRaceAndSerializes(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Run("witness_after_begin", func(t *testing.T) {
		f := originalDispositionPGFixture(t, db)
		owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "operator")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id) VALUES($1)`, f.pre.PreregistrationID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate())); err == nil {
			t.Fatal("late witness race accepted")
		}
	})
	t.Run("changed_original_after_begin", func(t *testing.T) {
		f := originalDispositionPGFixture(t, db)
		owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "operator")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,provider_status_code}','201') WHERE id=$1`, f.pre.OriginalCreateGrantID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate())); err == nil {
			t.Fatal("changed original accepted")
		}
	})
	t.Run("two_independent_owners", func(t *testing.T) {
		f := originalDispositionPGFixture(t, db)
		a, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "operator")
		if err != nil {
			t.Fatal(err)
		}
		b, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "operator")
		if err != nil {
			t.Fatal(err)
		}
		native := f.native(t, a.Candidate())
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, o := range []*OriginalCreateDispositionOwner{a, b} {
			wg.Add(1)
			go func(o *OriginalCreateDispositionOwner) {
				defer wg.Done()
				_, e := f.store.CompleteOriginalCreateDisposition(ctx, o, native)
				errs <- e
			}(o)
		}
		wg.Wait()
		close(errs)
		success := 0
		for e := range errs {
			if e == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatal("not exactly one disposition", success)
		}
	})
}

func TestOriginalDispositionPostgresSuccessorFence(t *testing.T) {
	db := originalDispositionPG(t)
	f := originalDispositionPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-successor-test")
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := f.store.CompleteOriginalCreateDisposition(ctx, owner, f.native(t, owner.Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	if disposition.ClosedGeneration != 1 || disposition.ClosedFencingToken != 2 {
		t.Fatal("fixture did not close original fence")
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		t.Fatal("fixture policy")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, upgrade := range []bool{false, true} {
		binding := f.record.Binding
		if upgrade {
			binding.IntegrationInstanceID = uuid.NewString()
			binding.ScopeChecksum = strings.Repeat("9", 64)
		}
		for _, scenario := range []struct {
			generation, fence int64
			allowed           bool
		}{{1, 3, false}, {2, 2, false}, {2, 3, true}} {
			err := requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, binding, 1, scenario.generation, scenario.fence)
			if (err == nil) != scenario.allowed {
				t.Fatalf("upgrade=%v generation=%d fence=%d allowed=%v err=%v", upgrade, scenario.generation, scenario.fence, scenario.allowed, err)
			}
		}
	}
}
