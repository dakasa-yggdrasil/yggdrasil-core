//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"net/url"
	"os"
	"reflect"
)

// Signed test-only content in an isolated, rolled-back database. No actual
// Guest, provider, process custody, readiness or business effect is asserted.
func TestRecoveryFixtureSignedInstallationStoredPostgres(t *testing.T) {
	db := guestOriginalPostgres(t)
	tx, ctx := guestOriginalStorageTx(t, db)
	p, b, reg, receipt, confirmation := capacity.RecoveryFixtureInstalled(t)
	pre := reg.Result.ProductionClock.Authority.Preregistration
	witness := reg.Result.ProductionClock.Authority.CreateWitness
	raw := func(v any) []byte {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	policyWire := raw(p)
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy','test-recovery','unit',1,$2,$3::jsonb,false)`, pre.PolicyID, pre.PolicyChecksum, string(policyWire))
	f := guestOriginalStorageFixture{pre: pre, binding: b, wire: raw(pre), bindingWire: raw(b)}
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, pre.OriginalDeadline)
	w := raw(witness)
	must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), w, string(w), witness.ObservedAt)
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(raw(receipt.Enrollment)), receipt.RecordedAt, raw(reg), raw(receipt))
	recorded := receipt.RecordedAt.Add(time.Second)
	must(`INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, pre.PreregistrationID, raw(confirmation), capacity.GuestRetirementSHA(confirmation), recorded)
	stored, err := loadGuestOriginalTx(ctx, tx, pre.PreregistrationID)
	if err != nil {
		t.Fatal("pre", err)
	}
	if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
		t.Fatal("witness", err)
	}
	got, _, err := loadGuestReceiptTx(ctx, tx, pre.PreregistrationID)
	if err != nil {
		t.Fatal("receipt", err)
	}
	if _, err = loadGuestInstallationTx(ctx, tx, stored, got); err != nil {
		t.Fatal("installed", err)
	}
	if err = capacity.GuestRetirementEnrollment(p, b, b.Members[0], got.Enrollment, got.RecordedAt); err != nil {
		t.Fatal("enrollment", err)
	}
	bad := stored
	bad.binding.ProvisionerPublicKey = strings.Repeat("x", 44)
	if err = validateGuestInstallationTx(ctx, tx, bad, got, confirmation, recorded); err == nil {
		t.Fatal("foreign producer accepted")
	}
	if context.Cause(ctx) != nil {
		t.Fatal("fixture deadline expired")
	}
}

func TestRecoveryFixtureCurrentSourceRegistry(t *testing.T) {
	p, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	if capacity.CurrentGuestCoreSource() == "" {
		t.Fatal("test binary requires clean verified VCS source")
	}
	if capacity.GuestBindingAuthorityCurrent(p, b) {
		t.Fatal("fixture key was in real registry")
	}
	if !capacity.GuestBindingAuthorityCurrent(p, b) {
		if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
			t.Fatal(err)
		}
	}
	if !capacity.GuestBindingAuthorityCurrent(p, b) || !capacity.GuestOriginalProfileEnabled(p, b, "hetzner") {
		t.Fatal("fixture approval does not match full source policy")
	}
}

func TestRecoveryFixtureSourceBindingsPostgres(t *testing.T) {
	db := guestOriginalPostgres(t)
	tx, ctx := guestOriginalStorageTx(t, db)
	p, b, reg, receipt, confirmation := capacity.RecoveryFixtureInstalled(t)
	p.ExecutionEnabled = true
	pre := reg.Result.ProductionClock.Authority.Preregistration
	if !capacity.GuestBindingAuthorityCurrent(p, b) {
		if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
			t.Fatal(err)
		}
	}
	if capacity.CurrentGuestCoreSource() == "" {
		t.Fatal("clean VCS source missing")
	}
	if !capacity.GuestBindingAuthorityCurrent(p, b) {
		t.Fatal("synthetic map did not bind actual fixture contract")
	}
	policy := model.Manifest{ID: uuid.MustParse(pre.PolicyID), Kind: "capacity_policy", Checksum: pre.PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "recovery-unit", Active: true}}
	steps, err := capacity.OriginalGuestReconcileGraph(policy, p)
	if err != nil {
		t.Fatal("graph", err)
	}
	enabled, no := true, false
	spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: steps}
	raw := func(v any) []byte {
		t.Helper()
		w, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return w
	}
	policy.Spec = raw(p)
	wf := model.Manifest{ID: uuid.MustParse(pre.WorkflowID), Kind: "workflow", Checksum: pre.WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: p.Workflow.Namespace, Name: p.Workflow.Name, Active: true}, Spec: raw(spec)}
	must := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','capacity_policy',$2,$3,1,$4,$5::jsonb,true)`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name, policy.Checksum, string(policy.Spec))
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','workflow',$2,$3,1,$4,$5::jsonb,true)`, wf.ID, wf.Metadata.Namespace, wf.Metadata.Name, wf.Checksum, string(wf.Spec))
	mutation := p.MutationBindings[0]
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_type','test-recovery','unit-type',1,$2,'{}'::jsonb,true)`, mutation.IntegrationTypeID, mutation.IntegrationTypeChecksum)
	ref := raw(map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})
	must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_instance','test-recovery','unit-instance',1,$2,$3::jsonb,true)`, mutation.IntegrationInstanceID, mutation.IntegrationChecksum, string(ref))
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store := CapacityStore{DB: db, WorkflowID: wf.ID, guestReconcile: &guestReconcileSource{workflow: wf, step: steps[0], source: capacity.CurrentGuestCoreSource()}}
	if err = store.guestReconcileSourceTx(bounded, tx, policy, p); err != nil {
		t.Fatal("original source graph/binding", err)
	}
	witness := reg.Result.ProductionClock.Authority.CreateWitness
	f := guestOriginalStorageFixture{pre: pre, binding: b, wire: raw(pre), bindingWire: raw(b)}
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, pre.OriginalDeadline)
	witnessWire := raw(witness)
	must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), witnessWire, string(witnessWire), witness.ObservedAt)
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(raw(receipt.Enrollment)), receipt.RecordedAt, raw(reg), raw(receipt))
	must(`INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, pre.PreregistrationID, raw(confirmation), capacity.GuestRetirementSHA(confirmation), receipt.RecordedAt.Add(time.Second))
	slot := capacityResourceSlot{BindingName: mutation.Name, ProfileName: mutation.ProfileName, DesiredSpecSHA256: mutation.Slots[0].DesiredSpecSHA256, ResourceID: reg.Result.Tuple.ResourceID, ResourceCreatedAt: reg.Result.Tuple.CreatedAt, ReceiptRef: "fixture-only", ObservedAt: time.Now().UTC()}
	if err = saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, mutation, 1, slot); err != nil {
		t.Fatal("fixture slot", err)
	}
	store.guestReconcile.inventory = capacity.RecoveryFixtureInventory(t, p, reg, time.Now().UTC())
	members, err := store.guestReconcileMembersTx(bounded, tx, policy, p, time.Now().UTC(), true)
	if err != nil || len(members) != 1 || members[0].PreregistrationID != pre.PreregistrationID {
		t.Fatal("original member join", members, err)
	}
}

// The full transaction test creates and drops a unique local PostgreSQL
// database. It refuses remote addresses and never reads production secrets.
func recoveryTestIsolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("explicit fixture-only gate required")
	}
	u, err := url.Parse(os.Getenv("RECOVERY_FIXTURE_ADMIN_URL"))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("explicit local admin URL required")
	}
	host := u.Hostname()
	socket := u.Query().Get("host")
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && !(host == "" && strings.HasPrefix(socket, "/")) {
		t.Fatal("remote PostgreSQL refused")
	}
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	var addr string
	if err = admin.QueryRow(`SELECT COALESCE(inet_server_addr()::text,'unix')`).Scan(&addr); err != nil || !(addr == "unix" || strings.HasPrefix(addr, "127.") || addr == "::1") {
		t.Fatal("nonlocal actual PostgreSQL refused", err)
	}
	name := "recovery_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, e := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)")
		if e != nil {
			t.Error("isolated database cleanup", e)
		}
		_ = admin.Close()
	})
	var major int
	if err = db.QueryRow(`SELECT current_setting('server_version_num')::int / 10000`).Scan(&major); err != nil || major != 16 {
		t.Fatal("PostgreSQL 16 required", err)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err = goose.Up(db, "../db/migrations"); err != nil {
		t.Fatal("source migrations", err)
	}
	return db
}

func TestRecoveryFixtureResumeSetupPostgres(t *testing.T) {
	for _, scenario := range []string{"bad_return_digest", "bad_run_lineage", "foreign_executor", "different_resource", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			db := recoveryTestIsolatedDB(t)
			db.SetMaxOpenConns(1)
			if _, e := db.Exec(`SET TIME ZONE 'UTC'`); e != nil {
				t.Fatal(e)
			}
			ctx, cancelSetup := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelSetup()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			p, b, reg, receipt, confirmation := capacity.RecoveryFixtureInstalled(t)
			p.ExecutionEnabled = true
			pre := reg.Result.ProductionClock.Authority.Preregistration
			if !capacity.GuestBindingAuthorityCurrent(p, b) {
				if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
					t.Fatal(err)
				}
			}
			if capacity.CurrentGuestCoreSource() == "" {
				t.Fatal("clean VCS source missing")
			}
			if !capacity.GuestBindingAuthorityCurrent(p, b) {
				t.Fatal("synthetic map did not bind actual fixture contract")
			}
			policy := model.Manifest{ID: uuid.MustParse(pre.PolicyID), Kind: "capacity_policy", Checksum: pre.PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "recovery-unit", Active: true}}
			steps, err := capacity.OriginalGuestReconcileGraph(policy, p)
			if err != nil {
				t.Fatal("graph", err)
			}
			enabled, no := true, false
			spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: steps}
			raw := func(v any) []byte {
				t.Helper()
				w, e := json.Marshal(v)
				if e != nil {
					t.Fatal(e)
				}
				return w
			}
			policy.Spec = raw(p)
			wf := model.Manifest{ID: uuid.MustParse(pre.WorkflowID), Kind: "workflow", Checksum: pre.WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: p.Workflow.Namespace, Name: p.Workflow.Name, Active: true}, Spec: raw(spec)}
			must := func(q string, args ...any) {
				t.Helper()
				if _, e := tx.ExecContext(ctx, q, args...); e != nil {
					t.Fatal(e)
				}
			}
			must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','capacity_policy',$2,$3,1,$4,$5::jsonb,true)`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name, policy.Checksum, string(policy.Spec))
			must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','workflow',$2,$3,1,$4,$5::jsonb,true)`, wf.ID, wf.Metadata.Namespace, wf.Metadata.Name, wf.Checksum, string(wf.Spec))
			mutation := p.MutationBindings[0]
			must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_type','test-recovery','unit-type',1,$2,'{}'::jsonb,true)`, mutation.IntegrationTypeID, mutation.IntegrationTypeChecksum)
			ref := raw(map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})
			must(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_instance','test-recovery','unit-instance',1,$2,$3::jsonb,true)`, mutation.IntegrationInstanceID, mutation.IntegrationChecksum, string(ref))
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			store := CapacityStore{DB: db, WorkflowID: wf.ID, guestReconcile: &guestReconcileSource{workflow: wf, step: steps[0], source: capacity.CurrentGuestCoreSource()}}
			if err = store.guestReconcileSourceTx(bounded, tx, policy, p); err != nil {
				t.Fatal("original source graph/binding", err)
			}
			witness := reg.Result.ProductionClock.Authority.CreateWitness
			f := guestOriginalStorageFixture{pre: pre, binding: b, wire: raw(pre), bindingWire: raw(b)}
			guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, pre.OriginalDeadline)
			witnessWire := raw(witness)
			must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), witnessWire, string(witnessWire), witness.ObservedAt)
			must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(raw(receipt.Enrollment)), receipt.RecordedAt, raw(reg), raw(receipt))
			must(`INSERT INTO public.capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,$2,$3,$4)`, pre.PreregistrationID, raw(confirmation), capacity.GuestRetirementSHA(confirmation), receipt.RecordedAt.Add(time.Second))
			slot := capacityResourceSlot{BindingName: mutation.Name, ProfileName: mutation.ProfileName, DesiredSpecSHA256: mutation.Slots[0].DesiredSpecSHA256, ResourceID: reg.Result.Tuple.ResourceID, ResourceCreatedAt: reg.Result.Tuple.CreatedAt, ReceiptRef: "fixture-only", ObservedAt: time.Now().UTC()}
			if err = saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, mutation, 1, slot); err != nil {
				t.Fatal("fixture slot", err)
			}
			store.guestReconcile.inventory = capacity.RecoveryFixtureInventory(t, p, reg, time.Now().UTC())
			members, err := store.guestReconcileMembersTx(bounded, tx, policy, p, time.Now().UTC(), true)
			if err != nil || len(members) != 1 || members[0].PreregistrationID != pre.PreregistrationID {
				t.Fatal("original member join", members, err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal("fixture setup commit", err)
			}
			var count int
			if err = db.QueryRow(`SELECT count(*) FROM public.capacity_vm_original_enrollments`).Scan(&count); err != nil || count != 1 {
				t.Fatal("fixture setup persistence", count, err)
			}
			rbac := CapacityDispatchManifestPin{ID: uuid.New(), Namespace: policy.Metadata.Namespace, Name: "unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("fixture-rbac"))}
			if _, err = db.Exec(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)`, rbac.ID, rbac.Namespace, rbac.Name, rbac.Checksum); err != nil {
				t.Fatal(err)
			}
			pin := func(m model.Manifest) CapacityDispatchManifestPin {
				return CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
			}
			start := func(tick int) (CapacityDispatchEnvelope, CapacityDispatchJob) {
				t.Helper()
				e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: time.Now().UTC().Add(time.Duration(tick) * time.Second).Truncate(time.Second).Format(time.RFC3339), Policy: pin(policy), Workflow: pin(wf), RBAC: rbac, MachinePrincipalID: "capacity-controller", PrincipalSHA256: capacityDispatchSHA([]byte("test-principal")), BindingSHA256: capacityDispatchSHA([]byte("test-binding"))}
				e.Inputs = map[string]any{"policy": map[string]any{"namespace": policy.Metadata.Namespace, "name": policy.Metadata.Name}}
				e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": wf.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_job_id": e.JobID.String(), "capacity_dispatch_protocol": e.Protocol}
				var eerr error
				e.InputsSHA256, e.MetadataSHA256, eerr = CapacityDispatchEnvelopeHashes(e)
				if eerr != nil {
					t.Fatal(eerr)
				}
				capacityDispatchEnqueueFixture(t, db, e)
				j := capacityDispatchClaimFixture(t, db, e, 30*time.Second)
				j, eerr = StartCapacityDispatch(ctx, db, j)
				if eerr != nil {
					t.Fatal("dispatch start", eerr)
				}
				return e, j
			}
			original, originalJob := start(0)
			response := capacityDispatchResponse(original, "failed")
			for _, id := range []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"} {
				s := model.WorkflowRunStepResult{ID: id, Status: "skipped"}
				if id == "plan-original-guest" || id == "provision-original-notify" {
					s.Status = "succeeded"
				}
				if id == "provision-original-notify" {
					s.Metadata = map[string]any{"preregistration": pre}
				}
				if id == "complete-original-provision" {
					s.Status = "failed"
				}
				response.Steps = append(response.Steps, s)
			}
			if err = FinishCapacityDispatch(ctx, db, originalJob, response, time.Now().UTC(), nil); err != nil {
				t.Fatal("original dispatch finish", err)
			}
			previous, previousJob := start(1)
			response = capacityDispatchResponse(previous, "failed")
			for _, id := range []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"} {
				s := model.WorkflowRunStepResult{ID: id, Status: "skipped"}
				if id == "plan-original-guest" {
					s.Status = "succeeded"
					s.Metadata = map[string]any{"mode": "refresh", "reason": "installed_original_readiness_reconcile", "generation": pre.Generation, "fencing_token": pre.Fence + 1}
				}
				if id == "refresh-original-membership" {
					s.Status = "failed"
				}
				response.Steps = append(response.Steps, s)
			}
			if err = FinishCapacityDispatch(ctx, db, previousJob, response, time.Now().UTC(), nil); err != nil {
				t.Fatal("previous dispatch finish", err)
			}
			current, _ := start(2)
			var originalWire, originalResult []byte
			if err = db.QueryRow(`SELECT row_to_json(w)::text,w.result FROM public.workflow_runs w WHERE id=$1`, original.RunID).Scan(&originalWire, &originalResult); err != nil || !originalInstalledFailureResult(originalResult, pre, wf.ID) {
				t.Fatal("original dispatch payload", err)
			}
			var previousResult []byte
			if err = db.QueryRow(`SELECT result FROM public.workflow_runs WHERE id=$1`, previous.RunID).Scan(&previousResult); err != nil || !failedInstalledResumeResult(previousResult, pre.Generation, pre.Fence+1) {
				t.Fatal("previous dispatch payload", err)
			}
			store.OriginalRunID = current.RunID
			store.ExecutorID = pre.ExecutorID
			rt, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer rt.Rollback()
			for _, v := range []struct {
				id     uuid.UUID
				result []byte
			}{{original.RunID, originalResult}, {previous.RunID, previousResult}, {current.RunID, nil}} {
				if e = store.installedGuestDispatchRunTx(ctx, rt, policy, p, v.id, v.result); e != nil {
					t.Fatal("verified actual dispatch", v.id, e)
				}
			}

			if e = rt.Rollback(); e != nil {
				t.Fatal(e)
			}
			at := time.Now().UTC().Add(-12 * time.Second).Truncate(time.Microsecond)
			read, pub, pubReturn, transport := capacity.RecoveryFixtureCausal(t, p, reg, receipt, uint64(pre.Fence+1), pre.LeaseOwner, at)
			wtx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer wtx.Rollback()
			write := func(q string, args ...any) {
				t.Helper()
				if _, err := wtx.ExecContext(ctx, q, args...); err != nil {
					t.Fatal("fixture row", err)
				}
			}
			write(`UPDATE public.capacity_mutation_grants SET state='confirmed' WHERE id=$1`, pre.OriginalCreateGrantID)
			for _, challenge := range []model.CapacityGuestNotifyCanaryChallenge{pub, read} {
				phase := "read"
				if challenge.ChallengeID == pub.ChallengeID {
					phase = "publish"
				}
				before := challenge
				before.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
				before.Signature = ""
				beforeWire := raw(before)
				beforeSHA := capacity.GuestRetirementSHA(before)
				write(`INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16)`, challenge.ChallengeID, challenge.PreregistrationID, challenge.RecordChallengeID, phase, challenge.PolicyID, challenge.WorkflowID, challenge.Generation, challenge.Fence, pre.ExecutorID, challenge.LeaseOwner, beforeSHA, challenge.NonceSHA256, beforeWire, string(beforeWire), challenge.OriginalDeadline, challenge.IssuedAt)
				write(`INSERT INTO public.capacity_guest_notify_canary_nonces(challenge_id,guest_nonce_sha256,nonce_wire,final_challenge_wire,final_challenge_sha256,original_transport,recorded_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6)`, challenge.ChallengeID, challenge.GuestNonce.NonceSHA256, raw(challenge.GuestNonce), raw(challenge), capacity.GuestRetirementSHA(challenge), challenge.IssuedAt)
				issue := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": challenge.ChallengeID, "issuer_actual_source_commit": originalReadCoreSource, "protocol_authority_source_commit": b.CoreAuthoritySourceCommit, "compatibility_map_sha256": capacity.GuestProtocolCompatibilityMapSHA256(), "profile": b.ProfileManifest.Profile, "policy_id": challenge.PolicyID, "workflow_id": challenge.WorkflowID, "executor_id": pre.ExecutorID, "issued_wire_sha256": beforeSHA}
				issueWire := raw(issue)
				write(`INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record) VALUES('canary_challenge',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, challenge.ChallengeID, originalReadCoreSource, b.CoreAuthoritySourceCommit, capacity.GuestProtocolCompatibilityMapSHA256(), b.ProfileManifest.Profile, challenge.PolicyID, challenge.WorkflowID, pre.ExecutorID, beforeSHA, issueWire, string(issueWire))
			}
			request := raw(model.CapacityGuestNotifyCanaryRequest{Challenge: read})
			write(`INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, read.ChallengeID, capacity.BusinessCreationSHA256(request), read.IssuedAt.Add(time.Millisecond), read.OriginalDeadline)
			pubWire := raw(pubReturn)
			write(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'accepted',$2,$3,$4::jsonb,$5)`, pub.ChallengeID, capacity.BusinessCreationSHA256(pubWire), pubWire, string(raw(transport)), transport.DriverReturnedAt)
			originalReturn := capacity.GuestOriginalHTTPReturn{StartedAt: read.IssuedAt.Add(2 * time.Millisecond), DoStartedAt: read.IssuedAt.Add(3 * time.Millisecond), DoReturnedAt: read.OriginalDeadline.Add(time.Millisecond), DriverReturnedAt: read.OriginalDeadline.Add(2 * time.Millisecond), DoFailed: true, OriginalContextFailed: true, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
			diagnostic := raw(originalReturn)
			digest := capacity.BusinessCreationSHA256(diagnostic)
			if scenario == "bad_return_digest" {
				digest = strings.Repeat("a", 64)
			}
			write(`INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_transport,recorded_at) VALUES($1,'held',$2,$3::jsonb,$4)`, read.ChallengeID, digest, string(diagnostic), originalReturn.DriverReturnedAt)
			expired := at
			assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, Owner: p.Owner, ResourceUID: "fixture-resource", WorkloadUID: "fixture-workload", WorkloadResourceVersion: "1", ResourceVersion: "1", Profile: mutation.ProfileName, Units: 1, ObservedAt: at}}
			old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: pre.Generation, FencingToken: pre.Fence + 1, Phase: "preparing", LeaseOwner: pre.LeaseOwner, LeaseExecutorID: pre.ExecutorID, LeaseExpiresAt: &expired, Decision: model.CapacityDecision{Profile: mutation.ProfileName, Units: 1}, Assessment: assessment, UpdatedAt: at, InstalledGuestReconcile: &model.CapacityInstalledGuestReconcile{Schema: "installed_original_guest_readiness_reconcile_v1", Attempt: 1, OriginalGeneration: pre.Generation, OriginalFence: pre.Fence, NewFence: pre.Fence + 1, OriginalRunID: original.RunID.String(), OriginalRunSHA256: capacity.BusinessCreationSHA256(originalWire), PreregistrationID: pre.PreregistrationID, NewRunID: previous.RunID.String(), OriginalFailurePreserved: true}}
			if scenario == "bad_run_lineage" {
				old.InstalledGuestReconcile.OriginalRunSHA256 = strings.Repeat("a", 64)
			}
			if scenario == "foreign_executor" {
				old.LeaseExecutorID = uuid.NewString()
			}
			write(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, string(raw(old)), old.UpdatedAt)
			if e = wtx.Commit(); e != nil {
				t.Fatal(e)
			}
			before := string(raw(old))
			callAssessment := assessment
			if scenario == "different_resource" {
				callAssessment.Snapshot.ResourceUID = "foreign-resource"
			}
			actual, ok, e := store.TryResumeInstalledGuest(bounded, policy, callAssessment)
			if scenario != "valid" {
				if ok || e == nil {
					t.Fatal("invalid lineage accepted", scenario, ok, e)
				}
				var current []byte
				var count int
				if x := db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&current); x != nil {
					t.Fatal(x)
				}
				var expected, after any
				if json.Unmarshal([]byte(before), &expected) != nil || json.Unmarshal(current, &after) != nil || !reflect.DeepEqual(expected, after) {
					t.Fatal("rejected resume changed intent")
				}
				if x := db.QueryRow(`SELECT count(*) FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_reconcile'`).Scan(&count); x != nil || count != 0 {
					t.Fatal("rejected resume created authority", count, x)
				}
				if x := db.QueryRow(`SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&count); x != nil || count != 0 {
					t.Fatal("rejected resume created event", count, x)
				}
				return
			}
			if e != nil || !ok {
				t.Fatalf("full TryResume: ok=%v err=%v candidate=%v profile=%v", ok, e, installedGuestResumeCandidate(&old, p, policy, time.Now().UTC()), capacityProfileCurrent(p, old.Decision, time.Now().UTC()))
			}
			if actual.FencingToken != old.FencingToken+1 || actual.InstalledGuestReconcile == nil || actual.InstalledGuestReconcile.Attempt != 2 {
				t.Fatal("wrong new epoch")
			}
			var storedIntent []byte
			if e = db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&storedIntent); e != nil {
				t.Fatal(e)
			}
			var persisted model.CapacityIntent
			if e = json.Unmarshal(storedIntent, &persisted); e != nil || persisted.InstalledGuestReconcile == nil {
				t.Fatal("marker persistence", e)
			}
			var found bool
			for _, r := range persisted.InstalledGuestReconcile.PreviousCanaries {
				if r.ChallengeID == read.ChallengeID {
					found = r.Outcome == "held" && r.OriginalTransportState == "unknown_read_timeout" && r.OriginalTransportSHA256 == capacity.BusinessCreationSHA256(diagnostic)
				}
			}
			if !found {
				t.Fatal("historical read was not durably retained unknown")
			}
			var issues, events int
			if e = db.QueryRow(`SELECT count(*) FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_reconcile' AND issue_id=$1`, current.RunID).Scan(&issues); e != nil || issues != 1 {
				t.Fatal("new authority audit", issues, e)
			}
			if e = db.QueryRow(`SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1 AND fencing_token=$2`, policy.Metadata.Namespace, actual.FencingToken).Scan(&events); e != nil || events != 1 {
				t.Fatal("new fence event", events, e)
			}
			var issueWire []byte
			var issueHash string
			if e = db.QueryRow(`SELECT original_wire,issued_wire_sha256 FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_reconcile' AND issue_id=$1`, current.RunID).Scan(&issueWire, &issueHash); e != nil {
				t.Fatal(e)
			}
			var issue struct {
				Marker string `json:"installed_reconcile_marker_base64"`
			}
			if e = json.Unmarshal(issueWire, &issue); e != nil {
				t.Fatal(e)
			}
			markerWire, e := base64.StdEncoding.DecodeString(issue.Marker)
			if e != nil || capacity.BusinessCreationSHA256(markerWire) != issueHash {
				t.Fatal("audit marker hash", e)
			}
			var auditMarker model.CapacityInstalledGuestReconcile
			if e = json.Unmarshal(markerWire, &auditMarker); e != nil || !reflect.DeepEqual(auditMarker, *persisted.InstalledGuestReconcile) {
				t.Fatal("audit differs from committed marker", e)
			}
			var outcome, returnSHA string
			var sends int
			if e = db.QueryRow(`SELECT outcome,return_sha256 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=$1`, read.ChallengeID).Scan(&outcome, &returnSHA); e != nil || outcome != "held" || returnSHA != capacity.BusinessCreationSHA256(diagnostic) {
				t.Fatal("original historical return changed", e)
			}
			if e = db.QueryRow(`SELECT count(*) FROM public.capacity_guest_notify_canary_sends`).Scan(&sends); e != nil || sends != 1 {
				t.Fatal("resume added or removed an old send", sends, e)
			}
			_, duplicate, e := store.TryResumeInstalledGuest(bounded, policy, assessment)
			if e != nil || duplicate {
				t.Fatal("live new lease allowed another resume", duplicate, e)
			}
			var final []byte
			if e = db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&final); e != nil || string(final) != string(storedIntent) {
				t.Fatal("second resume changed the fenced intent", e)
			}

		})
	}
}
