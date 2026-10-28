//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"crypto/ed25519"
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

// Exploratory source fixture: fake provider and all member facts are test data.
func TestSyntheticCompensationIssueExploration(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		protected bool
	}{{"unprotected_failed_create", false}, {"protected_failed_create_without_serving_membership", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			capacity.RecoveryFixtureApprovalScope(t)
			db := recoveryTestIsolatedDB(t)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			p, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
			ns := "unit-compensation-" + uuid.NewString()
			now := time.Now().UTC()
			v := 0.9
			generic := model.CapacityPolicySpec{Environment: "production", Domain: "api", Dimension: "replicas", TargetIdentity: "cluster/ns/api", Owner: "capacity-api", MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 30, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}}
			a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: generic.TargetIdentity, ResourceUID: "hpa-1", WorkloadUID: "deployment-1", WorkloadResourceVersion: "10", ResourceVersion: "1", Owner: generic.Owner, Units: 4, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "prom/api", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
			p.Environment, p.Domain, p.Dimension = generic.Environment, generic.Domain, generic.Dimension
			p.TargetIdentity, p.Owner, p.Signals = generic.TargetIdentity, generic.Owner, generic.Signals
			p.MaxEvidenceAgeSeconds, p.MaxSampleGapSeconds, p.MinSamples = generic.MaxEvidenceAgeSeconds, generic.MaxSampleGapSeconds, generic.MinSamples
			p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = generic.UpHoldSeconds, generic.DownHoldSeconds, generic.CooldownSeconds
			p.Workflow = model.ManifestSelector{Namespace: ns, Name: "synthetic-guest-workflow"}
			p.Floor, p.Ceiling, p.Step, p.LeaseSeconds = 2, 8, 2, 120
			p.ExecutionEnabled = true
			p.GuestNotifyReconcileBinding = nil
			p.Profiles[0].MinUnits = 2
			p.Profiles[0].QuoteValidUntil = time.Now().UTC().Add(time.Hour)
			p.Profiles[0].ValidationValidUntil = time.Now().UTC().Add(time.Hour)
			a.Snapshot.TargetIdentity = p.TargetIdentity
			a.Snapshot.Owner = p.Owner
			a.Snapshot.Profile = p.Profiles[0].Name
			create := func(kind, name string, spec any) model.Manifest {
				t.Helper()
				wire, e := json.Marshal(spec)
				if e != nil {
					t.Fatal(e)
				}
				m, e := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: wire}, capacity.BusinessCreationSHA256(wire))
				if e != nil {
					t.Fatal(e)
				}
				return m
			}
			typSpec := mutationTypeFixture()
			typSpec.Provider = "hetzner"
			typ := create("integration_type", "synthetic-type", typSpec)
			inst := create("integration_instance", "synthetic-instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()}})
			mutation := p.MutationBindings[0]
			mutation.IntegrationInstanceID = inst.ID.String()
			mutation.IntegrationChecksum = inst.Checksum
			mutation.IntegrationTypeID = typ.ID.String()
			mutation.IntegrationTypeChecksum = typ.Checksum
			mutation.ProtectedSlots = 2
			plans := map[int]model.CapacityMutationIssue{}
			for i := range mutation.Slots {
				slot := &mutation.Slots[i]
				slot.DesiredSpec.IntegrationInstanceID = inst.ID.String()
				wire, e := json.Marshal(slot.DesiredSpec)
				if e != nil {
					t.Fatal(e)
				}
				var canonical map[string]any
				if e = json.Unmarshal(wire, &canonical); e != nil {
					t.Fatal(e)
				}
				wire, e = json.Marshal(canonical)
				if e != nil {
					t.Fatal(e)
				}
				slot.DesiredSpecSHA256 = capacity.BusinessCreationSHA256(wire)
				plans[slot.Slot] = model.CapacityMutationIssue{BindingName: mutation.Name, DesiredSpec: wire}
			}
			p.MutationBindings = []model.CapacityMutationBinding{mutation}
			p.GuestRetirementBinding = &b
			if err := capacity.ValidateGuestRetirementBinding(p, &b); err != nil {
				t.Fatal("binding", err)
			}
			if err := capacity.ValidateGuestNotifyCanaryBinding(p); err != nil {
				t.Fatal("canary", err)
			}
			if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
				t.Fatal("test approval", err)
			}
			withCleanup := p
			withCleanup.MutationBindings = append([]model.CapacityMutationBinding(nil), p.MutationBindings...)
			withCleanup.MutationBindings[0].CompensationEnabled = true
			if err := capacity.RegisterRecoveryFixtureApproval(withCleanup, b, "hetzner"); err != nil {
				t.Fatal("test cleanup approval", err)
			}
			step := model.WorkflowStepSpec{ID: b.ProfileManifest.OriginalProvisioningStepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.ProvisionOriginalGuestOperation}, TimeoutSeconds: b.ProfileManifest.OriginalProvisioningBudgetSeconds}
			wf := create("workflow", p.Workflow.Name, map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": p.Workflow.Namespace, "name": "fixture-rbac"}}, "steps": []model.WorkflowStepSpec{step}})
			policy := create("capacity_policy", "synthetic-guest-policy", p)
			store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), strings.Repeat("a", 64))
			intent, e := store.Assess(ctx, policy, a)
			if e != nil {
				t.Fatal("assess", e)
			}
			t.Logf("assessed phase=%s action=%s reason=%s units=%d", intent.Phase, intent.Decision.Action, intent.Decision.Reason, intent.Decision.Units)
			intent, e = store.Claim(ctx, policy, intent.Generation, a)
			if e != nil {
				t.Fatal("claim", e)
			}
			f := mutationFixture{db: db, policy: policy, store: store, a: a, intent: intent, binding: mutation, plans: plans, created: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
			failedSlot := 5
			if scenario.protected {
				failedSlot = 1
				for slot := 2; slot <= 5; slot++ {
					f.record(t, slot)
				}
			} else {
				for slot := 1; slot <= 4; slot++ {
					f.record(t, slot)
				}
			}
			grant, e := store.IssueMutation(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, plans[failedSlot])
			if e != nil {
				t.Fatal("real IssueMutation", e)
			}
			nonce := uuid.NewString()
			redeem := mutationRedeem(grant, nonce)
			if _, e = store.RedeemMutation(ctx, mutation.AdapterPrincipalID, redeem); e != nil {
				t.Fatal("real RedeemMutation", e)
			}
			settle := mutationSettlement(redeem, f.created)
			instant := time.Now().UTC().Format(time.RFC3339Nano)
			settle.ResourceCreatedAt = instant
			settle.ResourceID = "123"
			settle.ObservedAt = instant
			settle.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: mutation.OriginalProviderSourceCommit, GrantID: grant.GrantID, AttemptID: redeem.AttemptID, RequestSHA256: grant.RequestSHA256, ResourceID: settle.ResourceID, ResourceCreatedAt: instant, ActionID: settle.ActionID, NextActionIDs: settle.NextActionIDs, CalledAt: instant, ReturnedAt: instant, ContextDeadline: grant.ExpiresAt.UTC().Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 100}
			if _, e = store.SettleMutation(ctx, mutation.AdapterPrincipalID, nonce, settle); e != nil {
				t.Fatal("real SettleMutation", e)
			}
			var preWire []byte
			if e = db.QueryRow(`SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, grant.GrantID).Scan(&preWire); e != nil {
				t.Fatal(e)
			}
			var pre model.CapacityGuestOriginalProvisioningPreregistration
			if e = json.Unmarshal(preWire, &pre); e != nil {
				t.Fatal(e)
			}
			witness, reg, receipt := capacity.RecoveryFixtureCompensationRegistration(t, p, b, pre, settle)
			if witness.PreregistrationID != pre.PreregistrationID || reg.Result.Tuple.ResourceID != settle.ResourceID || receipt.PreregistrationID != pre.PreregistrationID {
				t.Fatal("fixture lineage")
			}
			retirementID := syntheticRetirement(t, ctx, db, store, policy, p, b, pre, witness, reg, receipt, intent)
			proof := f.proof(t, failedSlot)
			proof.GrantID, proof.RequestSHA256, proof.ResourceID, proof.ResourceCreatedAt, proof.ObservedCreationGrantID = grant.GrantID, grant.RequestSHA256, settle.ResourceID, settle.ResourceCreatedAt, grant.GrantID
			proof.ActionsTerminal, proof.ActionsFailed, proof.SpecVerified, proof.CompensationIdentityVerified = true, true, false, true
			proof.ActionIDs = []string{"native-action", "bootstrap-action"}
			proof.ActionHistoryComplete = true
			off := map[string]any{"server": map[string]any{"id": settle.ResourceID, "created_at": settle.ResourceCreatedAt, "status": "off", "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}}
			offWire, _ := json.Marshal(off)
			if _, e = db.Exec(`INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, uuid.NewString(), retirementID, capacity.BusinessCreationSHA256(offWire), offWire, string(offWire)); e != nil {
				t.Fatal("synthetic native off", e)
			}
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			parent, e := readCompensationRecord(ctx, tx, policy, p, grant.GrantID, false)
			if e != nil {
				t.Fatal(e)
			}
			if e = store.guestFailedCreateCleanupTx(ctx, tx, p, parent, proof, time.Now().UTC(), ""); e != nil {
				t.Fatal("real cleanup evidence guard", e)
			}
			_ = tx.Rollback()
			var desired model.CapacityMutationSpecV1
			if e = json.Unmarshal(plans[failedSlot].DesiredSpec, &desired); e != nil {
				t.Fatal(e)
			}
			desired.Capability = mutation.DestroyCapability
			desired.ExpectedResourceID = settle.ResourceID
			desired.ExpectedResourceCreatedAt = settle.ResourceCreatedAt
			desiredRaw, _ := json.Marshal(desired)
			zero := 0
			drain := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:never-routed-and-complete-floor", Healthy: true, MembershipComplete: true, AdmissionClosed: true, RoutingWithdrawn: true, Inflight: &zero, NativeActionsInflight: &zero}
			issue := model.CapacityCompensationIssue{ParentGrantID: grant.GrantID, Mutation: model.CapacityMutationIssue{BindingName: mutation.Name, DesiredSpec: desiredRaw}, FailedProof: proof, DrainProof: drain}
			if _, e = store.IssueCompensation(ctx, policy, issue); e == nil {
				t.Fatal("disabled compensation accepted")
			}
			if _, e = db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, policy.Metadata.Namespace, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); e != nil {
				t.Fatal(e)
			}
			recovery := store
			recovery.ExecutionEnabled = false
			recovery.ExecutorID = uuid.NewString()
			lease, e := recovery.Recover(ctx, policy, intent.Generation, freshCapacityTestAssessment(a, 4))
			if e != nil {
				t.Fatal("recovery", e)
			}
			if _, e = recovery.IssueMutation(ctx, policy, intent.Generation, lease.FencingToken, lease.LeaseOwner, plans[6]); e == nil {
				t.Fatal("recovery issued new create")
			}
			p.MutationBindings[0].CompensationEnabled = true
			rawPolicy, _ := json.Marshal(p)
			current, e := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: policy.APIVersion, Kind: policy.Kind, Metadata: model.ManifestMetadataInput{Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name}, Spec: rawPolicy}, capacity.BusinessCreationSHA256(rawPolicy))
			if e != nil {
				t.Fatal(e)
			}
			issuer := store
			issuer.ExecutorID = uuid.NewString()
			check, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			parent, e = readCompensationRecord(ctx, check, current, p, grant.GrantID, false)
			if e != nil {
				t.Fatal(e)
			}
			t.Log("parent state", parent.Grant.State, "same binding", sameCompensationBinding(p.MutationBindings[0], parent.Binding), "proof", validFailedCreationProof(p, parent, proof, time.Now().UTC()), "cleanup", issuer.guestFailedCreateCleanupTx(ctx, check, p, parent, proof, time.Now().UTC(), ""), "drain", validateCompensationDrain(ctx, check, current.Metadata.Namespace, p, drain, time.Now().UTC(), parent.Generation))
			_ = check.Rollback()
			child, e := issuer.IssueCompensation(ctx, current, issue)
			if e != nil {
				t.Fatal("real IssueCompensation", e)
			}
			if child.CompensationOf != grant.GrantID {
				t.Fatal("wrong compensation lineage")
			}
			childNonce := uuid.NewString()
			childRedeem := mutationRedeem(child, childNonce)
			permit, e := issuer.RedeemMutation(ctx, mutation.AdapterPrincipalID, childRedeem)
			if e != nil || permit.Mode != "write_once" {
				t.Fatal("child redeem", permit, e)
			}
			again, e := issuer.RedeemMutation(ctx, mutation.AdapterPrincipalID, childRedeem)
			if e != nil || again.Mode != "read_only" {
				t.Fatal("child replay", again, e)
			}
			deleted := proof
			deleted.GrantID = child.GrantID
			deleted.RequestSHA256 = child.RequestSHA256
			deleted.ActionsSuccessful = true
			deleted.ActionsFailed = false
			deleted.ResourceAbsent = true
			deleted.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture"}}
			if _, e = issuer.ConfirmCompensation(ctx, current, deleted); e == nil {
				t.Fatal("absence alone confirmed")
			}
			childSettle := mutationSettlement(childRedeem, settle.ResourceCreatedAt)
			childSettle.ResourceID = settle.ResourceID
			if _, e = issuer.SettleMutation(ctx, mutation.AdapterPrincipalID, childNonce, childSettle); e != nil {
				t.Fatal("child settlement", e)
			}
			receiptAfter, e := issuer.MutationReceipt(ctx, mutation.AdapterPrincipalID, child.GrantID)
			if e != nil {
				t.Fatal(e)
			}
			observedAt := time.Now().UTC().Format(time.RFC3339Nano)
			native := model.CapacityVMRetirementObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: child.ExpectedResourceID, CreatedAt: child.ExpectedResourceCreatedAt}, DestroyGrantID: child.GrantID, DestroyGrantState: "settled", CompensationOf: grant.GrantID, OriginalOutcome: "accepted", OriginalTransportCompleted: true, ServerAbsent: true, ServerAbsenceComplete: true, ServerObservedAt: observedAt, DeleteAction: model.CapacityVMRetirementAction{Known: true, Observed: true, ID: childSettle.ActionID, Status: "success", Command: "delete_server", StartedAt: observedAt, FinishedAt: observedAt}, NextActions: []model.CapacityVMActionObservation{{ID: "bootstrap-action", Status: "success", Command: "delete_server", ResourceID: child.ExpectedResourceID, StartedAt: observedAt, FinishedAt: observedAt, ObservedAt: observedAt}}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "ip-fixture", Absent: true, ObservedAt: observedAt}}, AuxiliaryInventoryComplete: true, BillableResourcesAbsent: true, RetirementComplete: true, HoldReasons: []string{}, ObservationStartedAt: observedAt, ObservedAt: observedAt}
			native.BillingExposure = &model.CapacityVMBillingExposure{Basis: "profile_admission_ceiling_not_invoice", Currency: capacity.NativeBillingCurrency(p), WindowStart: child.ExpectedResourceCreatedAt, WindowEndUpperBound: observedAt, WindowEndSource: "native_delete_action_finished", Resources: []model.CapacityVMBillableResourceWindow{{Kind: "server", ID: child.ExpectedResourceID, WindowStart: child.ExpectedResourceCreatedAt, WindowStartSource: "native_server_created_at", WindowEndUpperBound: observedAt, WindowEndSource: "native_delete_action_finished", StartedHoursUpperBound: 1}, {Kind: "primary_ip", ID: "ip-fixture", WindowStart: child.ExpectedResourceCreatedAt, WindowStartSource: "server_creation_proxy_not_native_ip_creation", WindowEndUpperBound: observedAt, WindowEndSource: "first_complete_absence_observation", StartedHoursUpperBound: 1}}, StartedHoursUpperBound: 1, CalendarMonthsUpperBound: 1, ExcludedCosts: []string{"test only"}}
			if e = recovery.RecordVMRetirementReadback(ctx, policy, intent.Generation, lease.FencingToken, lease.LeaseOwner, native); e != nil {
				t.Fatal("real readback writer", e)
			}
			deleted, e = capacity.VMRetirementProof(p, p.MutationBindings[0], receiptAfter, native, time.Now().UTC(), "fixture:native-read")
			if e != nil {
				t.Fatal("synthetic native proof", e)
			}
			missing := deleted
			missing.AuxiliaryAbsent = nil
			if _, e = issuer.ConfirmCompensation(ctx, current, missing); e == nil {
				t.Fatal("missing auxiliary admitted")
			}
			confirmed, e := issuer.ConfirmCompensation(ctx, current, deleted)
			if e != nil || confirmed.State != "confirmed" {
				t.Fatal("real ConfirmCompensation", confirmed, e)
			}
		})
	}
}

// Declared source-owned SQL input. It never observes an actual Guest or host.
// RecordGuestObservation and RecordGuestCallerReturn are the real methods.
func syntheticRetirement(t *testing.T, ctx context.Context, db *sql.DB, store CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding, pre model.CapacityGuestOriginalProvisioningPreregistration, witness model.CapacityGuestOriginalCreateWitness, reg model.CapacityGuestOriginalProvisioningRegistration, receipt model.CapacityGuestOriginalProvisioningReceipt, epoch model.CapacityIntent) string {
	t.Helper()
	wire := func(x any) []byte {
		t.Helper()
		v, e := json.Marshal(x)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	must := func(q string, args ...any) {
		t.Helper()
		if _, e := db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal("synthetic record", e)
		}
	}
	witnessWire := wire(witness)
	must(`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, pre.PreregistrationID, witness.OriginalCreateAttemptID, capacity.GuestRetirementSHA(witness.Tuple), capacity.GuestRetirementSHA(witness), witnessWire, string(witnessWire), witness.ObservedAt)
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, pre.PreregistrationID, capacity.GuestRetirementSHA(receipt.Enrollment.Statement.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(wire(receipt.Enrollment)), receipt.RecordedAt, wire(reg), wire(receipt))
	// Times are fixture data with strictly ordered actual validation bounds.
	start := time.Now().UTC().Truncate(time.Microsecond).Add(40 * time.Millisecond)
	stamp := func(ms int) time.Time { return start.Add(time.Duration(ms) * time.Millisecond) }
	e := receipt.Enrollment
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	i := model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, BindingName: pre.BindingName, Slot: pre.Slot, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), NonceSHA256: strings.Repeat("a", 64), EnrollmentSHA256: capacity.GuestRetirementSHA(e), Tuple: e.Statement.Tuple, Actor: e.Statement.Actor, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: store.WorkflowID.String(), WorkflowChecksum: pre.WorkflowChecksum, Generation: uint64(epoch.Generation), Fence: uint64(epoch.FencingToken), LeaseOwner: epoch.LeaseOwner, WithdrawOperationID: uuid.NewString(), WithdrawRequestSHA256: strings.Repeat("d", 64), DrainOperationID: uuid.NewString(), DrainRequestSHA256: strings.Repeat("e", 64), IssuedAt: start, OriginalDeadline: start.Add(30 * time.Second)}
	r := model.CapacityGuestRetirementRequest{Intent: i}
	r.Signature, _ = capacity.GuestLifecycleSignature(core, i)
	if err := capacity.GuestRetirementRequest(r, e, start, false); err != nil {
		t.Fatal("signed retirement request", err)
	}
	must(`INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at,original_wire) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, i.RequestID, pre.PreregistrationID, i.AttemptID, i.NonceSHA256, capacity.GuestRetirementSHA(i), string(wire(i)), i.OriginalDeadline, i.IssuedAt, wire(r))
	must(`INSERT INTO public.capacity_guest_original_retirement_contexts(intent_id,executor_id,original_step_id,original_step_timeout_seconds,original_context_deadline,core_actual_source_commit,recorded_at) VALUES($1,$2,'synthetic-retire',60,$3,$4,$5)`, i.RequestID, store.ExecutorID, i.OriginalDeadline, capacity.CurrentGuestCoreSource(), i.IssuedAt)
	must(`INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,$4,$5,$6)`, i.RequestID, i.AttemptID, capacity.GuestRetirementSHA(r), b.Members[pre.Slot-1].ActorClientPrincipal, i.IssuedAt, i.OriginalDeadline)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.recordGuestAuthorityIssueTx(ctx, tx, policy, p, b, "retirement_intent", i.RequestID, capacity.GuestRetirementSHA(i)); err != nil {
		t.Fatal("audit", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	writer := e.Statement.Writers[0]
	census := func(ms int, processes []model.CapacityGuestRetirementNativeProcess) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: processes, RawCensusSHA256: digest, ObservedAt: stamp(ms)}
	}
	runtime := model.CapacityGuestRetirementRuntimeReturn{Schema: capacity.GuestRetirementSchema, IntentSHA256: capacity.GuestRetirementSHA(i), AttemptID: i.AttemptID, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, WithdrawRequestSHA256: i.WithdrawRequestSHA256, DrainRequestSHA256: i.DrainRequestSHA256, UnknownWriters: []string{}, ReturnedAt: stamp(41)}
	runtime.Withdraw = model.CapacityGuestRetirementOriginalOperation{OperationID: i.WithdrawOperationID, RequestSHA256: i.WithdrawRequestSHA256, ResultSHA256: digest, StartedAt: stamp(33), OriginalReturnedAt: stamp(34), Outcome: "returned"}
	runtime.Drain = model.CapacityGuestRetirementOriginalOperation{OperationID: i.DrainOperationID, RequestSHA256: i.DrainRequestSHA256, ResultSHA256: digest, StartedAt: stamp(35), OriginalReturnedAt: stamp(39), Outcome: "returned"}
	runtime.CensusBefore = census(32, []model.CapacityGuestRetirementNativeProcess{{PID: writer.Lifetime.PID, StartTicks: writer.Lifetime.StartTicks}})
	runtime.CensusAfter = census(40, []model.CapacityGuestRetirementNativeProcess{})
	runtime.Writers = []model.CapacityGuestRetirementWriterReturn{{Writer: writer, AdmissionClosedAt: stamp(32), OriginalWithdrawReturnedAt: stamp(34), OriginalWorkersJoinedAt: stamp(38), OriginalConnectionsJoinedAt: stamp(38), OriginalResultSHA256: digest, Outcome: "joined"}}
	op := model.CapacityGuestRetirementOperationReturn{StartedAt: stamp(31), PID: 200, StartTicks: 201, WaitReturnedAt: stamp(42), ExitCode: 0, BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	offStart := stamp(65)
	power := model.CapacityGuestRetirementOperationReturn{StartedAt: stamp(66), PID: 210, StartTicks: 211, WaitReturnedAt: stamp(69), ExitCode: 0, BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	record := model.CapacityGuestRetirementRecord{Schema: capacity.GuestRetirementSchema, Sequence: 1, State: "possible_start", Intent: i, IntentSHA256: capacity.GuestRetirementSHA(i), EnrollmentSHA256: capacity.GuestRetirementSHA(e), PossibleStartAt: stamp(19), RecordedAt: stamp(20), WriterQuiescenceScope: "enrolled_roster_only"}
	var observations []model.CapacityGuestRetirementObservation
	for n := 1; n <= 4; n++ {
		if n > 1 {
			record.PreviousSHA256 = observations[n-2].RecordSHA256
			record.Sequence = n
			record.RuntimeOperation = &op
			record.RuntimeReturn = &runtime
			record.WriterQuiescenceEvidence = true
			record.RecordedAt = stamp(45)
			record.State = "quiescent"
		}
		if n >= 3 {
			record.State = "poweroff_possible_start"
			record.PoweroffPossibleStartAt = &offStart
			record.RecordedAt = stamp(65)
		}
		if n == 4 {
			record.State = "poweroff_command_returned"
			record.PoweroffOperation = &power
			record.PoweroffCommandReturned = true
			record.RecordedAt = stamp(70)
		}
		observed := model.CapacityGuestRetirementObservation{Schema: capacity.GuestRetirementSchema, Record: record, RecordSHA256: capacity.GuestRetirementSHA(record), JournalComplete: true, HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: stamp([]int{25, 50, 68, 75}[n-1])}
		observed.Signature, _ = capacity.GuestLifecycleSignature(observer, observed)
		if err = capacity.GuestRetirementObservation(observed, e, i, observed.ObservedAt, false); err != nil {
			t.Fatalf("synthetic signed record %d: %v", n, err)
		}
		observations = append(observations, observed)
	}
	time.Sleep(150 * time.Millisecond)
	for _, observed := range observations {
		if err = store.RecordGuestObservation(ctx, i.RequestID, observed); err != nil {
			t.Fatal("real RecordGuestObservation", err)
		}
	}
	body := wire(observations[3])
	sha := capacity.BusinessCreationSHA256(body)
	call := GuestOriginalCallerReturn{RequestID: i.RequestID, AttemptID: i.AttemptID, StartedAt: stamp(1), DoStartedAt: stamp(2), DoReturnedAt: stamp(80), ReadReturnedAt: stamp(81), CloseReturnedAt: stamp(82), DriverReturnedAt: stamp(83), OriginalDeadline: i.OriginalDeadline, ReceivedBodyBytes: len(body), BodyPersisted: true, Body: body, Status: 200, ResponseSHA256: sha, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(body), RetainedPrefixSHA256: sha}
	if err = store.RecordGuestCallerReturn(ctx, call); err != nil {
		t.Fatal("real RecordGuestCallerReturn", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	loaded, err := loadGuestRetirementTx(ctx, tx, i.RequestID)
	if err != nil {
		t.Fatal("real retirement load", err)
	}
	if _, err = guestQuiescentProofTx(ctx, tx, loaded); err != nil {
		t.Fatal("signed retirement chain", err)
	}
	return i.RequestID
}
