package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"path/filepath"
	"strconv"
)

// DECLARED historical storage operands in the existing isolated Unix-socket
// PostgreSQL gate. Replica-mode construction precedes the first tested guard;
// it is not a signed Guest/provider execution or a production qualification.
// Every exercised disposition, CAS, refusal and immutable/deferred guard is real.
type httpMaintenanceFixture struct {
	unknownMaintenanceFixture
	prior  uuid.UUID
	canary uuid.UUID
	policy model.Manifest
	spec   model.CapacityPolicySpec
}

func httpMaintenanceDisposableDB(t *testing.T, parent *sql.DB) *sql.DB {
	t.Helper()
	// The parent has already passed originalDispositionPG's explicit Unix socket,
	// named disposable database and opt-in checks. Never consume generic DB_URL.
	var parentName string
	var local bool
	var major int
	if err := parent.QueryRow(`SELECT current_database(),inet_server_addr() IS NULL,current_setting('server_version_num')::int/10000`).Scan(&parentName, &local, &major); err != nil || !local || !strings.HasPrefix(parentName, "original_disposition_test_") || (major != 16 && major != 17) {
		t.Fatal("disposable parent identity", err, parentName, local, major)
	}
	name := "original_disposition_test_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := parent.Exec(`CREATE DATABASE ` + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", os.Getenv("ORIGINAL_CREATE_DISPOSITION_PG_DSN")+" dbname="+name)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(6)
	t.Cleanup(func() {
		_ = db.Close()
		if _, err := parent.Exec(`DROP DATABASE ` + pq.QuoteIdentifier(name) + ` WITH (FORCE)`); err != nil {
			t.Error("disposable HTTP fixture cleanup", err)
		}
	})
	var actual string
	if err = db.QueryRow(`SELECT current_database(),inet_server_addr() IS NULL`).Scan(&actual, &local); err != nil || actual != name || !local {
		t.Fatal("new disposable database differs", err, actual, local)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = goose.UpContext(ctx, db, "../db/migrations"); err != nil {
		t.Fatal("actual full migration91", err)
	}
	var version int64
	if err = db.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != 91 {
		t.Fatal("exact schema91 required", err, version)
	}
	return db
}

func httpMaintenancePGFixture(t *testing.T, parent *sql.DB, provider string) httpMaintenanceFixture {
	t.Helper()
	if provider != "aws" && provider != "hetzner" {
		t.Fatal("closed provider")
	}
	db := httpMaintenanceDisposableDB(t, parent)
	var p model.CapacityPolicySpec
	raw, err := os.ReadFile("../internal/capacity/testdata/b509-notify-" + provider + "-production-contract.json")
	if err != nil || json.Unmarshal(raw, &p) != nil {
		t.Fatal("public complete contract fixture", err)
	}
	p.MinSamples = 60
	if err = capacity.ValidatePolicy(p); err != nil || !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(p)) {
		t.Fatal("declared complete contract", err)
	}
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	lease := start.Add(5 * time.Minute)
	returned := start.Add(15 * time.Second)
	e := abandonedDispatchEnvelope(t, "dakasa-production", start.Format(time.RFC3339Nano))
	e.Dimension = p.Dimension
	e.Workflow.Namespace, e.Workflow.Name = p.Workflow.Namespace, p.Workflow.Name
	envelope, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	prior, pre, grant, id := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	priorChecksum := capacityDispatchSHA([]byte(prior.String()))
	priorSpec := p
	priorSpec.MinSamples = 61
	b := p.MutationBindings[0]
	old := start.Add(-time.Hour)
	created := start.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	resource := "1"
	if provider == "aws" {
		resource = "i-00000000000000001"
	}
	ids := []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"}
	ops := []string{"capacity.plan_original_guest", "capacity.provision_original_guest", "capacity.retire_original_guest", "capacity.complete_original_guest", "capacity.complete_original_guest", "capacity.finish_original_guest_retirement", "capacity.complete_original_guest"}
	steps := []map[string]any{}
	for i, step := range ids {
		v := map[string]any{"id": step, "kind": "yggdrasil", "operation": ops[i], "capability": ops[i], "status": "skipped"}
		if i == 0 {
			v["status"], v["attempts"], v["metadata"] = "succeeded", 1, map[string]any{"mode": "refresh", "slot": 0, "reason": "capacity_boundary", "generation": 8, "fencing_token": 21, "lease_owner": "", "preregistration_id": ""}
		}
		if i == 3 {
			v["status"], v["attempts"], v["error"], v["metadata"] = "failed", 1, "original Guest reconciliation held", map[string]any{"original_guest_reconcile_refusal_stage": "fresh_original_canary", "original_guest_notify_refusal_stage": "original_HTTP_or_return"}
		}
		steps = append(steps, v)
	}
	result := mustEncodeJSON(map[string]any{"status": "failed", "workflow": map[string]any{"id": e.Workflow.ID, "kind": "workflow", "namespace": e.Workflow.Namespace, "name": e.Workflow.Name, "version": e.Workflow.Version}, "steps": steps}, "{}")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`SET LOCAL session_replication_role=replica`)
	must(`INSERT INTO workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,error,result,inputs,metadata,updated_at) VALUES($1,'failed',$2,$3,$4,$5,$6,'capacity dispatch original context refused',$7::jsonb,$8::jsonb,$9::jsonb,$6)`, e.RunID, e.Workflow.Namespace, e.Workflow.Name, e.Workflow.Version, start, returned, result, mustEncodeJSON(e.Inputs, "{}"), mustEncodeJSON(e.Metadata, "{}"))
	must(`INSERT INTO capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_error,pending_wake_count,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed','capacity dispatch original context refused','capacity dispatch original context refused',32,$14)`, e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), owner, lease, start, returned)
	for _, pin := range []struct {
		kind string
		p    CapacityDispatchManifestPin
	}{{"capacity_policy", e.Policy}, {"workflow", e.Workflow}, {"rbac", e.RBAC}} {
		spec := "{}"
		if pin.kind == "capacity_policy" {
			spec = mustEncodeJSON(p, "{}")
		}
		must(`INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,$5,$6,$7::jsonb,true)`, pin.p.ID, pin.kind, pin.p.Namespace, pin.p.Name, pin.p.Version, pin.p.Checksum, spec)
	}
	must(`INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,false)`, prior, e.Policy.Namespace, e.Policy.Name, e.Policy.Version-1, priorChecksum, mustEncodeJSON(priorSpec, "{}"))
	intent := map[string]any{"policy_id": e.Policy.ID, "policy_checksum": e.Policy.Checksum, "generation": 8, "fencing_token": 21, "phase": "promoted", "decision": map[string]any{"action": "hold", "reason": "capacity_boundary", "execution_permitted": false}}
	must(`INSERT INTO capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,8,21,'promoted','declared-http-maintenance',$5)`, e.Realm, e.Environment, e.Domain, e.Dimension, old)
	must(`INSERT INTO capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, e.Realm, e.Environment, e.Domain, e.Dimension, mustEncodeJSON(intent, "{}"), start.Add(1400*time.Millisecond))
	slot := map[string]any{"binding_name": b.Name, "profile_name": b.ProfileName, "desired_spec_sha256": b.Slots[0].DesiredSpecSHA256, "resource_id": resource, "resource_created_at": created, "receipt_ref": "original-guest-reconcile:declared", "observed_at": start.Add(2100 * time.Millisecond), "tombstone": false}
	must(`INSERT INTO capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9::jsonb,281,$10)`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, e.Realm, e.Environment, e.Domain, e.Dimension, resource, mustEncodeJSON(slot, "{}"), start.Add(3*time.Second))
	must(`INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,8,$6,$7,$8,1,'confirmed',jsonb_build_object('created_at',$9::timestamptz),$10,$9)`, grant, e.Realm, e.Environment, e.Domain, e.Dimension, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, old, old.Add(time.Minute))
	pr := map[string]any{"slot": 1, "policy_id": prior, "policy_checksum": priorChecksum, "workflow_id": e.Workflow.ID, "workflow_checksum": e.Workflow.Checksum, "generation": 8, "fence": 21}
	digest := capacityDispatchSHA([]byte(pre.String()))
	must(`INSERT INTO capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, pre, grant, digest, p.GuestRetirementBinding.ProfileManifestSHA256, mustEncodeJSON(pr, "{}"), old.Add(time.Minute), old)
	enrollment := mustEncodeJSON(map[string]any{"statement": map[string]any{"tuple": map[string]any{"resource_id": resource, "resource_created_at": created}}}, "{}")
	must(`INSERT INTO capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$2,$2,$3::jsonb,$4)`, pre, digest, enrollment, old)
	must(`INSERT INTO capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,'{}'::bytea,$2,$3)`, pre, digest, old)
	at := start.Add(4 * time.Second)
	deadline := at.Add(5 * time.Second)
	record := mustEncodeJSON(map[string]any{"schema": "guest_notify_business_canary_publish_challenge_v1", "issued_at": at, "original_deadline": deadline, "usage_class": "steady_useful_membership", "policy_checksum": e.Policy.Checksum, "workflow_checksum": e.Workflow.Checksum}, "{}")
	nonce := []byte(`{"declared_nonce":"` + id.String() + `"}`)
	final := []byte(`{"declared_final_challenge":"` + id.String() + `"}`)
	must(`INSERT INTO capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$1,'publish',$3,$4,8,21,'declared-fixture','declared-fixture',$5,$6,$7,$8::jsonb,$9,$10)`, id, pre, e.Policy.ID, e.Workflow.ID, capacityDispatchSHA([]byte(record)), capacityDispatchSHA(nonce), []byte(record), record, deadline, at)
	must(`INSERT INTO capacity_guest_notify_canary_nonces(challenge_id,guest_nonce_sha256,nonce_wire,final_challenge_wire,final_challenge_sha256,original_transport,recorded_at) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6)`, id, capacityDispatchSHA(nonce), nonce, final, capacityDispatchSHA(final), at.Add(time.Millisecond))
	must(`INSERT INTO capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, id, capacityDispatchSHA(final), at.Add(time.Second), deadline)
	must(`INSERT INTO capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'held',$2,NULL,'{}'::jsonb,$3)`, id, capacityDispatchSHA([]byte(id.String()+"held")), at.Add(2*time.Second))
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	base := abandonedDispatchFixture{db: db, envelope: e, start: start, lease: lease, request: CapacityDispatchAbandonedDispositionRequest{JobID: e.JobID, ExpectedRunID: e.RunID, ExpectedEnvelopeSHA256: capacityDispatchSHA(envelope), ExpectedFencingToken: 1, ExpectedLeaseOwner: owner, ExpectedPendingWakeCount: 32, Issuer: "collaborator:" + uuid.NewString()}, barrier: CapacityDispatchExecutorBarrier{ProcessStartedAt: lease.Add(time.Minute), Hostname: "declared-http-fixture", PID: 4242, SourceCommit: strings.Repeat("a", 40)}}
	oldFixture := unknownMaintenanceFixture{abandonedDispatchFixture: base, returned: returned, pre: pre}
	policy := model.Manifest{ID: e.Policy.ID, Kind: "capacity_policy", Version: e.Policy.Version, Checksum: e.Policy.Checksum, Metadata: model.ManifestMetadata{Namespace: e.Policy.Namespace, Name: e.Policy.Name}, Spec: json.RawMessage(mustEncodeJSON(p, "{}"))}
	out := httpMaintenanceFixture{unknownMaintenanceFixture: oldFixture, prior: prior, canary: id, policy: policy, spec: p}
	var admitted, tolerable bool
	if err = db.QueryRow(`SELECT public.http_maintenance_dispatch_admission_valid($1),public.http_maintenance_dispatch_effect_scan_tolerable(public.http_maintenance_dispatch_effect_scan($1))`, e.JobID).Scan(&admitted, &tolerable); err != nil || !admitted || !tolerable {
		t.Fatal("positive declared fixture admission required before any negative", err, admitted, tolerable)
	}
	return out
}

func (f httpMaintenanceFixture) requestHTTP(t *testing.T) CapacityDispatchHTTPMaintenanceDispositionRequest {
	t.Helper()
	r := CapacityDispatchHTTPMaintenanceDispositionRequest{CapacityDispatchUnknownMaintenanceDispositionRequest: CapacityDispatchUnknownMaintenanceDispositionRequest{CapacityDispatchAbandonedDispositionRequest: f.request, ExpectedReturnedAt: f.returned}}
	if err := f.db.QueryRow(`SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),encode(sha256(convert_to(public.http_maintenance_dispatch_members(j.id)::text,'UTF8')),'hex') FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.envelope.JobID).Scan(&r.ExpectedRunSHA256, &r.ExpectedMembersSHA256); err != nil {
		t.Fatal(err)
	}

	return r
}
func (f httpMaintenanceFixture) canarySnapshot(t *testing.T) string {
	t.Helper()
	var raw string
	if err := f.db.QueryRow(`SELECT jsonb_build_object('challenge',to_jsonb(c),'nonce',to_jsonb(n),'send',to_jsonb(s),'return',to_jsonb(r))::text FROM capacity_guest_notify_canary_challenges c LEFT JOIN capacity_guest_notify_canary_nonces n ON n.challenge_id=c.id LEFT JOIN capacity_guest_notify_canary_sends s ON s.challenge_id=c.id LEFT JOIN capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.id=$1`, f.canary).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f httpMaintenanceFixture) assertHTTPUntouched(t *testing.T, j, w, c string) {
	t.Helper()
	aj, aw := f.snapshot(t)
	var rows int
	if err := f.db.QueryRow(`SELECT count(*) FROM capacity_dispatch_http_maintenance_dispositions WHERE job_id=$1`, f.envelope.JobID).Scan(&rows); err != nil || rows != 0 || aj != j || aw != w || f.canarySnapshot(t) != c {
		t.Fatal("refusal changed immutable originals", err, rows)
	}
}

func TestHTTPMaintenanceDispatchPostgresLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			f := httpMaintenancePGFixture(t, db, provider)
			request := f.requestHTTP(t)
			beforeJob, beforeRun := f.snapshot(t)
			beforeCanary := f.canarySnapshot(t)
			var oldOK bool
			if err := f.db.QueryRow(`SELECT public.unknown_maintenance_dispatch_effect_scan_tolerable(public.unknown_maintenance_dispatch_effect_scan($1))`, f.envelope.JobID).Scan(&oldOK); err != nil || oldOK {
				t.Fatal("87 must still refuse this class", oldOK, err)
			}
			calls := 0
			v, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, request, f.barrier, func(context.Context) error { calls++; return nil })
			if err != nil || calls != 2 || v.State != "http_maintenance_disposed" || v.HistoricalReturn != "unknown" || v.OriginalRunSHA256 != request.ExpectedRunSHA256 {
				t.Fatal("HTTP maintenance disposition", err, calls, v)
			}
			afterJob, afterRun := f.snapshot(t)
			var a, b map[string]json.RawMessage
			if json.Unmarshal([]byte(beforeJob), &a) != nil || json.Unmarshal([]byte(afterJob), &b) != nil {
				t.Fatal("job JSON")
			}
			for _, k := range []string{"state", "updated_at"} {
				delete(a, k)
				delete(b, k)
			}
			if mustEncodeJSON(a, "{}") != mustEncodeJSON(b, "{}") || beforeRun != afterRun || beforeCanary != f.canarySnapshot(t) {
				t.Fatal("original job/run/canaries changed")
			}
			got, err := ReadCapacityDispatchHTTPMaintenanceDisposition(context.Background(), f.db, f.envelope.JobID)
			if err != nil || got.ID != v.ID {
				t.Fatal("lost response readback", err)
			}
			if _, err = DisposeHTTPMaintenanceDispatch(context.Background(), f.db, request, f.barrier, abandonedAllow); err == nil {
				t.Fatal("duplicate POST accepted")
			}
			// Historical receipt stays readable after a later policy publication.
			f.mutate(t, `UPDATE manifests SET active=false WHERE id=$1`, f.policy.ID)
			if _, err = ReadCapacityDispatchHTTPMaintenanceDisposition(context.Background(), f.db, f.envelope.JobID); err != nil {
				t.Fatal("historical receipt depended on current policy", err)
			}
		})
	}
}

func TestHTTPMaintenanceDispatchPostgresRefusals(t *testing.T) {
	db := originalDispositionPG(t)
	cases := []struct{ name, sql string }{
		{"wrong_realm", `UPDATE capacity_dispatch_jobs SET realm='foreign' WHERE id=$1`},
		{"foreign_workflow_uuid", `UPDATE workflow_runs SET workflow_id=(SELECT id FROM manifests WHERE kind='rbac') WHERE id=$2`},
		{"wrong_error", `UPDATE capacity_dispatch_jobs SET return_error='capacity dispatch original deadline exceeded' WHERE id=$1`},
		{"missing_finalization_error", `UPDATE capacity_dispatch_jobs SET finalization_error=NULL WHERE id=$1`},
		{"different_finalization_error", `UPDATE capacity_dispatch_jobs SET finalization_error='other' WHERE id=$1`},
		{"ack_present", `UPDATE capacity_dispatch_jobs SET finalization_ack_at=returned_at WHERE id=$1`},
		{"unexpired_lease", `UPDATE capacity_dispatch_jobs SET lease_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`},
		{"wrong_plan_reason", `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,0,metadata,reason}','"signal_evidence_unavailable"') WHERE id=$2`},
		{"other_refusal_stage", `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,3,metadata,original_guest_notify_refusal_stage}','"reserve_send"') WHERE id=$2`},
		{"retire_executed", `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,2,status}','"succeeded"') WHERE id=$2`},
		{"owner_present", `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,0,metadata,lease_owner}','"forged"') WHERE id=$2`},
		{"request_present", `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,0,metadata,request_id}','"forged"') WHERE id=$2`},
		{"epoch_changed", `UPDATE capacity_intents SET intent=jsonb_set(intent,'{generation}','9') WHERE namespace=$3`},
		{"pending_forward", `UPDATE capacity_intents SET intent=jsonb_set(intent,'{retirement_forward}','{}') WHERE namespace=$3`},
		{"pending_disposal", `UPDATE capacity_intents SET intent=jsonb_set(intent,'{failed_serving_disposal}','{}') WHERE namespace=$3`},
		{"accepted_return", `UPDATE capacity_guest_notify_canary_returns SET outcome='accepted',original_wire='{}'::bytea WHERE challenge_id=$4`},
		{"unexpected_return_wire", `UPDATE capacity_guest_notify_canary_returns SET original_wire='{}'::bytea WHERE challenge_id=$4`},
		{"unexpected_business", `UPDATE capacity_guest_notify_canary_returns SET business_observation='{}'::jsonb WHERE challenge_id=$4`},
		{"missing_nonce", `DELETE FROM capacity_guest_notify_canary_nonces WHERE challenge_id=$4`},
		{"missing_send", `DELETE FROM capacity_guest_notify_canary_sends WHERE challenge_id=$4`},
		{"missing_return", `DELETE FROM capacity_guest_notify_canary_returns WHERE challenge_id=$4`},
		{"late_nonce", `UPDATE capacity_guest_notify_canary_nonces SET recorded_at=(SELECT lease_expires_at FROM capacity_dispatch_jobs WHERE id=$1) WHERE challenge_id=$4`},
		{"late_return", `UPDATE capacity_guest_notify_canary_returns SET recorded_at=(SELECT lease_expires_at FROM capacity_dispatch_jobs WHERE id=$1) WHERE challenge_id=$4`},
		{"late_send", `UPDATE capacity_guest_notify_canary_sends SET possible_send_at=original_deadline WHERE challenge_id=$4`},
		{"altered_send_deadline", `UPDATE capacity_guest_notify_canary_sends SET original_deadline=original_deadline+interval '1 second' WHERE challenge_id=$4`},
		{"challenge_wire_changed", `UPDATE capacity_guest_notify_canary_challenges SET original_wire='{}'::bytea WHERE id=$4`},
		{"wrong_tuple", `UPDATE capacity_resource_slots SET resource_id='foreign' WHERE namespace=$3`},
		{"slot_authority", `UPDATE capacity_resource_slots SET slot_record=slot_record||'{"authority_kind":"pending"}'::jsonb WHERE namespace=$3`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := httpMaintenancePGFixture(t, db, "hetzner")
			// Existing CHECK constraints reject these states even in replica mode.
			// Require the exact storage refusal, rollback and preservation of all
			// original records before this case can pass.
			constraint := map[string]string{
				"ack_present": "capacity_dispatch_jobs_original_ack_v2_check",
				"late_send":   "capacity_guest_notify_canary_sends_check",
			}[tc.name]
			if constraint != "" {
				j, w := f.snapshot(t)
				c := f.canarySnapshot(t)
				tx, err := f.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.Exec(`SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(`WITH declared_operands AS(SELECT $1::uuid,$2::uuid,$3::text,$4::uuid) `+tc.sql, f.envelope.JobID, f.envelope.RunID, f.envelope.Realm, f.canary)
				var check *pq.Error
				if !errors.As(err, &check) || check.Code != "23514" || check.Constraint != constraint {
					t.Fatal("exact existing CHECK must reject impossible fixture", tc.name, err)
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal("rollback after CHECK refusal", err)
				}
				f.assertHTTPUntouched(t, j, w, c)
				return
			}
			f.mutate(t, `WITH declared_operands AS(SELECT $1::uuid,$2::uuid,$3::text,$4::uuid) `+tc.sql, f.envelope.JobID, f.envelope.RunID, f.envelope.Realm, f.canary)
			j, w := f.snapshot(t)
			c := f.canarySnapshot(t)
			r := f.requestHTTP(t)
			if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, r, f.barrier, abandonedAllow); err == nil {
				t.Fatal("invalid original accepted")
			}
			f.assertHTTPUntouched(t, j, w, c)
		})
	}
}

func TestHTTPMaintenanceDispatchPostgresLineage(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"changed_prior_contract", "changed_intermediate_contract", "prior_newer", "different_name", "different_namespace", "missing_prior", "prior_checksum_forged", "current_inactive", "missing_binding", "malformed_binding", "duplicate_profile"} {
		t.Run(name, func(t *testing.T) {
			f := httpMaintenancePGFixture(t, db, "aws")
			switch name {
			case "changed_prior_contract":
				f.mutate(t, `UPDATE manifests SET spec=jsonb_set(spec,'{guest_retirement_binding,members,0,origin}','"https://foreign.invalid"') WHERE id=$1`, f.prior)
			case "changed_intermediate_contract":
				f.mutate(t, `UPDATE manifests SET version=version-1 WHERE id=$1`, f.prior)
				f.mutate(t, `INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) SELECT $2,'v1',kind,namespace,name,version-1,$3,jsonb_set(spec,'{guest_retirement_binding,members,0,origin}','"https://foreign.invalid"'),false FROM manifests WHERE id=$1`, f.policy.ID, uuid.New(), strings.Repeat("d", 64))
			case "prior_newer":
				f.mutate(t, `UPDATE manifests SET version=version+5 WHERE id=$1`, f.prior)
			case "different_name":
				f.mutate(t, `UPDATE manifests SET name='different' WHERE id=$1`, f.prior)
			case "different_namespace":
				f.mutate(t, `UPDATE manifests SET namespace='different' WHERE id=$1`, f.prior)
			case "missing_prior":
				f.mutate(t, `DELETE FROM manifests WHERE id=$1`, f.prior)
			case "prior_checksum_forged":
				f.mutate(t, `UPDATE capacity_vm_provisioning_preregistrations SET preregistration_record=jsonb_set(preregistration_record,'{policy_checksum}','"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"') WHERE id=$1`, f.pre)
			case "current_inactive":
				f.mutate(t, `UPDATE manifests SET active=false WHERE id=$1`, f.policy.ID)
			case "missing_binding":
				f.mutate(t, `UPDATE manifests SET spec=spec-'guest_retirement_binding' WHERE id=$1`, f.policy.ID)
			case "malformed_binding":
				f.mutate(t, `UPDATE manifests SET spec=jsonb_set(spec,'{guest_retirement_binding}','"invalid"') WHERE id=$1`, f.policy.ID)
			case "duplicate_profile":
				f.mutate(t, `UPDATE manifests SET spec=jsonb_set(spec,'{profiles}',(spec->'profiles')||(spec->'profiles')) WHERE id=$1`, f.policy.ID)
			}
			j, w := f.snapshot(t)
			c := f.canarySnapshot(t)
			if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, f.requestHTTP(t), f.barrier, abandonedAllow); err == nil {
				t.Fatal("invalid lineage accepted")
			}
			f.assertHTTPUntouched(t, j, w, c)
		})
	}
}

func TestHTTPMaintenanceDispatchPostgresCASAndConcurrency(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"member_digest", "run_digest", "envelope_digest", "dispatch_fence", "lease_owner", "wake_count", "returned_at", "old_process", "future_process", "permission_lost"} {
		t.Run(name, func(t *testing.T) {
			f := httpMaintenancePGFixture(t, db, "hetzner")
			r := f.requestHTTP(t)
			b := f.barrier
			calls := 0
			permission := func(context.Context) error {
				calls++
				if name == "permission_lost" && calls == 2 {
					return errors.New("permission withdrawn")
				}
				return nil
			}
			switch name {
			case "member_digest":
				r.ExpectedMembersSHA256 = strings.Repeat("0", 64)
			case "run_digest":
				r.ExpectedRunSHA256 = strings.Repeat("0", 64)
			case "envelope_digest":
				r.ExpectedEnvelopeSHA256 = strings.Repeat("0", 64)
			case "dispatch_fence":
				r.ExpectedFencingToken++
			case "lease_owner":
				r.ExpectedLeaseOwner = uuid.New()
			case "wake_count":
				r.ExpectedPendingWakeCount--
			case "returned_at":
				r.ExpectedReturnedAt = r.ExpectedReturnedAt.Add(time.Microsecond)
			case "old_process":
				b.ProcessStartedAt = f.lease
			case "future_process":
				b.ProcessStartedAt = time.Now().Add(time.Hour)
			}
			j, w := f.snapshot(t)
			c := f.canarySnapshot(t)
			if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, r, b, permission); err == nil {
				t.Fatal("invalid CAS/barrier accepted")
			}
			f.assertHTTPUntouched(t, j, w, c)
		})
	}
	t.Run("one_winner", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "aws")
		r := f.requestHTTP(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, r, f.barrier, abandonedAllow); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatal("exactly one disposition required", wins)
		}
	})
}

func TestHTTPMaintenanceDispatchMigration91Guards(t *testing.T) {
	db := originalDispositionPG(t)
	raw, err := os.ReadFile("../db/migrations/00091_recorded_http_maintenance_dispatch_dispositions.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ADD COLUMN") {
		t.Fatal("migration changed original job shape")
	}
	var total int
	if err = db.QueryRow(`SELECT count(*) FROM pg_attribute WHERE attrelid='capacity_dispatch_jobs'::regclass AND attname='http_maintenance_disposition_id' AND NOT attisdropped`).Scan(&total); err != nil || total != 0 {
		t.Fatal("new pointer column", err, total)
	}
	t.Run("terminal_without_receipt", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "aws")
		j, w := f.snapshot(t)
		c := f.canarySnapshot(t)
		if _, err := f.db.Exec(`UPDATE capacity_dispatch_jobs SET state='http_maintenance_disposed' WHERE id=$1`, f.envelope.JobID); err == nil {
			t.Fatal("unlinked terminal accepted")
		}
		f.assertHTTPUntouched(t, j, w, c)
	})
	t.Run("immutable_and_no_pointer", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "aws")
		if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, f.requestHTTP(t), f.barrier, abandonedAllow); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`UPDATE capacity_dispatch_jobs SET state='unknown' WHERE id=$1`, `UPDATE capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`, `UPDATE capacity_dispatch_http_maintenance_dispositions SET historical_return='succeeded' WHERE job_id=$1`, `DELETE FROM capacity_dispatch_http_maintenance_dispositions WHERE job_id=$1`, `UPDATE workflow_runs SET error='rewritten' WHERE id=(SELECT run_id FROM capacity_dispatch_jobs WHERE id=$1)`, `DELETE FROM workflow_runs WHERE id=(SELECT run_id FROM capacity_dispatch_jobs WHERE id=$1)`} {
			if _, err := f.db.Exec(q, f.envelope.JobID); err == nil {
				t.Fatal("immutable history changed", q)
			}
		}
		var pointers int
		if err := f.db.QueryRow(`SELECT num_nonnulls(failed_original_disposition_id,native_denied_disposition_id,enrolled_failed_disposition_id,abandoned_disposition_id,finalization_lost_disposition_id,unknown_maintenance_disposition_id) FROM capacity_dispatch_jobs WHERE id=$1`, f.envelope.JobID).Scan(&pointers); err != nil || pointers != 0 {
			t.Fatal("old pointer manufactured", err, pointers)
		}
	})
	t.Run("current_workflow_uuid", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "aws")
		f.mutate(t, `UPDATE workflow_runs SET workflow_id=$2 WHERE id=$1`, f.envelope.RunID, f.envelope.Workflow.ID)
		if _, err := DisposeHTTPMaintenanceDispatch(context.Background(), f.db, f.requestHTTP(t), f.barrier, abandonedAllow); err != nil {
			t.Fatal("exact nonnull workflow UUID refused", err)
		}
	})
	t.Run("receipt_without_transition", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "hetzner")
		j, w := f.snapshot(t)
		c := f.canarySnapshot(t)
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`SET LOCAL TIME ZONE 'UTC'`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO capacity_dispatch_http_maintenance_dispositions(id,job_id,run_id,original_dispatch_sha256,original_dispatch_updated_at,original_run_sha256,original_returned_at,current_members_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,issuer,reason,historical_return,recorded_at,provider_mutation_evidence)
   SELECT $1,j.id,j.run_id,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),j.updated_at,encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),j.returned_at,
   public.http_maintenance_dispatch_effect_scan(j.id)->>'current_members_sha256','disposing_core_process_started_after_lease_expiry_v1',$3,'declared-http-fixture',4242,$4,$5,'recorded_context_refused_http_maintenance_dispatch_disposed','unknown',clock_timestamp(),public.http_maintenance_dispatch_effect_scan(j.id)
   FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$2`, uuid.New(), f.envelope.JobID, f.barrier.ProcessStartedAt, f.barrier.SourceCommit, f.request.Issuer); err != nil {
			t.Fatal("positive insert guard refused before deferred test", err)
		}
		if err = tx.Commit(); err == nil {
			t.Fatal("receipt committed without terminal transition")
		}
		f.assertHTTPUntouched(t, j, w, c)
	})
	t.Run("old_r4_up89_after91", func(t *testing.T) {
		f := httpMaintenancePGFixture(t, db, "aws")
		j, w := f.snapshot(t)
		c := f.canarySnapshot(t)
		var historyBefore, historyAfter string
		if err := f.db.QueryRow(`SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`).Scan(&historyBefore); err != nil {
			t.Fatal(err)
		}
		oldFiles := t.TempDir()
		entries, err := os.ReadDir("../db/migrations")
		if err != nil {
			t.Fatal(err)
		}
		copied := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
				continue
			}
			version, err := strconv.ParseInt(strings.SplitN(entry.Name(), "_", 2)[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if version > 89 {
				continue
			}
			raw, err := os.ReadFile(filepath.Join("../db/migrations", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(oldFiles, entry.Name()), raw, 0600); err != nil {
				t.Fatal(err)
			}
			copied++
		}
		if copied != 88 {
			t.Fatal("original R4 1..39+41..89 file roster changed", copied)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err = goose.UpContext(ctx, f.db, oldFiles); err != nil {
			t.Fatal("old R4 <=89 Up against91", err)
		}
		if v, err := goose.GetDBVersionContext(ctx, f.db); err != nil || v != 91 {
			t.Fatal("old view changed schema91", v, err)
		}
		if err := f.db.QueryRow(`SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`).Scan(&historyAfter); err != nil || historyBefore != historyAfter {
			t.Fatal("old Up changed whole91 history", err)
		}
		f.assertHTTPUntouched(t, j, w, c)
		t.Log("R4_SOURCE_MIGRATION_VIEW_88_FILES_UP89_ON91_NOOP_PG_ONLY_NOT_OLD_CONTAINER_EXECUTION")
	})
	t.Run("pre91_literal_equivalence", func(t *testing.T) {
		query, err := os.ReadFile("../ops/http-maintenance/http_maintenance_pre91.sql")
		if err != nil {
			t.Fatal("mandatory Source-derived pre91 SQL absent", err)
		}
		for _, provider := range []string{"aws", "hetzner"} {
			t.Run(provider, func(t *testing.T) {
				for _, state := range []string{"positive", "wrong_realm", "wrong_stage", "discontinuous_policy", "accepted_return"} {
					t.Run(state, func(t *testing.T) {
						f := httpMaintenancePGFixture(t, db, provider)
						if state != "positive" {
							q := ""
							args := []any{}
							switch state {
							case "wrong_realm":
								q = `UPDATE capacity_dispatch_jobs SET realm='foreign' WHERE id=$1`
								args = []any{f.envelope.JobID}
							case "wrong_stage":
								q = `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,3,metadata,original_guest_notify_refusal_stage}','"reserve_send"') WHERE id=$1`
								args = []any{f.envelope.RunID}
							case "discontinuous_policy":
								q = `UPDATE manifests SET spec=jsonb_set(spec,'{guest_retirement_binding,members,0,origin}','"https://foreign.invalid"') WHERE id=$1`
								args = []any{f.prior}
							case "accepted_return":
								q = `UPDATE capacity_guest_notify_canary_returns SET outcome='accepted',original_wire='{}'::bytea WHERE challenge_id=$1`
								args = []any{f.canary}
							}
							f.mutate(t, q, args...)
						}
						tx, err := f.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
						if err != nil {
							t.Fatal(err)
						}
						defer tx.Rollback()
						if _, err = tx.Exec(`SET LOCAL TIME ZONE 'UTC'`); err != nil {
							t.Fatal(err)
						}
						var projected []byte
						if err = tx.QueryRow(string(query), f.envelope.JobID).Scan(&projected); err != nil {
							t.Fatal("canonical pre91 read", err)
						}
						var v struct {
							Admission  bool            `json:"admission"`
							EffectScan json.RawMessage `json:"effect_scan"`
						}
						if json.Unmarshal(projected, &v) != nil || len(v.EffectScan) == 0 {
							t.Fatal("pre91 output shape")
						}
						var admission, equal bool
						if err = tx.QueryRow(`SELECT public.http_maintenance_dispatch_admission_valid($1),public.http_maintenance_dispatch_effect_scan($1)=$2::jsonb`, f.envelope.JobID, string(v.EffectScan)).Scan(&admission, &equal); err != nil || v.Admission != admission || !equal || admission != (state == "positive") {
							t.Fatal("pre91/function91 semantic divergence", err, state, v.Admission, admission, equal)
						}
					})
				}
			})
		}
	})

}
