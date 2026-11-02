package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// DECLARED maintenance histories in the isolated schema87 Unix-socket CI DB.
// Replica mode seeds synthetic historical source shapes only, before guards
// are exercised. No native provider, signed Guest truth or production authority
// is asserted. The disposition, refused writes and atomicity use real guards.
type unknownMaintenanceFixture struct {
	abandonedDispatchFixture
	returned time.Time
	pre      uuid.UUID
}

func unknownMaintenancePGFixture(t *testing.T, db *sql.DB) unknownMaintenanceFixture {
	t.Helper()
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	f.tolerated(t, finalizationLostEffects{})
	e := f.envelope
	ret := f.start.Add(15 * time.Second)
	plan := map[string]any{"mode": "refresh", "slot": 0, "reason": "signal_evidence_unavailable", "generation": 8, "fencing_token": 21, "lease_owner": "", "preregistration_id": ""}
	steps := []map[string]any{}
	ids := []string{"plan-original-guest", "provision-original-notify", "retire-original-guest", "refresh-original-membership", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"}
	ops := []string{"capacity.plan_original_guest", "capacity.provision_original_guest", "capacity.retire_original_guest", "capacity.complete_original_guest", "capacity.complete_original_guest", "capacity.finish_original_guest_retirement", "capacity.complete_original_guest"}
	for i, id := range ids {
		s := map[string]any{"id": id, "kind": "yggdrasil", "operation": ops[i], "capability": ops[i], "status": "skipped"}
		if i == 0 {
			s["status"], s["attempts"], s["metadata"] = "succeeded", 1, plan
		}
		if i == 3 {
			s["status"], s["attempts"], s["error"] = "failed", 1, "original Guest reconciliation held"
			s["metadata"] = map[string]any{"original_guest_reconcile_refusal_stage": "fresh_original_canary", "original_guest_notify_refusal_stage": "nonce_finalize"}
		}
		steps = append(steps, s)
	}
	result := mustEncodeJSON(map[string]any{"status": "failed", "workflow": map[string]any{"id": e.Workflow.ID, "kind": "workflow", "namespace": e.Workflow.Namespace, "name": e.Workflow.Name, "version": e.Workflow.Version}, "steps": steps}, "{}")
	const reason = "capacity dispatch original deadline exceeded"
	if _, err := db.Exec(`UPDATE public.capacity_dispatch_jobs SET state='unknown',returned_at=$2,return_status='failed',return_error=$3,updated_at=$2 WHERE id=$1`, e.JobID, ret, reason); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE public.workflow_runs SET status='failed',error=$2,result=$3::jsonb,finished_at=$4,updated_at=$4 WHERE id=$1`, e.RunID, reason, result, ret); err != nil {
		t.Fatal(err)
	}
	var instance uuid.UUID
	var scope, profile, resource, created string
	if err := db.QueryRow(`SELECT integration_instance_id,scope_checksum,profile_name,resource_id,slot_record->>'resource_created_at' FROM capacity_resource_slots WHERE namespace=$1`, e.Realm).Scan(&instance, &scope, &profile, &resource, &created); err != nil {
		t.Fatal(err)
	}
	pre, grant := uuid.New(), uuid.New()
	old := f.start.Add(-time.Hour)
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
	for _, pin := range []struct {
		kind string
		p    CapacityDispatchManifestPin
	}{{"capacity_policy", e.Policy}, {"workflow", e.Workflow}, {"rbac", e.RBAC}} {
		spec := "{}"
		if pin.kind == "capacity_policy" {
			spec = mustEncodeJSON(map[string]any{"environment": e.Environment, "domain": e.Domain, "dimension": e.Dimension, "guest_notify_reconcile_binding": map[string]any{"mode": "original_guest_notify_reconcile_v1"}}, "{}")
		}
		must(`INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,$5,$6,$7::jsonb,true)`, pin.p.ID, pin.kind, pin.p.Namespace, pin.p.Name, pin.p.Version, pin.p.Checksum, spec)
	}
	must(`UPDATE capacity_intents SET intent=intent||jsonb_build_object('policy_id',$2::text,'policy_checksum',$3::text) WHERE namespace=$1`, e.Realm, e.Policy.ID.String(), e.Policy.Checksum)
	must(`INSERT INTO capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,8,$6,$7,$8,1,'confirmed',jsonb_build_object('created_at',$9::timestamptz),$10,$9)`, grant, e.Realm, e.Environment, e.Domain, e.Dimension, instance, scope, profile, old, old.Add(time.Minute))
	pr := mustEncodeJSON(map[string]any{"slot": 1, "policy_id": e.Policy.ID, "policy_checksum": e.Policy.Checksum, "workflow_id": e.Workflow.ID, "workflow_checksum": e.Workflow.Checksum, "generation": 8, "fence": 21}, "{}")
	digest := capacityDispatchSHA([]byte(pre.String()))
	must(`INSERT INTO capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at) VALUES($1,$2,$3,$3,$4::jsonb,$5,$6)`, pre, grant, digest, pr, old.Add(time.Minute), old)
	enrollment := mustEncodeJSON(map[string]any{"statement": map[string]any{"tuple": map[string]any{"resource_id": resource, "resource_created_at": created}}}, "{}")
	must(`INSERT INTO capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$2,$2,$3::jsonb,$4)`, pre, digest, enrollment, old)
	must(`INSERT INTO capacity_guest_original_installations(preregistration_id,original_wire,confirmation_sha256,recorded_at) VALUES($1,'{}'::bytea,$2,$3)`, pre, digest, old)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	out := unknownMaintenanceFixture{f, ret, pre}
	out.abandonedDispatchFixture.jobSnapshot, out.abandonedDispatchFixture.runSnapshot = out.snapshot(t)
	return out
}

func (f unknownMaintenanceFixture) requestNow(t *testing.T) CapacityDispatchUnknownMaintenanceDispositionRequest {
	t.Helper()
	r := CapacityDispatchUnknownMaintenanceDispositionRequest{CapacityDispatchAbandonedDispositionRequest: f.request, ExpectedReturnedAt: f.returned}
	if err := f.db.QueryRow(`SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),public.unknown_maintenance_dispatch_effect_scan(j.id)->>'current_members_sha256' FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.envelope.JobID).Scan(&r.ExpectedRunSHA256, &r.ExpectedMembersSHA256); err != nil {
		t.Fatal(err)
	}
	return r
}
func (f unknownMaintenanceFixture) mutate(t *testing.T, q string, args ...any) {
	t.Helper()
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f.jobSnapshot, f.runSnapshot = f.snapshot(t)
}
func (f unknownMaintenanceFixture) assertUnknownUntouched(t *testing.T, beforeJob, beforeRun string) {
	t.Helper()
	j, w := f.snapshot(t)
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM capacity_dispatch_unknown_maintenance_dispositions WHERE job_id=$1`, f.envelope.JobID).Scan(&count); err != nil || count != 0 || j != beforeJob || w != beforeRun {
		t.Fatal("refused maintenance disposition changed original history", err, count)
	}
}
func (f unknownMaintenanceFixture) addCanary(t *testing.T, usage string, epoch int) {
	t.Helper()
	id := uuid.New()
	digest := capacityDispatchSHA([]byte(id.String()))
	at := f.start.Add(4 * time.Second)
	deadline := at.Add(5 * time.Second)
	record := mustEncodeJSON(map[string]any{"schema": "guest_notify_business_canary_publish_challenge_v1", "issued_at": at, "original_deadline": deadline, "usage_class": usage, "policy_checksum": f.envelope.Policy.Checksum, "workflow_checksum": f.envelope.Workflow.Checksum}, "{}")
	if _, err := f.db.Exec(`INSERT INTO capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$1,'publish',$3,$4,$5,21,'declared-fixture','declared-fixture',$6,$6,'{}'::bytea,$7::jsonb,$8,$9)`, id, f.pre, f.envelope.Policy.ID, f.envelope.Workflow.ID, epoch, digest, record, deadline, at); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, id, digest, at.Add(time.Second), deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at) VALUES($1,'accepted',$2,'{}'::bytea,'{}'::jsonb,$3)`, id, digest, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownMaintenanceDispatchPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := unknownMaintenancePGFixture(t, db)
	f.addCanary(t, "steady_useful_membership", 8)
	beforeJob, beforeRun := f.snapshot(t)
	request := f.requestNow(t)
	calls := 0
	receipt, err := DisposeUnknownMaintenanceDispatch(context.Background(), db, request, f.barrier, func(context.Context) error { calls++; return nil })
	if err != nil || calls != 2 || receipt.State != "unknown_maintenance_disposed" || receipt.HistoricalReturn != "unknown" || !receipt.OriginalReturnedAt.Equal(f.returned) || receipt.EffectScan.Base.CanaryPossibleSendsSinceStart != 1 {
		t.Fatal("dispose", err, calls, receipt)
	}
	var afterJob map[string]any
	afterRaw, afterRun := f.snapshot(t)
	if json.Unmarshal([]byte(afterRaw), &afterJob) != nil {
		t.Fatal("decode job")
	}
	var original map[string]any
	_ = json.Unmarshal([]byte(beforeJob), &original)
	for _, key := range []string{"state", "updated_at", "unknown_maintenance_disposition_id"} {
		delete(original, key)
		delete(afterJob, key)
	}
	if mustEncodeJSON(original, "null") != mustEncodeJSON(afterJob, "null") || afterRun != beforeRun {
		t.Fatal("disposition rewrote original return or workflow")
	}
	// A new independently admitted dispatch may queue; the old one is never replayed.
	next := f.envelope
	next.JobID, next.RunID = uuid.New(), uuid.New()
	next.SourceTick = f.start.Add(time.Hour).Format(time.RFC3339Nano)
	next.Metadata = map[string]any{}
	for k, v := range f.envelope.Metadata {
		next.Metadata[k] = v
	}
	next.Metadata["scheduled_for"] = next.SourceTick
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	queued, coalesced, err := EnqueueCapacityDispatch(context.Background(), tx, next)
	if err != nil || coalesced || queued.JobID != next.JobID || queued.State != "queued" {
		tx.Rollback()
		t.Fatal("new independent admission stayed blocked", err, coalesced)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	read, err := ReadCapacityDispatchUnknownMaintenanceDisposition(context.Background(), db, f.envelope.JobID)
	if err != nil || read.ID != receipt.ID {
		t.Fatal("readback", err)
	}
	if _, err = DisposeUnknownMaintenanceDispatch(context.Background(), db, request, f.barrier, abandonedAllow); err == nil {
		t.Fatal("second disposition accepted")
	}
	for _, q := range []string{
		`UPDATE capacity_dispatch_jobs SET state='unknown',unknown_maintenance_disposition_id=NULL WHERE id=$1`,
		`UPDATE capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`,
		`UPDATE capacity_dispatch_jobs SET return_error='success' WHERE id=$1`,
		`UPDATE workflow_runs SET error='success' WHERE id=(SELECT run_id FROM capacity_dispatch_jobs WHERE id=$1)`,
		`DELETE FROM workflow_runs WHERE id=(SELECT run_id FROM capacity_dispatch_jobs WHERE id=$1)`,
		`UPDATE capacity_dispatch_unknown_maintenance_dispositions SET historical_return='succeeded' WHERE job_id=$1`,
		`DELETE FROM capacity_dispatch_unknown_maintenance_dispositions WHERE job_id=$1`,
	} {
		if _, err = db.Exec(q, f.envelope.JobID); err == nil {
			t.Fatal("terminal history mutable", q)
		}
	}
}

func TestUnknownMaintenanceDispatchPostgresRefusals(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"provision_mode", "retirement_step", "different_fence", "policy_inactive", "policy_changed", "leased_intent", "disposal_marker", "new_member", "nonsteady_canary", "foreign_canary_epoch", "native_effect", "recorded_success", "missing_result", "return_after_lease", "ack_present", "finalization_error", "current_source_pin_changed"} {
		t.Run(name, func(t *testing.T) {
			f := unknownMaintenancePGFixture(t, db)
			j, w := f.envelope.JobID, f.envelope.RunID
			switch name {
			case "provision_mode":
				f.mutate(t, `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,0,metadata,mode}','"provision"') WHERE id=$1`, w)
			case "retirement_step":
				f.mutate(t, `UPDATE workflow_runs SET result=jsonb_set(result,'{steps,2,status}','"succeeded"') WHERE id=$1`, w)
			case "different_fence":
				f.mutate(t, `UPDATE capacity_intents SET intent=jsonb_set(intent,'{fencing_token}','22') WHERE namespace=$1`, f.envelope.Realm)
			case "policy_inactive":
				f.mutate(t, `UPDATE manifests SET active=false WHERE id=$1`, f.envelope.Policy.ID)
			case "policy_changed":
				f.mutate(t, `UPDATE capacity_intents SET intent=jsonb_set(intent,'{policy_id}',to_jsonb($2::text)) WHERE namespace=$1`, f.envelope.Realm, uuid.NewString())
			case "leased_intent":
				f.mutate(t, `UPDATE capacity_intents SET intent=intent||jsonb_build_object('lease_owner','old-executor') WHERE namespace=$1`, f.envelope.Realm)
			case "disposal_marker":
				f.mutate(t, `UPDATE capacity_intents SET intent=intent||'{"failed_installed_disposal":{"state":"requested"}}'::jsonb WHERE namespace=$1`, f.envelope.Realm)
			case "new_member":
				f.mutate(t, `UPDATE capacity_resource_slots SET resource_id=$2 WHERE namespace=$1`, f.envelope.Realm, "new-unenrolled-resource")
			case "nonsteady_canary":
				f.addCanary(t, "before_retirement_floor", 8)
			case "foreign_canary_epoch":
				f.addCanary(t, "steady_useful_membership", 9)
			case "native_effect":
				f.mutate(t, `UPDATE capacity_mutation_grants SET updated_at=$2 WHERE namespace=$1`, f.envelope.Realm, f.start.Add(time.Second))
			case "recorded_success":
				f.mutate(t, `UPDATE capacity_dispatch_jobs SET return_status='succeeded' WHERE id=$1`, j)
			case "missing_result":
				f.mutate(t, `UPDATE workflow_runs SET result=NULL WHERE id=$1`, w)
			case "return_after_lease":
				f.mutate(t, `UPDATE capacity_dispatch_jobs SET returned_at=lease_expires_at+interval '1 second' WHERE id=$1`, j)
			case "ack_present":
				f.mutate(t, `UPDATE capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`, j)
			case "finalization_error":
				f.mutate(t, `UPDATE capacity_dispatch_jobs SET finalization_error='lost' WHERE id=$1`, j)
			case "current_source_pin_changed":
				f.mutate(t, `UPDATE manifests SET checksum=$2 WHERE id=$1`, f.envelope.Workflow.ID, strings.Repeat("d", 64))
			}
			beforeJob, beforeRun := f.snapshot(t)
			request := f.requestNow(t)
			if _, err := DisposeUnknownMaintenanceDispatch(context.Background(), db, request, f.barrier, abandonedAllow); err == nil {
				t.Fatal("unsafe maintenance disposition accepted")
			}
			f.assertUnknownUntouched(t, beforeJob, beforeRun)
		})
	}
}

func TestUnknownMaintenanceDispatchPostgresCASBarrierAndConcurrency(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"run_sha", "members_sha", "returned_at", "wake_count", "old_process", "young_lease", "operator_revoked"} {
		t.Run(name, func(t *testing.T) {
			f := unknownMaintenancePGFixture(t, db)
			r := f.requestNow(t)
			b := f.barrier
			allow := abandonedAllow
			switch name {
			case "run_sha":
				r.ExpectedRunSHA256 = strings.Repeat("0", 64)
			case "members_sha":
				r.ExpectedMembersSHA256 = strings.Repeat("0", 64)
			case "returned_at":
				r.ExpectedReturnedAt = r.ExpectedReturnedAt.Add(time.Microsecond)
			case "wake_count":
				r.ExpectedPendingWakeCount--
			case "old_process":
				b.ProcessStartedAt = f.start
			case "young_lease":
				f.mutate(t, `UPDATE capacity_dispatch_jobs SET lease_expires_at=clock_timestamp() WHERE id=$1`, f.envelope.JobID)
			case "operator_revoked":
				allow = func(context.Context) error { return errors.New("revoked") }
			}
			j, w := f.snapshot(t)
			if _, err := DisposeUnknownMaintenanceDispatch(context.Background(), db, r, b, allow); err == nil {
				t.Fatal("stale/unauthorized accepted")
			}
			f.assertUnknownUntouched(t, j, w)
		})
	}
	f := unknownMaintenancePGFixture(t, db)
	r := f.requestNow(t)
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := DisposeUnknownMaintenanceDispatch(context.Background(), db, r, f.barrier, abandonedAllow)
			out <- err
		}()
	}
	wg.Wait()
	close(out)
	success := 0
	for err := range out {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent receipts", success)
	}
	t.Run("catalog_lock_survives_operator_recheck", func(t *testing.T) {
		f := unknownMaintenancePGFixture(t, db)
		request := f.requestNow(t)
		calls := 0
		_, err := DisposeUnknownMaintenanceDispatch(context.Background(), db, request, f.barrier, func(context.Context) error {
			calls++
			if calls != 2 {
				return nil
			}
			other, e := db.Begin()
			if e != nil {
				return e
			}
			defer other.Rollback()
			if _, e = other.Exec(`SET LOCAL lock_timeout='100ms'`); e != nil {
				return e
			}
			_, e = other.Exec(`UPDATE manifests SET active=false WHERE id=$1`, f.envelope.Policy.ID)
			var lockError *pq.Error
			if !errors.As(e, &lockError) || lockError.Code != "55P03" {
				return errors.New("catalog publication was not fenced by disposition")
			}
			return nil
		})
		if err != nil || calls != 2 {
			t.Fatal("catalog pins not locked through second operator check", err, calls)
		}
		var active bool
		if err = db.QueryRow(`SELECT active FROM manifests WHERE id=$1`, f.envelope.Policy.ID).Scan(&active); err != nil || !active {
			t.Fatal("catalog changed inside disposition", err)
		}
	})

}

func TestUnknownMaintenanceDispatchMigration87Guards(t *testing.T) {
	db := originalDispositionPG(t)
	f := unknownMaintenancePGFixture(t, db)
	r := f.requestNow(t)
	// Direct terminal creation and a lone receipt cannot cross the boundary.
	if _, err := db.Exec(`UPDATE capacity_dispatch_jobs SET state='unknown_maintenance_disposed' WHERE id=$1`, f.envelope.JobID); err == nil {
		t.Fatal("terminal without receipt accepted")
	}
	insert := `INSERT INTO capacity_dispatch_unknown_maintenance_dispositions(id,job_id,run_id,original_dispatch_sha256,original_run_sha256,original_returned_at,current_members_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,issuer,reason,historical_return,recorded_at,provider_mutation_evidence)
 SELECT $1,j.id,j.run_id,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),$3,j.returned_at,$4,$5,$6,'guard-fixture',42,'',$7,$8,'unknown',clock_timestamp(),public.unknown_maintenance_dispatch_effect_scan(j.id) FROM capacity_dispatch_jobs j WHERE j.id=$2`
	args := []any{uuid.New(), f.envelope.JobID, r.ExpectedRunSHA256, r.ExpectedMembersSHA256, CapacityDispatchAbandonedBarrier, f.barrier.ProcessStartedAt, r.Issuer, CapacityDispatchUnknownMaintenanceReason}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(insert, args...); err != nil {
		tx.Rollback()
		t.Fatal("valid direct receipt fixture", err)
	}
	if err = tx.Commit(); err == nil {
		t.Fatal("orphan receipt committed")
	}
	beforeJob, beforeRun := f.snapshot(t)
	f.assertUnknownUntouched(t, beforeJob, beforeRun)
	bad := append([]any{}, args...)
	bad[0] = uuid.New()
	bad[2] = strings.Repeat("0", 64)
	if _, err = db.Exec(insert, bad...); err == nil {
		t.Fatal("forged original run digest accepted")
	}
}
