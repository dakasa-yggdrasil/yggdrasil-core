package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// DECLARED started-dispatch histories in the explicitly isolated Unix-socket
// database used by the disposition Source workflow (schema83). No provider,
// Guest, workflow execution or production authority is exercised here.
type abandonedDispatchFixture struct {
	db       *sql.DB
	envelope CapacityDispatchEnvelope
	request  CapacityDispatchAbandonedDispositionRequest
	barrier  CapacityDispatchExecutorBarrier
	start    time.Time
	lease    time.Time
	// The exact original job and run rows right after the fixture was built.
	jobSnapshot string
	runSnapshot string
}

type abandonedDispatchFixtureOptions struct {
	start       time.Time
	leaseFor    time.Duration
	jobState    string
	runStatus   string
	runStarted  *time.Time
	runError    string
	pendingWake int
	domain      string
}

func abandonedDispatchEnvelope(t *testing.T, realm, tick string) CapacityDispatchEnvelope {
	t.Helper()
	e := CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: realm, Environment: "production", Domain: "notify", Dimension: "original_notify_hetzner_vm_members", SourceTick: tick,
		Policy:             CapacityDispatchManifestPin{ID: uuid.New(), Namespace: realm, Name: "notify-hetzner", Version: 9, Checksum: strings.Repeat("e", 64)},
		Workflow:           CapacityDispatchManifestPin{ID: uuid.New(), Namespace: realm, Name: "original", Version: 1, Checksum: strings.Repeat("f", 64)},
		RBAC:               CapacityDispatchManifestPin{ID: uuid.New(), Namespace: realm, Name: "isolated-rbac", Version: 1, Checksum: strings.Repeat("9", 64)},
		MachinePrincipalID: "isolated-abandoned-test", PrincipalSHA256: strings.Repeat("8", 64), BindingSHA256: strings.Repeat("7", 64)}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": e.Policy.Namespace, "name": e.Policy.Name}}
	e.Metadata = map[string]any{WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": e.Workflow.ID.String(), "scheduled_for": e.SourceTick}
	e.InputsSHA256, e.MetadataSHA256, _ = CapacityDispatchEnvelopeHashes(e)
	return e
}

func abandonedDispatchPGFixture(t *testing.T, db *sql.DB, o abandonedDispatchFixtureOptions) abandonedDispatchFixture {
	t.Helper()
	if o.start.IsZero() {
		o.start = time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	}
	if o.leaseFor == 0 {
		o.leaseFor = 5 * time.Minute
	}
	if o.jobState == "" {
		o.jobState = "started"
	}
	if o.runStatus == "" {
		o.runStatus = "running"
	}
	if o.pendingWake == 0 {
		o.pendingWake = MaxCapacityDispatchPendingWakes
	}
	runStarted := o.start
	if o.runStarted != nil {
		runStarted = *o.runStarted
	}
	realm := "abandoned-" + uuid.NewString()
	e := abandonedDispatchEnvelope(t, realm, o.start.Format(time.RFC3339Nano))
	if o.domain != "" {
		e.Domain = o.domain
	}
	envelope, err := encodeCapacityDispatchEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	inputs, metadata := mustEncodeJSON(e.Inputs, "{}"), mustEncodeJSON(e.Metadata, "{}")
	lease := o.start.Add(o.leaseFor)
	owner := uuid.New()
	var runError any
	if o.runError != "" {
		runError = o.runError
	}
	var finished any
	if o.runStatus != "running" {
		finished = lease
	}
	if _, err = db.Exec(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,error,inputs,metadata) VALUES($1,$2,$3,'original',1,$4,$5,$6,$7::jsonb,$8::jsonb)`, e.RunID, o.runStatus, realm, runStarted, finished, runError, inputs, metadata); err != nil {
		t.Fatal(err)
	}
	var returned, returnStatus any
	if o.jobState == "unknown" || o.jobState == "returned" {
		returned, returnStatus = lease, "failed"
	}
	var jobStarted any = o.start
	if o.jobState == "queued" {
		jobStarted = nil
	}
	if _, err = db.Exec(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,pending_wake_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,$16,$17)`,
		e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), o.jobState, owner, lease, jobStarted, returned, returnStatus, o.pendingWake); err != nil {
		t.Fatal(err)
	}
	f := abandonedDispatchFixture{db: db, envelope: e, start: o.start, lease: lease,
		request: CapacityDispatchAbandonedDispositionRequest{JobID: e.JobID, ExpectedRunID: e.RunID, ExpectedEnvelopeSHA256: capacityDispatchSHA(envelope), ExpectedFencingToken: 1, ExpectedLeaseOwner: owner, ExpectedPendingWakeCount: o.pendingWake, Issuer: "collaborator:" + uuid.NewString()},
		barrier: CapacityDispatchExecutorBarrier{ProcessStartedAt: lease.Add(time.Minute), Hostname: "abandoned-fixture-core", PID: 4242, SourceCommit: strings.Repeat("a", 40)}}
	f.jobSnapshot, f.runSnapshot = f.snapshot(t)
	return f
}

func (f abandonedDispatchFixture) snapshot(t *testing.T) (string, string) {
	t.Helper()
	var job, run string
	if err := f.db.QueryRow(`SELECT to_jsonb(j)::text,to_jsonb(w)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.envelope.JobID).Scan(&job, &run); err != nil {
		t.Fatal(err)
	}
	return job, run
}

func abandonedAllow(context.Context) error { return nil }

// A refused disposal leaves the original job and run byte-identical to the
// fixture snapshot and writes no receipt, whatever shape that fixture had.
func (f abandonedDispatchFixture) assertUntouched(t *testing.T) {
	t.Helper()
	job, run := f.snapshot(t)
	var receipts int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_abandoned_dispositions WHERE job_id=$1`, f.envelope.JobID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if job != f.jobSnapshot || run != f.runSnapshot || receipts != 0 {
		t.Fatal("refused disposal changed the original history", receipts)
	}
}

func TestAbandonedStartedDispatchPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	calls := 0
	receipt, err := DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, func(context.Context) error { calls++; return nil })
	if err != nil || calls != 2 {
		t.Fatal("dispose", err, calls)
	}
	if receipt.JobID != f.envelope.JobID || receipt.RunID != f.envelope.RunID || receipt.State != "abandoned_disposed" || receipt.HistoricalReturn != "unknown" ||
		receipt.ReturnedAt != nil || receipt.FinalizationAckAt != nil || receipt.WorkflowRunStatus != "failed" || receipt.RunError != CapacityDispatchAbandonedRunError ||
		receipt.WorkflowRunFinishedAt == nil || !receipt.WorkflowRunFinishedAt.Equal(receipt.RecordedAt) || receipt.WorkflowRunResultPresent ||
		receipt.PendingWakeCount != MaxCapacityDispatchPendingWakes || receipt.FencingToken != 1 || receipt.LeaseOwner != f.request.ExpectedLeaseOwner ||
		!receipt.StartedAt.Equal(f.start) || !receipt.LeaseExpiresAt.Equal(f.lease) || !receipt.CoreProcessStartedAt.Equal(f.barrier.ProcessStartedAt) ||
		receipt.CoreHostname != f.barrier.Hostname || receipt.CorePID != f.barrier.PID || receipt.CoreSourceCommit != f.barrier.SourceCommit ||
		receipt.Issuer != f.request.Issuer || receipt.MinimumLeaseAgeSeconds != 900 || !receipt.EffectScan.zero() || receipt.EffectScan.ProviderReadPerformed {
		t.Fatalf("receipt fabricated or lost a fact: %+v", receipt)
	}
	read, err := ReadCapacityDispatchAbandonedDisposition(ctx, db, f.envelope.JobID)
	if err != nil || read.ID != receipt.ID || !read.RecordedAt.Equal(receipt.RecordedAt) || read.OriginalDispatchSHA256 != receipt.OriginalDispatchSHA256 {
		t.Fatal("lost response readback", err)
	}
	var returnStatus, ack sql.NullString
	var returned sql.NullTime
	var result sql.NullString
	if err = db.QueryRow(`SELECT j.return_status,j.finalization_ack_at::text,j.returned_at,w.result::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.envelope.JobID).Scan(&returnStatus, &ack, &returned, &result); err != nil || returnStatus.Valid || ack.Valid || returned.Valid || result.Valid {
		t.Fatal("disposal fabricated an original return, ACK or result", err)
	}
	if _, err = DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, abandonedAllow); err == nil {
		t.Fatal("second disposal accepted")
	}
	// Terminal immutability: no replay, downgrade, wake, return or receipt edit.
	for _, statement := range []string{
		`UPDATE public.capacity_dispatch_jobs SET state='started',abandoned_disposition_id=NULL WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET state='unknown',abandoned_disposition_id=NULL WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET state='queued',started_at=NULL,abandoned_disposition_id=NULL WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET updated_at=clock_timestamp() WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET returned_at=clock_timestamp() WHERE id=$1`,
		`UPDATE public.capacity_dispatch_abandoned_dispositions SET reason=reason WHERE job_id=$1`,
		`DELETE FROM public.capacity_dispatch_abandoned_dispositions WHERE job_id=$1`,
	} {
		if _, execErr := db.Exec(statement, f.envelope.JobID); execErr == nil {
			t.Fatal("terminal history mutated", statement)
		}
	}
	for _, statement := range []string{
		`UPDATE public.workflow_runs SET status='succeeded' WHERE id=$1`,
		`UPDATE public.workflow_runs SET status='cancelled',finished_at=NOW() WHERE id=$1`,
		`UPDATE public.workflow_runs SET result='{}'::jsonb WHERE id=$1`,
		`UPDATE public.workflow_runs SET error=NULL WHERE id=$1`,
	} {
		if _, execErr := db.Exec(statement, f.envelope.RunID); execErr == nil {
			t.Fatal("administratively closed run mutated", statement)
		}
	}
	// The dimension admits a NEW job through ordinary Enqueue afterwards.
	next := abandonedDispatchEnvelope(t, f.envelope.Realm, time.Now().UTC().Format(time.RFC3339Nano))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, duplicate, err := EnqueueCapacityDispatch(ctx, tx, next)
	if err != nil || duplicate || job.JobID != next.JobID || job.State != "queued" || job.PendingWakeCount != 1 {
		_ = tx.Rollback()
		t.Fatal("dimension still blocked after disposal", err, duplicate)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var stillDisposed string
	if err = db.QueryRow(`SELECT state FROM public.capacity_dispatch_jobs WHERE id=$1`, f.envelope.JobID).Scan(&stillDisposed); err != nil || stillDisposed != "abandoned_disposed" {
		t.Fatal("new admission rewrote the disposed original", stillDisposed, err)
	}
}

func TestAbandonedStartedDispatchPostgresRefusedPreconditions(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	now := time.Now().UTC()
	fresh := now.Add(-10 * time.Minute).Truncate(time.Millisecond)
	skewed := now.Add(-2 * time.Hour).Add(time.Second).Truncate(time.Millisecond)
	insertGrant := func(f abandonedDispatchFixture, state string, updated time.Time, record string) error {
		_, err := db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,8,$6,'abandoned-scope','notify-hetzner-elastic',1,$7,$8::jsonb,$9,$10)`,
			uuid.New(), f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, uuid.New(), state, record, updated.Add(time.Hour), updated)
		return err
	}
	cases := []struct {
		name    string
		options abandonedDispatchFixtureOptions
		mutate  func(*abandonedDispatchFixture) error
		allow   func(context.Context) error
	}{
		{name: "lease_younger_than_fifteen_minutes", options: abandonedDispatchFixtureOptions{start: fresh}},
		{name: "job_queued", options: abandonedDispatchFixtureOptions{jobState: "queued"}},
		{name: "job_unknown_with_return", options: abandonedDispatchFixtureOptions{jobState: "unknown"}},
		{name: "run_not_running", options: abandonedDispatchFixtureOptions{runStatus: "cancelled"}},
		{name: "run_started_at_differs", options: abandonedDispatchFixtureOptions{runStarted: &skewed}},
		{name: "run_already_has_error", options: abandonedDispatchFixtureOptions{runError: "historical"}},
		{name: "barrier_process_started_before_lease_expiry", mutate: func(f *abandonedDispatchFixture) error {
			f.barrier.ProcessStartedAt = f.lease.Add(-time.Second)
			return nil
		}},
		{name: "barrier_process_start_in_future", mutate: func(f *abandonedDispatchFixture) error {
			f.barrier.ProcessStartedAt = time.Now().UTC().Add(time.Hour)
			return nil
		}},
		{name: "barrier_without_identity", mutate: func(f *abandonedDispatchFixture) error {
			f.barrier.Hostname, f.barrier.PID = "", 0
			return nil
		}},
		{name: "grant_created_after_start", mutate: func(f *abandonedDispatchFixture) error {
			return insertGrant(*f, "confirmed", time.Now().UTC(), `{}`)
		}},
		{name: "grant_record_created_after_start", mutate: func(f *abandonedDispatchFixture) error {
			return insertGrant(*f, "confirmed", f.start.Add(-time.Hour), `{"created_at":"`+f.start.Add(time.Minute).Format(time.RFC3339Nano)+`"}`)
		}},
		{name: "open_issued_grant_before_start", mutate: func(f *abandonedDispatchFixture) error {
			return insertGrant(*f, "issued", f.start.Add(-time.Hour), `{}`)
		}},
		{name: "intent_event_after_start", mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,8,21,'preparing','abandoned-test')`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension)
			return err
		}},
		{name: "resource_slot_updated_after_start", mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,'abandoned-scope','notify-hetzner-elastic',1,$2,$3,$4,$5,'','{}'::jsonb)`, uuid.New(), f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension)
			return err
		}},
		{name: "native_command_after_start", mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,phase,sequence,state,authority_token_sha256,command_record) VALUES($1,$2,$3,$4,$5,8,'create','send',1,'issued',$6,'{}'::jsonb)`, uuid.New(), f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, strings.ReplaceAll(uuid.NewString(), "-", "")+strings.ReplaceAll(uuid.NewString(), "-", ""))
			return err
		}},
		{name: "intent_event_inside_clock_skew_margin", mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,8,21,'preparing','abandoned-skew',$5)`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, f.start.Add(-10*time.Second))
			return err
		}},
		{name: "intent_updated_after_start", mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, f.start.Add(time.Minute))
			return err
		}},
		{name: "original_notify_window_marker_for_job", mutate: func(f *abandonedDispatchFixture) error {
			// BeginOriginalNotifyWindow writes this marker with a raw intent
			// UPDATE and no intent event; it counts with no time bound.
			marker := `{"generation":8,"original_notify_window":{"schema":"original_notify_window_v1","state":"possible_start","dispatch_job_id":"` + f.envelope.JobID.String() + `","dispatch_fence":1}}`
			_, err := db.Exec(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, marker, f.start.Add(-time.Hour))
			return err
		}},
		// Go json.Marshal escapes '&' as \u0026 and array_to_json does not, so
		// the scope lock key would differ between the Go path and the guard.
		{name: "scope_name_with_divergent_lock_encoding", options: abandonedDispatchFixtureOptions{domain: "notify&guest"}},
		{name: "operator_no_longer_current", allow: func(context.Context) error { return errors.New("revoked") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := abandonedDispatchPGFixture(t, db, c.options)
			if c.mutate != nil {
				if err := c.mutate(&f); err != nil {
					t.Fatal("fixture mutation", err)
				}
			}
			allow := c.allow
			if allow == nil {
				allow = abandonedAllow
			}
			if _, err := DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, allow); err == nil {
				t.Fatal("refused precondition accepted")
			}
			f.assertUntouched(t)
		})
	}
}

func TestAbandonedStartedDispatchPostgresStaleCAS(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{pendingWake: 7})
	mutations := map[string]func(*CapacityDispatchAbandonedDispositionRequest){
		"run": func(r *CapacityDispatchAbandonedDispositionRequest) { r.ExpectedRunID = uuid.New() },
		"envelope": func(r *CapacityDispatchAbandonedDispositionRequest) {
			r.ExpectedEnvelopeSHA256 = strings.Repeat("0", 64)
		},
		"fence":     func(r *CapacityDispatchAbandonedDispositionRequest) { r.ExpectedFencingToken = 2 },
		"owner":     func(r *CapacityDispatchAbandonedDispositionRequest) { r.ExpectedLeaseOwner = uuid.New() },
		"wakes":     func(r *CapacityDispatchAbandonedDispositionRequest) { r.ExpectedPendingWakeCount = 8 },
		"job":       func(r *CapacityDispatchAbandonedDispositionRequest) { r.JobID = uuid.New() },
		"issuer":    func(r *CapacityDispatchAbandonedDispositionRequest) { r.Issuer = "machine:abandoned" },
		"no_issuer": func(r *CapacityDispatchAbandonedDispositionRequest) { r.Issuer = "" },
	}
	for name, mutate := range mutations {
		request := f.request
		mutate(&request)
		if _, err := DisposeAbandonedStartedDispatch(ctx, db, request, f.barrier, abandonedAllow); err == nil {
			t.Fatal("stale CAS accepted", name)
		}
		f.assertUntouched(t)
	}
	if _, err := DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, abandonedAllow); err != nil {
		t.Fatal("exact CAS refused after stale attempts", err)
	}
}

func TestAbandonedStartedDispatchMigration83Guards(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	// A job carrying an abandoned disposition can never be inserted directly.
	// The row uses its own fresh run and a non-terminal state, so no UNIQUE
	// run_id or state CHECK can refuse it before the insert trigger does.
	e := abandonedDispatchEnvelope(t, f.envelope.Realm+"-x", time.Now().UTC().Format(time.RFC3339Nano))
	envelope, _ := encodeCapacityDispatchEnvelope(e)
	if _, err := db.Exec(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,inputs,metadata) VALUES($1,'running',$2,'original',1,$3,'{}'::jsonb,'{}'::jsonb)`, e.RunID, e.Realm, f.start); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,abandoned_disposition_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'started',$11,1,$12,$13,$14)`,
		e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.lease, f.start, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "abandoned disposition requires a retained original started job") {
		t.Fatal("direct disposition-linked insert was not refused by its trigger", err)
	}
	// The terminal requires its receipt; a bare state change is refused.
	if _, err := db.Exec(`UPDATE public.capacity_dispatch_jobs SET state='abandoned_disposed' WHERE id=$1`, f.envelope.JobID); err == nil {
		t.Fatal("receipt-less terminal accepted")
	}
	insertReceipt := func(tx *sql.Tx, dispatchSHA, scan string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_abandoned_dispositions(id,job_id,run_id,realm,environment,domain,dimension,envelope_sha256,fencing_token,lease_owner,lease_expires_at,started_at,pending_wake_count,original_dispatch_sha256,original_run_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,minimum_lease_age_seconds,recorded_at,issuer,reason,historical_return,run_status,run_error,provider_mutation_evidence)
SELECT $1,j.id,j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count,
 COALESCE($3,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),
 $4,$5,'abandoned-fixture-core',4242,'',900,clock_timestamp(),$6,$7,'unknown','failed',$8,COALESCE($9::jsonb,public.abandoned_started_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at))
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$2`,
			uuid.New(), f.envelope.JobID, nullableText(dispatchSHA), CapacityDispatchAbandonedBarrier, f.lease.Add(time.Minute), f.request.Issuer, CapacityDispatchAbandonedReason, CapacityDispatchAbandonedRunError, nullableText(scan))
		return err
	}
	for name, values := range map[string][2]string{
		"forged_original_dispatch": {strings.Repeat("0", 64), ""},
		"forged_effect_scan":       {"", `{"schema":"abandoned_started_dispatch_effect_scan_v2","clock_skew_margin_seconds":30,"provider_read_performed":false,"provider_quiescence_proved":false}`},
	} {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if insertReceipt(tx, values[0], values[1]) == nil {
			_ = tx.Rollback()
			t.Fatal("forged receipt accepted", name)
		}
		_ = tx.Rollback()
	}
	// A receipt alone, without the job terminal and run close, cannot commit.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertReceipt(tx, "", ""); err != nil {
		_ = tx.Rollback()
		t.Fatal("exact receipt refused before deferred link check", err)
	}
	if err = tx.Commit(); err == nil {
		t.Fatal("unlinked receipt committed")
	}
	f.assertUntouched(t)
	// A lease younger than the minimum age is refused by the database itself.
	young := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{start: time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)})
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	f2 := f
	f = young
	if insertReceipt(tx, "", "") == nil {
		_ = tx.Rollback()
		t.Fatal("young lease receipt accepted")
	}
	_ = tx.Rollback()
	f = f2
	// Grant history cannot be deleted.
	grantID := uuid.New()
	if _, err = db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,'production','notify','grant-delete-guard',1,$3,'abandoned-scope','notify-hetzner-elastic',1,'expired','{}'::jsonb,clock_timestamp())`, grantID, "abandoned-grant-"+uuid.NewString(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM public.capacity_mutation_grants WHERE id=$1`, grantID); err == nil {
		t.Fatal("grant history deleted")
	}
	// The real lane still succeeds on the untouched original.
	if _, err = DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, abandonedAllow); err != nil {
		t.Fatal("guards blocked the exact lane", err)
	}
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
