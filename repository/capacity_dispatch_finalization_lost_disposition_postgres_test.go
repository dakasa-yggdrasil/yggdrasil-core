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

// DECLARED started-dispatch histories shaped like production job 09a9fee8
// (AWS original_notify_aws_vm_members): the executor returned, the plan step
// wrote one hold assessment and the refresh step one slot observation, then
// the finalization write was lost. Explicitly isolated Unix-socket database
// (schema86); no provider, Guest or workflow execution is exercised.

const finalizationLostEvidence = "2026-11-02 08:04:17.377 UTC [177447] ERROR:  canceling statement due to user request\n" +
	"2026-11-02 08:04:17.377 UTC [177447] STATEMENT:  UPDATE public.workflow_runs SET status=$2,result=$3::jsonb,error=NULLIF($4,''),finished_at=$5,updated_at=clock_timestamp() WHERE id=$1 AND (status='running' OR ($7 AND status='cancelled')) AND started_at=$6"

type finalizationLostEffects struct {
	intentLeased        bool
	intentAction        string
	intentPhase         string
	eventPhase          string
	noEvent             bool
	intentAfterLease    bool
	slotTombstone       bool
	slotRevision        int
	slotCreatedAfter    bool
	slotObservedBefore  bool
	slotAuthority       bool
	slotAfterLease      bool
	slotResourceMissing bool
}

// tolerated writes the two bookkeeping effects the lane accepts, optionally
// spoiled by one field.
func (f abandonedDispatchFixture) tolerated(t *testing.T, o finalizationLostEffects) {
	t.Helper()
	if o.intentAction == "" {
		o.intentAction = "hold"
	}
	if o.intentPhase == "" {
		o.intentPhase = "promoted"
	}
	if o.eventPhase == "" {
		o.eventPhase = o.intentPhase
	}
	if o.slotRevision == 0 {
		o.slotRevision = 281
	}
	e := f.envelope
	if !o.noEvent {
		if _, err := f.db.Exec(`INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,8,21,$5,'finalization-lost-test',$6)`, e.Realm, e.Environment, e.Domain, e.Dimension, o.eventPhase, f.start.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	lease := ""
	if o.intentLeased {
		lease = `,"lease_owner":"` + uuid.NewString() + `","lease_executor_id":"executor","lease_expires_at":"` + f.lease.Format(time.RFC3339Nano) + `"`
	}
	intent := `{"generation":8,"fencing_token":21,"phase":"` + o.intentPhase + `","decision":{"action":"` + o.intentAction + `","reason":"signal_evidence_unavailable","execution_permitted":false}` + lease + `}`
	intentAt := f.start.Add(1400 * time.Millisecond)
	if o.intentAfterLease {
		intentAt = f.lease.Add(time.Second)
	}
	if _, err := f.db.Exec(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, e.Realm, e.Environment, e.Domain, e.Dimension, intent, intentAt); err != nil {
		t.Fatal(err)
	}
	created := f.start.Add(-30 * 24 * time.Hour)
	if o.slotCreatedAfter {
		created = f.start.Add(time.Second)
	}
	observed := f.start.Add(2100 * time.Millisecond)
	if o.slotObservedBefore {
		observed = f.start.Add(-time.Hour)
	}
	// EC2-shaped like production i-0e3aba1cf6fe34a50, but unique per fixture:
	// capacity_executor_power_vm_overlap_idx (00067) is global across scopes,
	// and every test in the job shares one database.
	resource := "i-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:17]
	recordResource := resource
	if o.slotResourceMissing {
		recordResource = ""
	}
	authority := ""
	if o.slotAuthority {
		authority = `,"authority_kind":"core_mutation_grants"`
	}
	record := `{"binding_name":"notify-aws","profile_name":"notify-aws-elastic","desired_spec_sha256":"` + strings.Repeat("c", 64) + `","resource_id":"` + recordResource + `","resource_created_at":"` + created.Format(time.RFC3339) + `","receipt_ref":"original-guest-reconcile:test","observed_at":"` + observed.Format(time.RFC3339Nano) + `","tombstone":` + map[bool]string{true: "true", false: "false"}[o.slotTombstone] + authority + `}`
	slotAt := f.start.Add(3 * time.Second)
	if o.slotAfterLease {
		slotAt = f.lease.Add(time.Second)
	}
	if _, err := f.db.Exec(`INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record,revision,updated_at) VALUES($1,'finalization-scope','notify-aws-elastic',1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, uuid.New(), e.Realm, e.Environment, e.Domain, e.Dimension, resource, record, o.slotRevision, slotAt); err != nil {
		t.Fatal(err)
	}
}

func (f abandonedDispatchFixture) finalizationLostRequest() CapacityDispatchFinalizationLostDispositionRequest {
	r := f.request
	return CapacityDispatchFinalizationLostDispositionRequest{JobID: r.JobID, ExpectedRunID: r.ExpectedRunID, ExpectedEnvelopeSHA256: r.ExpectedEnvelopeSHA256,
		ExpectedFencingToken: r.ExpectedFencingToken, ExpectedLeaseOwner: r.ExpectedLeaseOwner, ExpectedPendingWakeCount: r.ExpectedPendingWakeCount,
		Evidence: finalizationLostEvidence, Issuer: r.Issuer}
}

// A refused finalization-lost disposal leaves the job and run byte-identical
// and writes no receipt in either disposition table.
func (f abandonedDispatchFixture) assertFinalizationLostUntouched(t *testing.T) {
	t.Helper()
	f.assertUntouched(t)
	var receipts int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_finalization_lost_dispositions WHERE job_id=$1`, f.envelope.JobID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("refused finalization-lost disposal wrote a receipt", receipts, err)
	}
}

func TestFinalizationLostDispatchPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	f.tolerated(t, finalizationLostEffects{})
	f.jobSnapshot, f.runSnapshot = f.snapshot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// ADR-0089 refuses this history: its scan is not all zero.
	if _, err := DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, abandonedAllow); err == nil {
		t.Fatal("abandoned lane accepted a job with recorded bookkeeping effects")
	}
	f.assertUntouched(t)
	calls := 0
	request := f.finalizationLostRequest()
	receipt, err := DisposeFinalizationLostStartedDispatch(ctx, db, request, f.barrier, func(context.Context) error { calls++; return nil })
	if err != nil || calls != 2 {
		t.Fatal("dispose", err, calls)
	}
	scan := receipt.EffectScan
	if receipt.JobID != f.envelope.JobID || receipt.RunID != f.envelope.RunID || receipt.State != "finalization_lost_disposed" ||
		receipt.HistoricalReturn != "unknown" || receipt.ReturnObservation != CapacityDispatchFinalizationLostObservation ||
		receipt.ReturnedAt != nil || receipt.FinalizationAckAt != nil || receipt.WorkflowRunStatus != "failed" ||
		receipt.RunError != CapacityDispatchFinalizationLostRunError || receipt.WorkflowRunFinishedAt == nil ||
		!receipt.WorkflowRunFinishedAt.Equal(receipt.RecordedAt) || receipt.WorkflowRunResultPresent ||
		receipt.EvidenceSHA256 != capacityDispatchFinalizationEvidenceSHA(finalizationLostEvidence) || receipt.EvidenceBytes != len(finalizationLostEvidence) ||
		receipt.PendingWakeCount != MaxCapacityDispatchPendingWakes || !receipt.StartedAt.Equal(f.start) || !receipt.LeaseExpiresAt.Equal(f.lease) ||
		receipt.Issuer != request.Issuer || receipt.MinimumLeaseAgeSeconds != 900 ||
		scan.IntentsUpdatedSinceStart != 1 || scan.PureAssessmentIntentUpdates != 1 || scan.ResourceSlotsUpdatedSinceStart != 1 ||
		scan.ObservationRefreshSlotUpdates != 1 || scan.ProviderReadPerformed || scan.ProviderQuiescenceProved || !scan.tolerable() {
		t.Fatalf("receipt fabricated or lost a fact: %+v", receipt)
	}
	var stored string
	if err = db.QueryRow(`SELECT operator_evidence FROM public.capacity_dispatch_finalization_lost_dispositions WHERE job_id=$1`, f.envelope.JobID).Scan(&stored); err != nil || stored != finalizationLostEvidence {
		t.Fatal("operator evidence was not retained verbatim", err)
	}
	read, err := ReadCapacityDispatchFinalizationLostDisposition(ctx, db, f.envelope.JobID)
	if err != nil || read.ID != receipt.ID || !read.RecordedAt.Equal(receipt.RecordedAt) {
		t.Fatal("lost response readback", err)
	}
	var returnStatus, ack, result sql.NullString
	var returned sql.NullTime
	if err = db.QueryRow(`SELECT j.return_status,j.finalization_ack_at::text,j.returned_at,w.result::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, f.envelope.JobID).Scan(&returnStatus, &ack, &returned, &result); err != nil || returnStatus.Valid || ack.Valid || returned.Valid || result.Valid {
		t.Fatal("disposal fabricated an original return, ACK or result", err)
	}
	if _, err = DisposeFinalizationLostStartedDispatch(ctx, db, request, f.barrier, abandonedAllow); err == nil {
		t.Fatal("second disposal accepted")
	}
	if _, err = DisposeAbandonedStartedDispatch(ctx, db, f.request, f.barrier, abandonedAllow); err == nil {
		t.Fatal("abandoned lane accepted a finalization-lost terminal")
	}
	for _, statement := range []string{
		`UPDATE public.capacity_dispatch_jobs SET state='started',finalization_lost_disposition_id=NULL WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET state='unknown',finalization_lost_disposition_id=NULL WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET updated_at=clock_timestamp() WHERE id=$1`,
		`UPDATE public.capacity_dispatch_jobs SET returned_at=clock_timestamp() WHERE id=$1`,
		`UPDATE public.capacity_dispatch_finalization_lost_dispositions SET operator_evidence='forged' WHERE job_id=$1`,
		`DELETE FROM public.capacity_dispatch_finalization_lost_dispositions WHERE job_id=$1`,
	} {
		if _, execErr := db.Exec(statement, f.envelope.JobID); execErr == nil {
			t.Fatal("terminal history mutated", statement)
		}
	}
	for _, statement := range []string{
		`UPDATE public.workflow_runs SET status='succeeded' WHERE id=$1`,
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
	if err != nil || duplicate || job.JobID != next.JobID || job.State != "queued" {
		_ = tx.Rollback()
		t.Fatal("dimension still blocked after disposal", err, duplicate)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizationLostDispatchPostgresRefusedEffects(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cases := []struct {
		name    string
		options abandonedDispatchFixtureOptions
		effects *finalizationLostEffects
		mutate  func(*abandonedDispatchFixture) error
	}{
		{name: "intent_leased", effects: &finalizationLostEffects{intentLeased: true}},
		{name: "intent_decision_not_hold", effects: &finalizationLostEffects{intentAction: "drain"}},
		{name: "intent_phase_moved_without_event", effects: &finalizationLostEffects{intentPhase: "draining", eventPhase: "promoted"}},
		{name: "intent_phase_unprovable_without_event", effects: &finalizationLostEffects{noEvent: true}},
		{name: "intent_written_after_lease", effects: &finalizationLostEffects{intentAfterLease: true}},
		{name: "slot_tombstone", effects: &finalizationLostEffects{slotTombstone: true}},
		{name: "slot_newly_inserted", effects: &finalizationLostEffects{slotRevision: 1}},
		{name: "slot_resource_created_after_start", effects: &finalizationLostEffects{slotCreatedAfter: true}},
		{name: "slot_observation_not_fresh", effects: &finalizationLostEffects{slotObservedBefore: true}},
		{name: "slot_authority_record", effects: &finalizationLostEffects{slotAuthority: true}},
		{name: "slot_written_after_lease", effects: &finalizationLostEffects{slotAfterLease: true}},
		{name: "slot_record_resource_mismatch", effects: &finalizationLostEffects{slotResourceMissing: true}},
		{name: "intent_event_after_start", effects: &finalizationLostEffects{}, mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref,recorded_at) VALUES($1,$2,$3,$4,8,21,'promoted','after-start',$5)`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, f.start.Add(time.Second))
			return err
		}},
		{name: "grant_after_start", effects: &finalizationLostEffects{}, mutate: func(f *abandonedDispatchFixture) error {
			_, err := db.Exec(`INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,8,$6,'finalization-scope','notify-aws-elastic',1,'confirmed','{}'::jsonb,$7,$8)`,
				uuid.New(), f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, uuid.New(), f.start.Add(time.Hour), f.start.Add(time.Second))
			return err
		}},
		{name: "original_notify_window_marker_for_job", effects: nil, mutate: func(f *abandonedDispatchFixture) error {
			marker := `{"generation":8,"fencing_token":21,"phase":"promoted","decision":{"action":"hold"},"original_notify_window":{"dispatch_job_id":"` + f.envelope.JobID.String() + `"}}`
			_, err := db.Exec(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, f.envelope.Realm, f.envelope.Environment, f.envelope.Domain, f.envelope.Dimension, marker, f.start.Add(-time.Hour))
			return err
		}},
		{name: "lease_younger_than_fifteen_minutes", options: abandonedDispatchFixtureOptions{start: time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)}, effects: &finalizationLostEffects{}},
		{name: "job_unknown_with_return", options: abandonedDispatchFixtureOptions{jobState: "unknown"}, effects: &finalizationLostEffects{}},
		{name: "run_not_running", options: abandonedDispatchFixtureOptions{runStatus: "cancelled"}, effects: &finalizationLostEffects{}},
		{name: "barrier_process_started_before_lease_expiry", effects: &finalizationLostEffects{}, mutate: func(f *abandonedDispatchFixture) error {
			f.barrier.ProcessStartedAt = f.lease.Add(-time.Second)
			return nil
		}},
		{name: "scope_name_with_divergent_lock_encoding", options: abandonedDispatchFixtureOptions{domain: "notify&guest"}, effects: &finalizationLostEffects{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := abandonedDispatchPGFixture(t, db, c.options)
			if c.effects != nil {
				f.tolerated(t, *c.effects)
			}
			if c.mutate != nil {
				if err := c.mutate(&f); err != nil {
					t.Fatal("fixture mutation", err)
				}
			}
			f.jobSnapshot, f.runSnapshot = f.snapshot(t)
			if _, err := DisposeFinalizationLostStartedDispatch(ctx, db, f.finalizationLostRequest(), f.barrier, abandonedAllow); err == nil {
				t.Fatal("refused effect or precondition accepted")
			}
			f.assertFinalizationLostUntouched(t)
		})
	}
}

func TestFinalizationLostDispatchPostgresStaleCASAndEvidence(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{pendingWake: 7})
	f.tolerated(t, finalizationLostEffects{})
	f.jobSnapshot, f.runSnapshot = f.snapshot(t)
	mutations := map[string]func(*CapacityDispatchFinalizationLostDispositionRequest){
		"run": func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.ExpectedRunID = uuid.New() },
		"envelope": func(r *CapacityDispatchFinalizationLostDispositionRequest) {
			r.ExpectedEnvelopeSHA256 = strings.Repeat("0", 64)
		},
		"fence":       func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.ExpectedFencingToken = 2 },
		"owner":       func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.ExpectedLeaseOwner = uuid.New() },
		"wakes":       func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.ExpectedPendingWakeCount = 8 },
		"job":         func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.JobID = uuid.New() },
		"issuer":      func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.Issuer = "machine:finalization" },
		"no_issuer":   func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.Issuer = "" },
		"no_evidence": func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.Evidence = "" },
		"blank_evidence": func(r *CapacityDispatchFinalizationLostDispositionRequest) {
			r.Evidence = " \n\t "
		},
		"oversize_evidence": func(r *CapacityDispatchFinalizationLostDispositionRequest) {
			r.Evidence = strings.Repeat("x", CapacityDispatchFinalizationLostEvidenceMax+1)
		},
		"control_evidence": func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.Evidence = "log\x00line" },
		"invalid_utf8":     func(r *CapacityDispatchFinalizationLostDispositionRequest) { r.Evidence = "log\xffline" },
	}
	for name, mutate := range mutations {
		request := f.finalizationLostRequest()
		mutate(&request)
		if _, err := DisposeFinalizationLostStartedDispatch(ctx, db, request, f.barrier, abandonedAllow); err == nil {
			t.Fatal("stale CAS or invalid evidence accepted", name)
		}
		f.assertFinalizationLostUntouched(t)
	}
	if _, err := DisposeFinalizationLostStartedDispatch(ctx, db, f.finalizationLostRequest(), f.barrier, func(context.Context) error { return errors.New("revoked") }); err == nil {
		t.Fatal("operator no longer current accepted")
	}
	f.assertFinalizationLostUntouched(t)
	if _, err := DisposeFinalizationLostStartedDispatch(ctx, db, f.finalizationLostRequest(), f.barrier, abandonedAllow); err != nil {
		t.Fatal("exact CAS refused after stale attempts", err)
	}
}

func TestFinalizationLostDispatchMigration84Guards(t *testing.T) {
	db := originalDispositionPG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var schema int
	if err := db.QueryRow(`SELECT max(version_id) FROM public.goose_db_version WHERE is_applied`).Scan(&schema); err != nil || schema != 86 {
		t.Fatal("owning schema86 required", schema, err)
	}
	f := abandonedDispatchPGFixture(t, db, abandonedDispatchFixtureOptions{})
	f.tolerated(t, finalizationLostEffects{})
	f.jobSnapshot, f.runSnapshot = f.snapshot(t)
	// A job carrying a finalization-lost disposition can never be inserted directly.
	e := abandonedDispatchEnvelope(t, f.envelope.Realm+"-x", time.Now().UTC().Format(time.RFC3339Nano))
	envelope, _ := encodeCapacityDispatchEnvelope(e)
	if _, err := db.Exec(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,inputs,metadata) VALUES($1,'running',$2,'original',1,$3,'{}'::jsonb,'{}'::jsonb)`, e.RunID, e.Realm, f.start); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,finalization_lost_disposition_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'started',$11,1,$12,$13,$14)`,
		e.JobID, e.RunID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.lease, f.start, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "finalization-lost disposition requires a retained original started job") {
		t.Fatal("direct disposition-linked insert was not refused by its trigger", err)
	}
	if _, err := db.Exec(`UPDATE public.capacity_dispatch_jobs SET state='finalization_lost_disposed' WHERE id=$1`, f.envelope.JobID); err == nil {
		t.Fatal("receipt-less terminal accepted")
	}
	insertReceipt := func(tx *sql.Tx, evidenceSHA, scan string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_finalization_lost_dispositions(id,job_id,run_id,realm,environment,domain,dimension,envelope_sha256,fencing_token,lease_owner,lease_expires_at,started_at,pending_wake_count,original_dispatch_sha256,original_run_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,minimum_lease_age_seconds,recorded_at,issuer,reason,return_observation,historical_return,run_status,run_error,operator_evidence,operator_evidence_sha256,provider_mutation_evidence)
SELECT $1,j.id,j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count,
 encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),
 $3,$4,'finalization-fixture-core',4242,'',900,clock_timestamp(),$5,$6,$7,'unknown','failed',$8,$9,COALESCE($10,encode(sha256(convert_to($9,'UTF8')),'hex')),COALESCE($11::jsonb,public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at))
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$2`,
			uuid.New(), f.envelope.JobID, CapacityDispatchAbandonedBarrier, f.lease.Add(time.Minute), f.request.Issuer, CapacityDispatchFinalizationLostReason,
			CapacityDispatchFinalizationLostObservation, CapacityDispatchFinalizationLostRunError, finalizationLostEvidence, nullableText(evidenceSHA), nullableText(scan))
		return err
	}
	for name, values := range map[string][2]string{
		"forged_evidence_digest": {strings.Repeat("0", 64), ""},
		"forged_effect_scan":     {"", `{"schema":"finalization_lost_dispatch_effect_scan_v1","base_schema":"abandoned_started_dispatch_effect_scan_v2","clock_skew_margin_seconds":30,"provider_read_performed":false,"provider_quiescence_proved":false,"intents_updated_since_start":0,"resource_slots_updated_since_start":0,"pure_assessment_intent_updates":0,"observation_refresh_slot_updates":0}`},
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
	f.assertFinalizationLostUntouched(t)
	// The real lane still succeeds on the untouched original.
	if _, err = DisposeFinalizationLostStartedDispatch(ctx, db, f.finalizationLostRequest(), f.barrier, abandonedAllow); err != nil {
		t.Fatal("guards blocked the exact lane", err)
	}
}
