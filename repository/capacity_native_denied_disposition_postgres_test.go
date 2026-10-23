package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeDeniedFixture struct {
	dispositionPGFixture
	jobID, runID                  uuid.UUID
	originalDispatch, originalRun string
}

func nativeDeniedPGFixture(t *testing.T, db *sql.DB) nativeDeniedFixture {
	t.Helper()
	f := originalDispositionPGFixture(t, db)
	f.record.Binding.OriginalProviderSourceCommit = nativeDeniedOriginalAWSCreator
	f.record.Settlement = &model.CapacityMutationSettleRequest{GrantID: f.pre.OriginalCreateGrantID, AttemptID: f.record.AttemptID, RequestSHA256: f.record.Grant.RequestSHA256, Outcome: "uncertain", TransportCompleted: true, ObservedAt: f.pre.ReservedAt.Add(2 * time.Second).Format(time.RFC3339Nano)}
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		t.Fatal("policy")
	}
	p.Profiles[0].Region = "us-east-1"
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
	result.Steps = []model.WorkflowRunStepResult{{ID: "plan-original-guest", Status: "succeeded", Metadata: map[string]any{"generation": f.record.Generation, "fencing_token": f.record.FencingToken, "lease_owner": f.record.LeaseOwner}}, {ID: f.pre.OriginalWorkflowStepID, Status: "failed", Error: "original Guest reconciliation held", Metadata: map[string]any{"original_guest_refusal_predicate": "original-guest-step-25"}}}
	resultRaw, _ := json.Marshal(result)
	inputsRaw, _ := json.Marshal(e.Inputs)
	metadataRaw, _ := json.Marshal(e.Metadata)

	grantRaw, _ := json.Marshal(f.record)
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`UPDATE public.manifests SET spec=$2::jsonb WHERE id=$1`, f.policy.ID, string(policyRaw))
	must(`UPDATE public.capacity_mutation_grants SET grant_record=$2::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, string(grantRaw))
	must(`INSERT INTO public.workflow_runs(id,status,workflow_namespace,workflow_name,workflow_version,started_at,finished_at,result,error,inputs,metadata) VALUES($1,'failed',$2,'original',1,$3,$4,$5::jsonb,'original Create failed',$6::jsonb,$7::jsonb)`, runID, f.policy.Metadata.Namespace, start, finish, string(resultRaw), string(inputsRaw), string(metadataRaw))
	must(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'unknown',$11,1,$12,$13,$14,'failed','original Create failed','original deadline elapsed')`, jobID, runID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.pre.OriginalDeadline, start, finish)
	var gd, jd, rd string
	if err := db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&gd); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, jobID).Scan(&jd); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, runID).Scan(&rd); err != nil {
		t.Fatal(err)
	}
	f.rawGrant = gd
	return nativeDeniedFixture{f, jobID, runID, jd, rd}
}

func nativeDeniedEvidence(t *testing.T, c model.CapacityNativeDeniedCandidate) model.CapacityNativeDeniedObservation {
	t.Helper()
	now := time.Now().UTC()
	q := c.Request
	o := model.CapacityNativeDeniedObservation{Schema: model.NativeDeniedObservationSchema, Request: q, AdapterSourceCommit: strings.Repeat("e", 40), AccountID: "153828470928", PrincipalARN: "arn:aws:iam::153828470928:user/scopedcapacity-provider-aws-20261021", Region: "us-east-1", ClientToken: originalDispositionDigest([]byte(q.GrantID + ":" + q.RequestSHA256)), EventID: uuid.NewString(), RequestID: uuid.NewString(), DeniedAt: q.SettlementObservedAt.Truncate(time.Second), Decision: "authorization_denied", HistoricalProfileRequestMatched: true, SameTokenInstancesEmpty: true, ObservationStartedAt: now, ObservedAt: now.Add(10 * time.Millisecond), NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{}}
	event := map[string]any{"eventID": o.EventID, "eventName": "RunInstances", "eventSource": "ec2.amazonaws.com", "eventTime": o.DeniedAt.Format(time.RFC3339), "awsRegion": o.Region, "recipientAccountId": o.AccountID, "requestID": o.RequestID, "errorCode": "Client.UnauthorizedOperation", "userIdentity": map[string]any{"type": "IAMUser", "accountId": o.AccountID, "arn": o.PrincipalARN}, "requestParameters": map[string]any{"clientToken": o.ClientToken}, "responseElements": nil}
	ev, _ := json.Marshal(event)
	page := map[string]any{"Events": []any{map[string]any{"EventId": o.EventID, "CloudTrailEvent": string(ev)}}}
	projection := map[string]any{"schema": "cloudtrail_lookup_events_userdata_omitted_projection_v1", "original_http_body_retained": false, "original_http_body_hashed": false, "original_eof_and_close": true, "user_data_fields_removed": 1, "response": page}
	ct, _ := json.Marshal(projection)
	sts := []byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>` + o.AccountID + `</Account><Arn>` + o.PrincipalARN + `</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	for i, x := range []struct {
		op, kind, id, representation string
		raw                          []byte
	}{{"GetCallerIdentity", "aws_account", o.AccountID, "raw_http_body_v1", sts}, {"LookupEvents", "aws_cloudtrail_event", o.ClientToken, "cloudtrail_lookup_events_userdata_omitted_projection_v1", ct}, {"DescribeInstances", "aws_ec2_instance", o.ClientToken, "raw_http_body_v1", []byte(originalDispositionEmptyInstancesXML)}} {
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: x.op, ResourceKind: x.kind, ResourceID: x.id, Status: 200, ResponseRepresentation: x.representation, ResponseBytes: int64(len(x.raw)), ResponseSHA256: originalDispositionDigest(x.raw), ResponseBodyBase64: base64.StdEncoding.EncodeToString(x.raw), CalledAt: now.Add(time.Duration(i) * time.Millisecond), ReturnedAt: now.Add(time.Duration(i)*time.Millisecond + time.Microsecond)})
	}
	return o
}
func TestNativeDeniedDispositionPostgresWholeLifecycle(t *testing.T) {
	db := originalDispositionPG(t)
	f := nativeDeniedPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	issuer := "collaborator:" + uuid.NewString()
	owner, e := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), issuer)
	if e != nil {
		t.Fatal("begin", e)
	}
	c := owner.Candidate()
	c.Request.GrantID = "foreign"
	if owner.Candidate().Request.GrantID == "foreign" {
		t.Fatal("alias")
	}
	v, e := f.store.CompleteNativeDeniedDisposition(ctx, owner, nativeDeniedEvidence(t, owner.Candidate()))
	if e != nil {
		t.Fatal("complete", e)
	}
	read, e := f.store.ReadNativeDeniedDisposition(ctx, v.GrantID)
	if e != nil || originalDispositionJSONSHA(read) != originalDispositionJSONSHA(v) {
		t.Fatal("recover only committed GET", e)
	}
	var gd, rd, state string
	var ack sql.NullTime
	if e = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, v.GrantID).Scan(&gd); e != nil || gd != f.rawGrant {
		t.Fatal("uncertain changed", e)
	}
	if e = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&rd); e != nil || rd != f.originalRun {
		t.Fatal("failed run changed", e)
	}
	if e = db.QueryRow(`SELECT state,finalization_ack_at FROM public.capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); e != nil || state != "native_denied_disposed" || ack.Valid {
		t.Fatal("late success ACK", e)
	}
	var raw []byte
	if e = db.QueryRow(`SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var next model.CapacityIntent
	if json.Unmarshal(raw, &next) != nil || next.Phase != "reconciled_failed_floor" || !next.FloorDegraded || next.Decision.ExecutionPermitted || next.FencingToken != f.intent.FencingToken+1 {
		t.Fatal("denial licensed new execution")
	}
	// A terminal denial closes this logical slot even after an IID/scope upgrade.
	var policy model.CapacityPolicySpec
	if e = json.Unmarshal(f.policy.Spec, &policy); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
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
		}{{v.ClosedGeneration, v.ClosedFencingToken + 1, false}, {v.ClosedGeneration + 1, v.ClosedFencingToken, false}, {v.ClosedGeneration + 1, v.ClosedFencingToken + 1, true}} {
			err := requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, policy, binding, f.record.Grant.Slot, scenario.generation, scenario.fence)
			if (err == nil) != scenario.allowed {
				t.Fatalf("denied successor upgrade=%v generation=%d fence=%d allowed=%v err=%v", upgrade, scenario.generation, scenario.fence, scenario.allowed, err)
			}
		}
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.BeginNativeDeniedDisposition(ctx, v.GrantID, f.jobID.String(), issuer); e == nil {
		t.Fatal("reopened")
	}
	if _, e = f.store.CompleteNativeDeniedDisposition(ctx, owner, v.Observation); e == nil {
		t.Fatal("owner reused")
	}
	if _, e = f.store.BeginOriginalCreateDisposition(ctx, v.GrantID, issuer); e == nil {
		t.Fatal("accepted lane reused")
	}
}
func TestNativeDeniedDispositionPostgresEligibility(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"accepted", "foreign_source", "resource_identity", "action", "witness", "enrollment", "installation", "wrong_step", "live_deadline", "foreign_workflow"} {
		t.Run(name, func(t *testing.T) {
			f := nativeDeniedPGFixture(t, db)
			q := ""
			var args []any
			switch name {
			case "accepted":
				q = `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,outcome}','"accepted"') WHERE id=$1`
				args = []any{f.pre.OriginalCreateGrantID}
			case "foreign_source":
				q = `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{binding,original_provider_source_commit}',to_jsonb($2::text)) WHERE id=$1`
				args = []any{f.pre.OriginalCreateGrantID, strings.Repeat("f", 40)}
			case "resource_identity":
				q = `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,resource_id}','"i-foreign"') WHERE id=$1`
				args = []any{f.pre.OriginalCreateGrantID}
			case "action":
				q = `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,action_id}','"foreign-action"') WHERE id=$1`
				args = []any{f.pre.OriginalCreateGrantID}
			case "witness":
				q = `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id)VALUES($1)`
				args = []any{f.pre.PreregistrationID}
			case "enrollment":
				q = `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id)VALUES($1)`
				args = []any{f.pre.PreregistrationID}
			case "installation":
				q = `INSERT INTO public.capacity_guest_original_installations(preregistration_id)VALUES($1)`
				args = []any{f.pre.PreregistrationID}
			case "wrong_step":
				q = `UPDATE public.workflow_runs SET result=jsonb_set(result,'{steps,1,metadata,original_guest_refusal_predicate}','"original-guest-step-29"') WHERE id=$1`
				args = []any{f.runID}
			case "live_deadline":
				q = `UPDATE public.capacity_vm_provisioning_preregistrations SET original_deadline=clock_timestamp()+interval '1 hour' WHERE id=$1`
				args = []any{f.pre.PreregistrationID}
			case "foreign_workflow":
				q = `UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`
				args = []any{f.runID, uuid.New()}
			}
			if _, e := db.Exec(q, args...); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, e := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString()); e == nil {
				t.Fatal("open boundary", name)
			}
		})
	}
}
func TestNativeDeniedDispositionPostgresConcurrentAndStaleCAS(t *testing.T) {
	db := originalDispositionPG(t)
	f := nativeDeniedPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	issuer := "collaborator:" + uuid.NewString()
	a, e := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), issuer)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), issuer)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, owner := range []*NativeDeniedDispositionOwner{a, b} {
		o := owner
		proof := nativeDeniedEvidence(t, o.Candidate())
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.store.CompleteNativeDeniedDisposition(ctx, o, proof)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatal("CAS did not have exactly one winner", passed)
	}
	f = nativeDeniedPGFixture(t, db)
	a, e = f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), issuer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{fencing_token}',to_jsonb(2)) WHERE namespace=$1`, f.policy.Metadata.Namespace); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.CompleteNativeDeniedDisposition(ctx, a, nativeDeniedEvidence(t, a.Candidate())); e == nil {
		t.Fatal("stale owner")
	}
}
