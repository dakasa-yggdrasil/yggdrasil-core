package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// The existing dedicated Unix-only PG harness installs the exact predecessor
// migrations. This successor applies only75, once, in that isolated database.
func nativeDeniedACKPG(t *testing.T) *sql.DB {
	t.Helper()
	db := originalDispositionPG(t)
	var exists bool
	if err := db.QueryRow(`SELECT to_regprocedure('public.native_denied_original_ack_matches(jsonb,text,timestamptz,timestamptz,timestamptz,text)') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "00075_native_denied_failed_returned_ack_dispositions.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.Split(string(raw), "-- +goose Down")[0]); err != nil {
			t.Fatal("migration75", err)
		}
	}
	return db
}

func nativeDeniedReturnedACKPGFixture(t *testing.T, db *sql.DB) nativeDeniedFixture {
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
	finish := f.pre.ReservedAt.Add(3 * time.Second)
	ack := finish.Add(time.Millisecond)
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
	must(`INSERT INTO public.capacity_dispatch_jobs(id,run_id,protocol,realm,environment,domain,dimension,source_tick,envelope,envelope_sha256,state,lease_owner,fencing_token,lease_expires_at,started_at,returned_at,return_status,return_error,finalization_error,finalization_ack_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'returned',$11,1,$12,$13,$14,'failed','original Create failed',NULL,$15)`, jobID, runID, e.Protocol, e.Realm, e.Environment, e.Domain, e.Dimension, e.SourceTick, string(envelope), capacityDispatchSHA(envelope), uuid.New(), f.pre.OriginalDeadline, start, finish, ack)
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

func migration75Record(t *testing.T, ctx context.Context, tx *sql.Tx, f nativeDeniedFixture) (model.CapacityNativeDeniedDisposition, nativeDeniedDispositionSnapshot) {
	t.Helper()
	v, s := migration74Record(t, ctx, tx, f)
	ack := s.job.FinalizationAckAt.UTC()
	v.Schema = model.NativeDeniedReturnedACKDispositionSchema
	v.OriginalUnknownACKPreserved = false
	v.OriginalDispatchState = "returned"
	v.OriginalFinalizationACKAt = &ack
	v.OriginalFailedWorkflowACKPreserved = true
	return v, s
}

func TestNativeDeniedReturnedACKPostgresLanesAndFence(t *testing.T) {
	db := nativeDeniedACKPG(t)
	for _, returned := range []bool{false, true} {
		f := nativeDeniedPGFixture(t, db)
		if returned {
			f = nativeDeniedReturnedACKPGFixture(t, db)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		owner, err := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
		if err != nil {
			cancel()
			t.Fatal("begin", returned, err)
		}
		stale, err := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var beforeACK sql.NullTime
		var beforeOther string
		if err = db.QueryRow(`SELECT finalization_ack_at,(to_jsonb(j)-ARRAY['state','updated_at','native_denied_disposition_id'])::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, f.jobID).Scan(&beforeACK, &beforeOther); err != nil {
			cancel()
			t.Fatal(err)
		}
		v, err := f.store.CompleteNativeDeniedDisposition(ctx, owner, nativeDeniedEvidence(t, owner.Candidate()))
		if err != nil {
			cancel()
			t.Fatal("complete", returned, err)
		}
		read, err := f.store.ReadNativeDeniedDisposition(ctx, v.GrantID)
		if err != nil || originalDispositionJSONSHA(read) != originalDispositionJSONSHA(v) {
			cancel()
			t.Fatal("read", returned, err)
		}
		var ack sql.NullTime
		var other, grant, run string
		if err = db.QueryRow(`SELECT finalization_ack_at,(to_jsonb(j)-ARRAY['state','updated_at','native_denied_disposition_id'])::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, f.jobID).Scan(&ack, &other); err != nil || other != beforeOther || ack.Valid != beforeACK.Valid || ack.Valid && !ack.Time.Equal(beforeACK.Time) {
			cancel()
			t.Fatal("original dispatch/ACK rewritten", err)
		}
		if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, v.GrantID).Scan(&grant); err != nil || grant != f.rawGrant {
			cancel()
			t.Fatal("uncertain settlement rewritten", err)
		}
		if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, v.RunID).Scan(&run); err != nil || run != f.originalRun {
			cancel()
			t.Fatal("failed nullable-workflow run rewritten", err)
		}
		if returned {
			if v.Schema != model.NativeDeniedReturnedACKDispositionSchema || !ack.Valid || !nativeDeniedDispositionACKMatches(v, &ack.Time) {
				cancel()
				t.Fatal("returned ACK relabelled unknown")
			}
		} else if v.Schema != model.NativeDeniedDispositionSchema || !nativeDeniedDispositionACKMatches(v, nil) {
			cancel()
			t.Fatal("V1 changed")
		}
		if _, err = f.store.CompleteNativeDeniedDisposition(ctx, stale, nativeDeniedEvidence(t, stale.Candidate())); err == nil {
			cancel()
			t.Fatal("stale owner accepted")
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(f.policy.Spec, &p) != nil {
			cancel()
			t.Fatal("policy")
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		b := f.record.Binding
		b.IntegrationInstanceID = uuid.NewString()
		b.ScopeChecksum = strings.Repeat("9", 64)
		for _, row := range []struct {
			g, f int64
			ok   bool
		}{{v.ClosedGeneration, v.ClosedFencingToken + 1, false}, {v.ClosedGeneration + 1, v.ClosedFencingToken, false}, {v.ClosedGeneration + 1, v.ClosedFencingToken + 1, true}} {
			e := requireOriginalDispositionSuccessorTx(ctx, tx, f.policy.Metadata.Namespace, p, b, f.record.Grant.Slot, row.g, row.f)
			if (e == nil) != row.ok {
				tx.Rollback()
				cancel()
				t.Fatal("logical successor fence", returned, row, e)
			}
		}
		tx.Rollback()
		cancel()
	}
}

func TestNativeDeniedReturnedACKMigration75DeferredAndForged(t *testing.T) {
	db := nativeDeniedACKPG(t)
	for _, name := range []string{"none", "omit_grant", "omit_job", "omit_intent", "ACK_missing", "ACK_null", "ACK_changed", "unknown_claim", "wrong_state", "preserved_false", "V1_relabel", "successful_workflow", "unknown_relabelled_V2"} {
		t.Run(name, func(t *testing.T) {
			var f nativeDeniedFixture
			if name == "unknown_relabelled_V2" {
				f = nativeDeniedPGFixture(t, db)
			} else {
				f = nativeDeniedReturnedACKPGFixture(t, db)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var v model.CapacityNativeDeniedDisposition
			var s nativeDeniedDispositionSnapshot
			if name == "unknown_relabelled_V2" {
				v, s = migration74Record(t, ctx, tx, f)
				ack := f.pre.ReservedAt.Add(4 * time.Second)
				v.Schema = model.NativeDeniedReturnedACKDispositionSchema
				v.OriginalUnknownACKPreserved = false
				v.OriginalDispatchState = "returned"
				v.OriginalFinalizationACKAt = &ack
				v.OriginalFailedWorkflowACKPreserved = true
			} else {
				v, s = migration75Record(t, ctx, tx, f)
			}
			if name == "successful_workflow" {
				if _, err = tx.Exec(`UPDATE public.workflow_runs SET status='succeeded',result=jsonb_set(result,'{status}','"succeeded"') WHERE id=$1`, f.runID); err != nil {
					t.Fatal(err)
				}
				var changed []byte
				if err = tx.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&changed); err != nil {
					t.Fatal(err)
				}
				// Re-close the changed run digest: the SQL failure guard, rather
				// than a stale hash, must still reject successful workflows.
				v.OriginalRunSHA256 = originalDispositionDigest(changed)
			}
			raw, _ := json.Marshal(v)
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("wire")
			}
			switch name {
			case "ACK_missing":
				delete(m, "original_finalization_ack_at")
			case "ACK_null":
				m["original_finalization_ack_at"] = nil
			case "ACK_changed":
				m["original_finalization_ack_at"] = v.OriginalFinalizationACKAt.Add(time.Microsecond).Format(time.RFC3339Nano)
			case "unknown_claim":
				m["original_unknown_ACK_preserved"] = true
			case "wrong_state":
				m["original_dispatch_state"] = "unknown"
			case "preserved_false":
				m["original_failed_workflow_ACK_preserved"] = false
			case "V1_relabel":
				m["schema"] = model.NativeDeniedDispositionSchema
				m["original_unknown_ACK_preserved"] = true
				delete(m, "original_dispatch_state")
				delete(m, "original_finalization_ack_at")
				delete(m, "original_failed_workflow_ACK_preserved")
			}
			raw, _ = json.Marshal(m)
			err = migration74InsertWire(ctx, tx, v, raw)
			forged := !strings.HasPrefix(name, "omit_") && name != "none"
			if forged {
				if err == nil {
					t.Fatal("reclosed forged ACK accepted", name)
				}
				return
			}
			if err != nil {
				t.Fatal("valid insert", err)
			}
			omit := strings.TrimPrefix(name, "omit_")
			migration74Projections(t, tx, v, s, omit)
			_, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			if (err == nil) != (name == "none") {
				t.Fatal("atomic links", name, err)
			}
		})
	}
}

func TestNativeDeniedReturnedACKPostgresImmutableHistory(t *testing.T) {
	db := nativeDeniedACKPG(t)
	f := nativeDeniedReturnedACKPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.store.CompleteNativeDeniedDisposition(ctx, owner, nativeDeniedEvidence(t, owner.Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		q    string
		args []any
	}{
		{`UPDATE public.capacity_dispatch_jobs SET finalization_ack_at=NULL WHERE id=$1`, []any{v.JobID}},
		{`UPDATE public.capacity_dispatch_jobs SET finalization_ack_at=finalization_ack_at+interval '1 microsecond' WHERE id=$1`, []any{v.JobID}},
		{`UPDATE public.capacity_dispatch_jobs SET state='returned' WHERE id=$1`, []any{v.JobID}},
		{`UPDATE public.workflow_runs SET status='succeeded' WHERE id=$1`, []any{v.RunID}},
		{`UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,outcome}','"accepted"') WHERE id=$1`, []any{v.GrantID}},
		{`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id)VALUES($1)`, []any{v.PreregistrationID}},
		{`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id)VALUES($1)`, []any{v.PreregistrationID}},
		{`DELETE FROM public.capacity_native_denied_dispositions WHERE id=$1`, []any{v.ID}},
	} {
		if _, e := db.Exec(row.q, row.args...); e == nil {
			t.Fatal("immutable failed ACK history changed", row.q)
		}
	}
	if _, err = f.store.BeginNativeDeniedDisposition(ctx, v.GrantID, v.JobID, "collaborator:"+uuid.NewString()); err == nil {
		t.Fatal("terminal reopened")
	}
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "00075_native_denied_failed_returned_ack_dispositions.sql"))
	if err != nil {
		t.Fatal(err)
	}
	down := strings.Split(string(raw), "-- +goose Down")[1]
	if _, err = db.Exec(down); err == nil {
		t.Fatal("V2 history downgraded into V1")
	}
}
