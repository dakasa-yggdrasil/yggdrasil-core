package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func migration74Record(t *testing.T, ctx context.Context, tx *sql.Tx, f nativeDeniedFixture) (model.CapacityNativeDeniedDisposition, nativeDeniedDispositionSnapshot) {
	t.Helper()
	snap, err := loadNativeDeniedDispositionSnapshot(ctx, tx, f.pre.OriginalCreateGrantID, f.jobID.String())
	if err != nil {
		t.Fatal("snapshot", err)
	}
	c := snap.candidate
	o := &NativeDeniedDispositionOwner{grantID: f.pre.OriginalCreateGrantID, jobID: f.jobID.String(), issuer: "collaborator:" + uuid.NewString()}
	observation := nativeDeniedEvidence(t, model.CapacityNativeDeniedCandidate{Original: c, Request: snap.request})
	result := model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedDispositionSchema, ID: uuid.NewString(), GrantID: o.grantID, PreregistrationID: c.Preregistration.PreregistrationID, JobID: o.jobID, RunID: snap.job.RunID.String(), Issuer: o.issuer,
		OriginalGrantSHA256: c.OriginalGrantSHA256, OriginalPreregistrationSHA256: c.OriginalPreregistrationSHA256, OriginalSettlementSHA256: c.OriginalSettlementSHA256, OriginalBindingSHA256: c.OriginalBindingSHA256, OriginalPolicySHA256: c.OriginalPolicySHA256, OriginalWorkflowSHA256: c.OriginalWorkflowSHA256, OriginalDispatchSHA256: snap.dispatchSHA, OriginalRunSHA256: snap.runSHA,
		OriginalGeneration: snap.record.Generation, OriginalFencingToken: snap.record.FencingToken, ClosedGeneration: snap.intent.Generation, ClosedFencingToken: snap.intent.FencingToken + 1, OriginalDeadline: c.Preregistration.OriginalDeadline, HistoricalCoreSourceCommit: c.Preregistration.CoreSourceCommit,
		Observation: observation, ObservationSHA256: originalDispositionJSONSHA(observation), RecordedAt: snap.now, OriginalUncertainAndNullIdentitiesUnchanged: true, OriginalUnknownACKPreserved: true, WitnessEnrollmentInstallationAbsent: true}
	return result, snap
}
func migration74Insert(ctx context.Context, tx *sql.Tx, result model.CapacityNativeDeniedDisposition) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return migration74InsertWire(ctx, tx, result, raw)
}

// This direct SQL seam re-closes the supplied wire digest after deliberate JSON
// field deletion; the database must reject forgery independently of Go parsing.
func migration74InsertWire(ctx context.Context, tx *sql.Tx, result model.CapacityNativeDeniedDisposition, raw []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_native_denied_dispositions(id,grant_id,preregistration_id,job_id,run_id,original_grant_sha256,original_preregistration_sha256,original_dispatch_sha256,original_run_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15)`, result.ID, result.GrantID, result.PreregistrationID, result.JobID, result.RunID, result.OriginalGrantSHA256, result.OriginalPreregistrationSHA256, result.OriginalDispatchSHA256, result.OriginalRunSHA256, originalDispositionDigest(raw), raw, string(raw), result.RecordedAt, result.ClosedGeneration, result.ClosedFencingToken)
	return err
}
func migration74Projections(t *testing.T, tx *sql.Tx, v model.CapacityNativeDeniedDisposition, s nativeDeniedDispositionSnapshot, omit string) {
	t.Helper()
	if omit != "grant" {
		if _, e := tx.Exec(`UPDATE public.capacity_mutation_grants SET native_denied_disposition_id=$2 WHERE id=$1`, v.GrantID, v.ID); e != nil {
			t.Fatal(e)
		}
	}
	if omit != "job" {
		if _, e := tx.Exec(`UPDATE public.capacity_dispatch_jobs SET state='native_denied_disposed',native_denied_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1`, v.JobID, v.ID); e != nil {
			t.Fatal(e)
		}
	}
	if omit != "intent" {
		i := s.intent
		i.Phase = "reconciled_failed_floor"
		i.FloorDegraded = true
		i.RecoveryOnly = false
		i.Decision.ExecutionPermitted = false
		i.FencingToken = v.ClosedFencingToken
		i.LeaseOwner = ""
		i.LeaseExecutorID = ""
		i.LeaseExpiresAt = nil
		raw, _ := json.Marshal(i)
		if _, e := tx.Exec(`UPDATE public.capacity_intents SET intent=$5::jsonb WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, i.Namespace, i.Environment, i.Domain, i.Dimension, string(raw)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestNativeDeniedDispositionMigration74DeferredLinks(t *testing.T) {
	db := originalDispositionPG(t)
	for _, omit := range []string{"grant", "job", "intent", "none"} {
		t.Run(omit, func(t *testing.T) {
			f := nativeDeniedPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			v, s := migration74Record(t, ctx, tx, f)
			if e = migration74Insert(ctx, tx, v); e != nil {
				t.Fatal("insert", e)
			}
			migration74Projections(t, tx, v, s, omit)
			_, e = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			if (e == nil) != (omit == "none") {
				t.Fatal("incomplete atomic links", omit, e)
			}
		})
	}
}
func TestNativeDeniedDispositionMigration74RejectsForgedDecision(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"grant_hash", "dispatch_hash", "uncertain_preserved", "ACK_preserved", "witness_absence", "original_HTTP", "foreign_token", "not_denied", "serving_authority", "native_mutation", "observation_times_missing", "observation_times_null", "denied_time_missing", "read_times_STS_missing", "read_times_CloudTrail_missing", "read_times_EC2_missing", "read_times_EC2_null", "EC2_body_triplet_missing", "EC2_body_triplet_null", "EC2_body_wrong_type", "EC2_bytes_wrong_type", "EC2_digest_wrong_type"} {
		t.Run(name, func(t *testing.T) {
			f := nativeDeniedPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			v, _ := migration74Record(t, ctx, tx, f)
			switch name {
			case "grant_hash":
				v.OriginalGrantSHA256 = strings.Repeat("0", 64)
			case "dispatch_hash":
				v.OriginalDispatchSHA256 = strings.Repeat("0", 64)
			case "uncertain_preserved":
				v.OriginalUncertainAndNullIdentitiesUnchanged = false
			case "ACK_preserved":
				v.OriginalUnknownACKPreserved = false
			case "witness_absence":
				v.WitnessEnrollmentInstallationAbsent = false
			case "original_HTTP":
				v.Observation.OriginalHTTPResponseAvailable = true
			case "foreign_token":
				v.Observation.ClientToken = strings.Repeat("0", 64)
			case "not_denied":
				nativeDeniedMutateCT(t, &v.Observation, func(_ map[string]any, e map[string]any) { e["errorCode"] = "ThrottlingException" })
			case "serving_authority":
				v.ServingOrBusinessOrSavingsAuthority = true
			case "native_mutation":
				v.Observation.NativeMutations = 1
			}
			raw, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			var wire map[string]any
			if e = json.Unmarshal(raw, &wire); e != nil {
				t.Fatal(e)
			}
			observation := wire["observation"].(map[string]any)
			reads := observation["native_reads"].([]any)
			expectedGuard := ""
			switch name {
			case "observation_times_missing", "observation_times_null":
				for _, k := range []string{"observation_started_at", "observed_at"} {
					delete(observation, k)
					if name == "observation_times_null" {
						observation[k] = nil
					}
				}
				expectedGuard = "typed read-only decision evidence"
			case "denied_time_missing":
				delete(observation, "denied_at")
				expectedGuard = "typed read-only decision evidence"
			case "read_times_STS_missing", "read_times_CloudTrail_missing", "read_times_EC2_missing", "read_times_EC2_null":
				i := 2
				if name == "read_times_STS_missing" {
					i = 0
				}
				if name == "read_times_CloudTrail_missing" {
					i = 1
				}
				read := reads[i].(map[string]any)
				for _, k := range []string{"called_at", "returned_at"} {
					delete(read, k)
					if name == "read_times_EC2_null" {
						read[k] = nil
					}
				}
				expectedGuard = "HTTP time ordering"
			case "EC2_body_triplet_missing", "EC2_body_triplet_null":
				read := reads[len(reads)-1].(map[string]any)
				for _, k := range []string{"response_body_base64", "response_bytes", "response_sha256"} {
					delete(read, k)
					if name == "EC2_body_triplet_null" {
						read[k] = nil
					}
				}
				expectedGuard = "typed body and digest"
			case "EC2_body_wrong_type":
				reads[len(reads)-1].(map[string]any)["response_body_base64"] = 1
				expectedGuard = "typed body and digest"
			case "EC2_bytes_wrong_type":
				read := reads[len(reads)-1].(map[string]any)
				read["response_bytes"] = "1"
				expectedGuard = "typed body and digest"
			case "EC2_digest_wrong_type":
				reads[len(reads)-1].(map[string]any)["response_sha256"] = nil
				expectedGuard = "typed body and digest"
			}
			wire["observation_sha256"] = originalDispositionJSONSHA(observation)
			raw, e = json.Marshal(wire)
			if e != nil {
				t.Fatal(e)
			}
			if e = migration74InsertWire(ctx, tx, v, raw); e == nil {
				t.Fatal("forged decision accepted", name)
			}
			if expectedGuard != "" && !strings.Contains(e.Error(), expectedGuard) {
				t.Fatal("forgery did not reach its independent SQL guard", name, e)
			}
		})
	}
}
func TestNativeDeniedDispositionMigration74ClosedHistoryImmutable(t *testing.T) {
	db := originalDispositionPG(t)
	f := nativeDeniedPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	o, e := f.store.BeginNativeDeniedDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
	if e != nil {
		t.Fatal(e)
	}
	v, e := f.store.CompleteNativeDeniedDisposition(ctx, o, nativeDeniedEvidence(t, o.Candidate()))
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`UPDATE public.capacity_mutation_grants SET native_denied_disposition_id=NULL WHERE id=$1`, []any{v.GrantID}},
		{`UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{settlement,outcome}','"accepted"') WHERE id=$1`, []any{v.GrantID}},
		{`UPDATE public.capacity_dispatch_jobs SET state='returned',finalization_ack_at=clock_timestamp() WHERE id=$1`, []any{v.JobID}},
		{`UPDATE public.workflow_runs SET status='succeeded' WHERE id=$1`, []any{v.RunID}},
		{`UPDATE public.capacity_vm_provisioning_preregistrations SET original_deadline=clock_timestamp()+interval '1 hour' WHERE id=$1`, []any{v.PreregistrationID}},
		{`INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id)VALUES($1)`, []any{v.PreregistrationID}},
		{`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id)VALUES($1)`, []any{v.PreregistrationID}},
		{`DELETE FROM public.capacity_native_denied_dispositions WHERE id=$1`, []any{v.ID}},
	} {
		if _, e = db.Exec(q.query, q.args...); e == nil {
			t.Fatal("immutable terminal changed", q.query)
		}
	}
}
