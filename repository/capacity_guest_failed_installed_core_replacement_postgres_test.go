package repository

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// Real migrated PG82 append-only storage and issuer-scope selection. All rows
// below are expressly synthetic local operands, never a production authority,
// accepted useful observation, signed V2 retirement or actual provider absence.
func TestFailedInstalledCoreReplacementPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	t.Run("optional_marker_closed_shape_and_no_retrofill", func(t *testing.T) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		f := guestOriginalStorageRecords(t)
		guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
		r := coreReplacementStorageMarker()
		r.Schema = "failed_installed_guest_disposal_v1"
		r.ID = uuid.NewString()
		r.Stage = "requested"
		r.Namespace = policy.Metadata.Namespace
		r.Environment = "production"
		r.Domain = "notify"
		r.Dimension = "local-Core-replacement"
		r.PreregistrationID = f.pre.PreregistrationID
		r.Issuer = "local-storage-only"
		r.OriginalRun = `{"status":"failed","preserved":true}`
		r.LastFailedRun = r.OriginalRun
		r.InstallationSHA256 = strings.Repeat("e", 64)
		r.EnrollmentSHA256 = strings.Repeat("f", 64)
		r.BusinessEffectsPreserved = true
		sha, e := insertFailedInstalledDisposalTx(ctx, tx, r)
		if e != nil {
			t.Fatal("new complete optional marker", e)
		}
		got, gotSHA, e := loadFailedInstalledDisposalTx(ctx, tx, r.ID, "requested")
		if e != nil || sha != gotSHA || got.OriginalFailedIssuerCoreSource != r.OriginalFailedIssuerCoreSource || got.ReplacementCoreSource != r.ActualCoreSource {
			t.Fatal("immutable distinct issuers", e)
		}
		claim := r
		claim.Stage = "claimed"
		claim.AdmissionSHA256 = sha
		claim.ClaimedIntent = &model.CapacityIntent{Generation: 8, FencingToken: 21}
		if _, e = insertFailedInstalledDisposalTx(ctx, tx, claim); e != nil {
			t.Fatal("new metadata preserved by old stage chain", e)
		}
		for _, name := range []string{"partial", "null", "same_Core", "wrong_request_Core", "unknown_mode", "legacy_mode", "unknown_key"} {
			t.Run(name, func(t *testing.T) {
				x := guestOriginalStorageRecords(t)
				guestOriginalStoragePre(t, tx, ctx, x, x.wire, x.wire, x.pre.OriginalDeadline)
				wire, _ := json.Marshal(r)
				var v map[string]any
				_ = json.Unmarshal(wire, &v)
				v["id"] = uuid.NewString()
				v["preregistration_id"] = x.pre.PreregistrationID
				switch name {
				case "partial":
					delete(v, "original_failed_issuer_core_source")
				case "null":
					v["replacement_core_source"] = nil
				case "same_Core":
					v["original_failed_issuer_core_source"] = r.ReplacementCoreSource
				case "wrong_request_Core":
					v["replacement_core_source"] = strings.Repeat("a", 40)
				case "unknown_mode":
					v["replacement_mode"] = "arbitrary"
				case "legacy_mode":
					v["retirement_mode"] = failedInstalledLegacyV1Mode
					v["blocked_guest_source"] = "548734eef627404f10b5117e0ec7f27582ae9048"
				case "unknown_key":
					v["old_failure_cause_fixed"] = true
				}
				wire, _ = json.Marshal(v)
				guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_guest_failed_installed_disposals(id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256)VALUES($1,'requested',$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, v["id"], r.Namespace, r.Environment, r.Domain, r.Dimension, v["preregistration_id"], wire, string(wire), capacity.BusinessCreationSHA256(wire))
			})
		}
		for _, field := range []string{"replacement_core_source", "original_failed_issuer_core_source"} {
			guestOriginalExpectedSQLRefusal(t, tx, ctx, `UPDATE public.capacity_guest_failed_installed_disposals SET original_record=jsonb_set(original_record,ARRAY[$2],to_jsonb($3::text)) WHERE id=$1`, r.ID, field, strings.Repeat("9", 40))
		}
		// A later stage cannot change the requested marker even if its individual
		// field shapes remain valid. This deliberately supplies no real V2 proof.
		bad := claim
		bad.Stage = "quiescent"
		bad.ReplacementCoreSource = strings.Repeat("9", 40)
		bad.ActualCoreSource = bad.ReplacementCoreSource
		bad.RetirementRequestID = uuid.NewString()
		bad.NativePoweroffSHA256 = strings.Repeat("8", 64)
		raw, _ := json.Marshal(bad)
		guestOriginalExpectedSQLRefusal(t, tx, ctx, `INSERT INTO public.capacity_guest_failed_installed_disposals(id,stage,namespace,environment,domain,dimension,preregistration_id,original_wire,original_record,record_sha256)VALUES($1,'quiescent',$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, bad.ID, bad.Namespace, bad.Environment, bad.Domain, bad.Dimension, bad.PreregistrationID, raw, string(raw), capacity.BusinessCreationSHA256(raw))
		if _, _, _, e = loadFailedInstalledQuiescentTx(ctx, tx, r.PreregistrationID, r.ID, ""); e == nil {
			t.Fatal("storage marker became native absence authority")
		}
	})
	t.Run("actual_issuer_query_is_original_run_scoped", func(t *testing.T) {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		f := guestOriginalStorageRecords(t)
		guestOriginalStorageChain(t, tx, ctx, f)
		at := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
		run := uuid.NewString()
		executor := uuid.NewString()
		source := strings.Repeat("1", 40)
		if _, e = tx.ExecContext(ctx, `INSERT INTO public.workflow_runs(id,workflow_namespace,workflow_name,workflow_id,status,created_at,finished_at)VALUES($1,'local','Core-replacement-scope',$2,'failed',$3,$4)`, run, policy.ID, at.Add(-time.Second), at.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
		// Exact immutable SQL scopes, not synthetic production signatures. The
		// production helper subsequently verifies full signed wire + approvals.
		pub, read := uuid.NewString(), uuid.NewString()
		for i, id := range []string{pub, read} {
			phase, schema, recordID, outcome := "publish", "guest_notify_business_canary_publish_challenge_v1", pub, "accepted"
			if i == 1 {
				phase = "read"
				schema = "guest_notify_business_canary_challenge_v1"
				outcome = "held"
			}
			c := map[string]any{"schema": schema, "issued_at": at, "original_deadline": at.Add(5 * time.Second), "challenge_id": id}
			wire, _ := json.Marshal(c)
			sha := capacity.BusinessCreationSHA256(wire)
			if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at)VALUES($1,$2,$3,$4,$5,$5,8,20,$6,'local',$7,$8,$9,$10::jsonb,$11,$12)`, id, f.pre.PreregistrationID, recordID, phase, policy.ID, executor, sha, capacity.BusinessCreationSHA256([]byte(id)), wire, string(wire), at.Add(5*time.Second), at); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,recorded_at)VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, id, outcome, sha, []byte(`{}`), at); e != nil {
				t.Fatal(e)
			}
			if i == 1 {
				if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at)VALUES($1,$2,$3,$4,$3)`, id, sha, at, at.Add(5*time.Second)); e != nil {
					t.Fatal(e)
				}
			}
			a := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": id, "issuer_actual_source_commit": source, "protocol_authority_source_commit": strings.Repeat("2", 40), "compatibility_map_sha256": strings.Repeat("3", 64), "profile": "notify-hetzner-elastic", "policy_id": policy.ID.String(), "workflow_id": policy.ID.String(), "executor_id": executor, "issued_wire_sha256": sha}
			awire, _ := json.Marshal(a)
			if _, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES('canary_challenge',$1,$2,$3,$4,'notify-hetzner-elastic',$5,$5,$6,$7,$8,$9::jsonb)`, id, source, strings.Repeat("2", 40), strings.Repeat("3", 64), policy.ID, executor, sha, awire, string(awire)); e != nil {
				t.Fatal(e)
			}
		}
		count := func(runID, preID, workflowID, policyID, owner string, generation, fence int64) int {
			t.Helper()
			rows, e := tx.QueryContext(ctx, failedInstalledOriginalCanaryIssuerQuery, runID, preID, workflowID, policyID, generation, fence, owner)
			if e != nil {
				t.Fatal(e)
			}
			n := 0
			for rows.Next() {
				var a, b, s, ps, x, px, h, ph string
				if e = rows.Scan(&a, &b, &s, &ps, &x, &px, &h, &ph); e != nil {
					t.Fatal(e)
				}
				if s != source || ps != source {
					t.Fatal("disposal or protocol issuer substituted")
				}
				n++
			}
			if e = rows.Err(); e != nil {
				t.Fatal(e)
			}
			if e = rows.Close(); e != nil {
				t.Fatal(e)
			}
			return n
		}
		if count(run, f.pre.PreregistrationID, policy.ID.String(), policy.ID.String(), executor, 8, 20) != 1 {
			t.Fatal("exact original immutable issuer not selected")
		}
		for _, name := range []string{"run", "pre", "workflow", "policy", "executor", "generation", "fence"} {
			t.Run(name, func(t *testing.T) {
				r, pr, w, p, x, g, fc := run, f.pre.PreregistrationID, policy.ID.String(), policy.ID.String(), executor, int64(8), int64(20)
				switch name {
				case "run":
					r = uuid.NewString()
				case "pre":
					pr = uuid.NewString()
				case "workflow":
					w = uuid.NewString()
				case "policy":
					p = uuid.NewString()
				case "executor":
					x = uuid.NewString()
				case "generation":
					g++
				case "fence":
					fc++
				}
				if count(r, pr, w, p, x, g, fc) != 0 {
					t.Fatal("foreign original scope selected")
				}
			})
		}
		var noStored model.CapacityGuestOriginalProvisioningReceipt
		if _, e = failedInstalledOriginalCanaryIssuerTx(ctx, tx, model.CapacityPolicySpec{}, guestOriginalStored{pre: f.pre, binding: f.binding}, noStored, run); e == nil {
			t.Fatal("query fixture conferred signed profile authority")
		}
	})
}
