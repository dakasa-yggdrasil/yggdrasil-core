package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Actual PostgreSQL constraints/transactions and actual signed DTO validators.
// The declared enrollment/storage fixture is not a production native supplier.
// No provider or Guest command is run and every row is rolled back.
func TestPartialNativeOffReconciliationPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	tx, ctx := guestOriginalStorageTx(t, db)
	var schema int
	if e := tx.QueryRowContext(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&schema); e != nil || schema != 81 {
		t.Fatal("owning schema81 required", schema, e)
	}
	f, parent, old, disposal, recovery := recoveryStorageFixture(t, tx, ctx, policy)
	before := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)
	admission, e := insertRetirementRecoveryTx(ctx, tx, recovery)
	if e != nil {
		t.Fatal(e)
	}
	next := recoveryNextStorage(old, recovery, admission)
	expiry := time.Now().Add(4 * time.Second).UTC()
	next.LeaseExpiresAt = &expiry
	recovery.Stage = "claimed"
	recovery.AdmissionSHA256 = admission
	recovery.ClaimedIntent = &next
	if _, e = insertRetirementRecoveryTx(ctx, tx, recovery); e != nil {
		t.Fatal(e)
	}
	if e = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); e != nil {
		t.Fatal(e)
	}
	request, _ := recoveryFreshSignedDTO(t, parent, next)
	signed := partialSignedFixtureWith(t, &request.Intent, f.pre.PreregistrationID, 10)
	request.Intent = signed.stored.Request.Intent
	if e = issueNeverSentSuccessorTx(ctx, tx, next, request.Intent, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	recoveryInsertIntent(t, tx, ctx, f.pre.PreregistrationID, request)
	recoveryInsertContextAndIssuer(t, tx, ctx, policy, next, request.Intent, request.Intent.OriginalDeadline)
	partialStoreHistory(t, tx, ctx, signed)
	// The original real deadline expires once. No fixture UPDATE or renewal.
	timer := time.NewTimer(time.Until(expiry) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	evidence, e := partialNativeOffEvidenceTx(ctx, tx, signed.stored, time.Now().UTC())
	if e != nil {
		t.Fatal("actual signed retained history", e)
	}
	_, claimSHA, e := loadFailedInstalledDisposalTx(ctx, tx, disposal.ID, "claimed")
	if e != nil {
		t.Fatal(e)
	}
	r := FailedInstalledPartialNativeOff{Schema: partialNativeOffSchema, ID: uuid.NewString(), Stage: "admitted", DisposalID: disposal.ID, PreregistrationID: f.pre.PreregistrationID, RetirementRequestID: request.Intent.RequestID, Issuer: "declared-storage-admin-no-native-authority", ActualCoreSource: strings.Repeat("d", 40), OriginalClaimSHA256: claimSHA, OriginalClaimedIntent: next, FailedRun: `{"failed":true,"ACK":true}`, Evidence: evidence}
	t.Run("closed_admission_lineage_and_null_refusals", func(t *testing.T) {
		for _, kind := range []string{"caller200", "wrong_history", "foreign_claim", "changed_epoch", "unknown_key", "null_evidence", "missing_evidence", "missing_nested_hash"} {
			t.Run(kind, func(t *testing.T) {
				v := r
				var m map[string]any
				_ = json.Unmarshal(mustRecoveryJSON(t, v), &m)
				switch kind {
				case "caller200":
					v.Evidence.CallerSHA256 = strings.Repeat("f", 64)
				case "wrong_history":
					v.Evidence.ObservationSHA256[2] = strings.Repeat("f", 64)
				case "foreign_claim":
					v.OriginalClaimSHA256 = strings.Repeat("f", 64)
				case "changed_epoch":
					v.OriginalClaimedIntent.FencingToken++
				case "unknown_key":
					m["force"] = true
				case "null_evidence":
					m["evidence"] = nil
				case "missing_evidence":
					delete(m, "evidence")
				case "missing_nested_hash":
					delete(m["evidence"].(map[string]any), "caller_sha256")
				}
				recoveryRefusal(t, tx, ctx, func() error {
					if kind == "unknown_key" || strings.Contains(kind, "evidence") || kind == "missing_nested_hash" {
						return partialInsertRaw(t, tx, ctx, v, m)
					}
					_, e := insertPartialNativeOffTx(ctx, tx, v)
					return e
				})
			})
		}
	})
	sha, e := insertPartialNativeOffTx(ctx, tx, r)
	if e != nil {
		t.Fatal("unique81 admission", e)
	}
	got, hash, e := loadPartialNativeOffTx(ctx, tx, r.ID, "admitted")
	if e != nil || hash != sha || !bytes.Equal(mustRecoveryJSON(t, r), mustRecoveryJSON(t, got)) {
		t.Fatal("original81 bytes", e)
	}
	t.Run("unique_admission_no_original_success_alias", func(t *testing.T) {
		recoveryRefusal(t, tx, ctx, func() error { v := r; v.ID = uuid.NewString(); _, e := insertPartialNativeOffTx(ctx, tx, v); return e })
		recoveryRefusal(t, tx, ctx, func() error {
			v := r
			v.Stage = "qualified"
			v.AdmissionSHA256 = sha
			v.NativeReadID = uuid.NewString()
			v.NativeOffSHA256 = strings.Repeat("f", 64)
			_, e := insertPartialNativeOffTx(ctx, tx, v)
			return e
		})
		q := disposal
		q.Stage = "quiescent"
		q.ClaimedIntent = &next
		q.RetirementRequestID = request.Intent.RequestID
		q.NativePoweroffSHA256 = strings.Repeat("f", 64)
		recoveryRefusal(t, tx, ctx, func() error { _, e := insertFailedInstalledDisposalTx(ctx, tx, q); return e })
	})
	t.Run("atomic_distinct_qualification_storage_and_rollback", func(t *testing.T) {
		if _, e := tx.ExecContext(ctx, `SAVEPOINT partial_qualified_storage`); e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		read := PartialNativeOffRead{Schema: "partial_guest548_native_off_read_v1", ReadID: uuid.NewString(), ReconciliationID: r.ID, PreregistrationID: r.PreregistrationID, RetirementRequestID: r.RetirementRequestID, Ordinal: 1, AdmissionSHA256: sha, EvidenceSHA256: partialEvidenceSHA(evidence), IssuedAt: now, OriginalDeadline: now.Add(5 * time.Second)}
		if e := insertPartialNativeReadTx(ctx, tx, read, "started", read); e != nil {
			t.Fatal(e)
		}
		// This deliberately incomplete plan tests SQL storage, never the owning
		// provider/full-plan authentication exercised by production qualification.
		result := PartialNativeOffReturn{Schema: "partial_guest548_native_off_return_v1", Read: read, Status: "observed", Plan: &model.CapacityVMFleetPlan{Server: &model.CapacityVMServerObservation{Status: "off"}}, StartedAt: now, ReturnedAt: time.Now().UTC()}
		if e := insertPartialNativeReadTx(ctx, tx, read, "returned", result); e != nil {
			t.Fatal(e)
		}
		qualified := r
		qualified.Stage, qualified.AdmissionSHA256, qualified.NativeReadID, qualified.NativeOffSHA256 = "qualified", sha, read.ReadID, capacity.GuestRetirementSHA(result)
		if _, e := insertPartialNativeOffTx(ctx, tx, qualified); e != nil {
			t.Fatal("distinct81 qualification storage", e)
		}
		q, e := effectiveFailedInstalledClaimTx(ctx, tx, disposal, next)
		if e != nil {
			t.Fatal(e)
		}
		q.Stage, q.RetirementRequestID, q.NativePoweroffSHA256 = "quiescent", request.Intent.RequestID, qualified.NativeOffSHA256
		if _, e := insertFailedInstalledDisposalTx(ctx, tx, q); e != nil {
			t.Fatal("81 joins existing78 without adding normal4/200", e)
		}
		if _, _, _, e := loadFailedInstalledQuiescentTx(ctx, tx, q.PreregistrationID, q.ID, ""); e == nil {
			t.Fatal("declared incomplete storage plan authorized native cleanup")
		}
		if _, e := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT partial_qualified_storage`); e != nil {
			t.Fatal(e)
		}
		var count int
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM capacity_guest_partial_nativeoff_reconciliations WHERE id=$1 AND stage='qualified'`, r.ID).Scan(&count); e != nil || count != 0 {
			t.Fatal("qualification survived atomic rollback", e)
		}
	})
	t.Run("readonly_attempts_pending_failure_and_three_bound", func(t *testing.T) {
		var previous PartialNativeOffRead
		for ordinal := 1; ordinal <= 3; ordinal++ {
			now := time.Now().UTC()
			read := PartialNativeOffRead{Schema: "partial_guest548_native_off_read_v1", ReadID: uuid.NewString(), ReconciliationID: r.ID, PreregistrationID: r.PreregistrationID, RetirementRequestID: r.RetirementRequestID, Ordinal: ordinal, AdmissionSHA256: sha, EvidenceSHA256: partialEvidenceSHA(evidence), IssuedAt: now, OriginalDeadline: now.Add(5 * time.Second)}
			if e := insertPartialNativeReadTx(ctx, tx, read, "started", read); e != nil {
				t.Fatal("linear original readonly attempt", e)
			}
			recoveryRefusal(t, tx, ctx, func() error {
				v := read
				v.ReadID = uuid.NewString()
				v.Ordinal++
				return insertPartialNativeReadTx(ctx, tx, v, "started", v)
			})
			recoveryRefusal(t, tx, ctx, func() error {
				v := read
				v.ReadID = uuid.NewString()
				v.PreregistrationID = uuid.NewString()
				return insertPartialNativeReadTx(ctx, tx, v, "started", v)
			})
			result := PartialNativeOffReturn{Schema: "partial_guest548_native_off_return_v1", Read: read, Status: "unavailable", StartedAt: now, ReturnedAt: time.Now().UTC(), CallFailed: true}
			recoveryRefusal(t, tx, ctx, func() error {
				v := result
				v.Read.OriginalDeadline = v.Read.OriginalDeadline.Add(time.Second)
				return insertPartialNativeReadTx(ctx, tx, read, "returned", v)
			})
			if e := insertPartialNativeReadTx(ctx, tx, read, "returned", result); e != nil {
				t.Fatal("retain failed GET without qualifying", e)
			}
			q := r
			q.Stage = "qualified"
			q.AdmissionSHA256 = sha
			q.NativeReadID = read.ReadID
			q.NativeOffSHA256 = capacity.GuestRetirementSHA(result)
			recoveryRefusal(t, tx, ctx, func() error { _, e := insertPartialNativeOffTx(ctx, tx, q); return e })
			previous = read
		}
		previous.ReadID = uuid.NewString()
		previous.Ordinal = 4
		recoveryRefusal(t, tx, ctx, func() error { return insertPartialNativeReadTx(ctx, tx, previous, "started", previous) })
		var rows int
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=$1`, r.ID).Scan(&rows); e != nil || rows != 6 {
			t.Fatal("three original failure pairs retained", rows, e)
		}
	})
	t.Run("immutable_and_original63_78_79_preserved", func(t *testing.T) {
		for _, table := range []string{"capacity_guest_partial_nativeoff_reconciliations", "capacity_guest_partial_nativeoff_reads"} {
			for _, verb := range []string{"UPDATE " + table + " SET recorded_at=clock_timestamp()", "DELETE FROM " + table} {
				recoveryRefusal(t, tx, ctx, func() error { _, e := tx.ExecContext(ctx, verb); return e })
			}
		}
		if after := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID); !bytes.Equal(before, after) {
			t.Fatal("old original changed")
		}
		var intents, obs, callers, normalOff int
		if e := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM capacity_vm_retirement_intents WHERE preregistration_id=$1),(SELECT count(*) FROM capacity_vm_retirement_original_returns WHERE intent_id=$2),(SELECT count(*) FROM capacity_guest_original_caller_returns WHERE intent_id=$2),(SELECT count(*) FROM capacity_guest_original_native_poweroff_reads WHERE intent_id=$2)`, r.PreregistrationID, r.RetirementRequestID).Scan(&intents, &obs, &callers, &normalOff); e != nil || intents != 2 || obs != 3 || callers != 1 || normalOff != 0 {
			t.Fatal("81 created a Guest request or forged normal proof", e)
		}
	})
}
func partialInsertRaw(t *testing.T, tx *sql.Tx, ctx context.Context, r FailedInstalledPartialNativeOff, value any) error {
	t.Helper()
	wire := mustRecoveryJSON(t, value)
	_, e := tx.ExecContext(ctx, `INSERT INTO capacity_guest_partial_nativeoff_reconciliations(id,stage,disposal_id,preregistration_id,retirement_request_id,original_wire,original_record,record_sha256)VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, r.ID, r.Stage, r.DisposalID, r.PreregistrationID, r.RetirementRequestID, wire, string(wire), capacity.BusinessCreationSHA256(wire))
	return e
}
func partialStoreHistory(t *testing.T, tx *sql.Tx, ctx context.Context, f partialFixture) {
	t.Helper()
	i := f.stored.Request.Intent
	caller := mustRecoveryJSON(t, f.caller)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline)VALUES($1,$2,$3,'declared-no-transport',$4,$5)`, i.RequestID, i.AttemptID, strings.Repeat("a", 64), f.caller.DoStartedAt, i.OriginalDeadline)
	exec(`INSERT INTO capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4::jsonb,$5)`, i.RequestID, capacity.BusinessCreationSHA256(caller), caller, string(caller), f.caller.DriverReturnedAt)
	for _, o := range f.observations {
		wire := mustRecoveryJSON(t, o)
		exec(`INSERT INTO capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire)VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, i.RequestID, o.Record.Sequence, o.Record.State, o.Record.PreviousSHA256, o.RecordSHA256, string(wire), o.ObservedAt, wire)
	}
	for _, r := range f.reads {
		authority := mustRecoveryJSON(t, r.authority)
		exec(`INSERT INTO capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at)VALUES($1,$2,$3,$4,$5,$6)`, r.id, i.RequestID, r.phase, r.ordinal, r.deadline, r.possible)
		for _, v := range r.stages {
			wire := mustRecoveryJSON(t, v.t)
			if v.challenge != nil {
				ch := mustRecoveryJSON(t, *v.challenge)
				exec(`INSERT INTO capacity_guest_runtime_snapshot_challenges(id,intent_id,phase,ordinal,challenge_sha256,original_wire,original_record,original_deadline,recorded_at)VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, v.challenge.ChallengeID, i.RequestID, r.phase, r.ordinal, capacity.BusinessCreationSHA256(ch), ch, string(ch), v.challenge.OriginalDeadline, v.challenge.IssuedAt)
				exec(`INSERT INTO capacity_guest_runtime_snapshot_returns(challenge_id,return_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4::jsonb,$5)`, v.challenge.ChallengeID, capacity.BusinessCreationSHA256(v.snapshot), v.snapshot, string(v.snapshot), v.t.DriverReturnedAt)
			}
			exec(`INSERT INTO capacity_guest_original_authority_transport_returns(read_id,native_stage,return_sha256,original_wire,original_record,original_reply_wire,recorded_at)VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, r.id, v.stage, capacity.BusinessCreationSHA256(wire), wire, string(wire), v.reply, v.t.DriverReturnedAt)
		}
		exec(`INSERT INTO capacity_guest_original_authority_returns(read_id,authority_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4::jsonb,$5)`, r.id, capacity.BusinessCreationSHA256(authority), authority, string(authority), r.recorded)
	}
}
