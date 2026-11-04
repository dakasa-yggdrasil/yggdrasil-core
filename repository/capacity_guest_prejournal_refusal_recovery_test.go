package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Signed declared DTOs exercise the actual verifier. They do not claim an
// observed VM, native journal, real enrollment or production retirement.
func prejournalSignedFixture(t *testing.T) (GuestRetirementOriginal, GuestOriginalCallerReturn, model.CapacityGuestRuntimeSnapshotChallenge, prejournalSnapshotTransport, []byte, time.Time) {
	t.Helper()
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	sha := strings.Repeat("a", 64)
	_, core, _ := ed25519.GenerateKey(rand.Reader)
	_, observer, _ := ed25519.GenerateKey(rand.Reader)
	life := model.CapacityGuestRetirementLifetime{BootID: uuid.NewString(), ProcessNonceSHA256: sha, PID: 100, StartTicks: 101, SourceCommit: failedInstalledLegacyGuestSource, BinarySHA256: sha, ServiceInvocationID: strings.Repeat("b", 32)}
	writer := life
	writer.PID = 102
	writer.StartTicks = 103
	e := model.CapacityGuestRetirementEnrollment{}
	e.Statement.BindingName = "declared"
	e.Statement.Tuple = model.CapacityGuestNativeTuple{Slot: 1, Provider: "hetzner", ResourceID: "declared-not-native", CreatedAt: "2026-10-25T00:00:00Z"}
	e.Statement.Actor = life
	e.Statement.Runtime = life
	e.Statement.Writers = []model.CapacityGuestRetirementWriter{{ID: "declared", Lifetime: writer}}
	e.Statement.WriterRosterSHA256 = capacity.GuestRetirementSHA(e.Statement.Writers)
	e.Statement.CoreAuthoritySourceCommit = strings.Repeat("c", 40)
	e.Statement.CoreIntentPublicKey = base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey))
	e.Statement.ObservationPublicKey = base64.StdEncoding.EncodeToString(observer.Public().(ed25519.PublicKey))
	i := model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, BindingName: e.Statement.BindingName, Slot: 1, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), NonceSHA256: sha, EnrollmentSHA256: capacity.GuestRetirementSHA(e), Tuple: e.Statement.Tuple, Actor: life, PolicyID: uuid.NewString(), PolicyChecksum: sha, WorkflowID: uuid.NewString(), WorkflowChecksum: sha, Generation: 6, Fence: 16, LeaseOwner: uuid.NewString(), IssuedAt: at, OriginalDeadline: at.Add(30 * time.Second)}
	stored := GuestRetirementOriginal{Request: model.CapacityGuestRetirementRequest{Intent: i}, Binding: model.CapacityGuestRetirementBinding{GuestSourceCommit: failedInstalledLegacyGuestSource}, Receipt: model.CapacityGuestOriginalProvisioningReceipt{Enrollment: e}}
	stored.Preregistration.PreregistrationID = uuid.NewString()
	c := GuestOriginalCallerReturn{RequestID: i.RequestID, AttemptID: i.AttemptID, OriginalDeadline: i.OriginalDeadline, StartedAt: at.Add(time.Second), DoStartedAt: at.Add(1100 * time.Millisecond), DoReturnedAt: at.Add(4 * time.Second), ReadReturnedAt: at.Add(4100 * time.Millisecond), CloseReturnedAt: at.Add(4200 * time.Millisecond), DriverReturnedAt: at.Add(4300 * time.Millisecond), Status: 409, Body: []byte{}, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead}
	problem := []byte("{\"code\":\"guest_retirement.original_attempt_held\",\"status\":409,\"title\":\"Guest retirement held\",\"detail\":\"The original Guest retirement requires its enrolled authority and complete original results.\"}\n")
	c.ReceivedBodyBytes = len(problem)
	c.RetainedPrefixBytes = len(problem)
	c.ResponseSHA256 = capacity.BusinessCreationSHA256(problem)
	c.RetainedPrefixSHA256 = c.ResponseSHA256
	ch := model.CapacityGuestRuntimeSnapshotChallenge{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: uuid.NewString(), BindingName: i.BindingName, Slot: 1, PreregistrationID: stored.Preregistration.PreregistrationID, PreregistrationNonceSHA256: sha, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, EnrollmentSHA256: i.EnrollmentSHA256, ProfileManifestSHA256: sha, Tuple: i.Tuple, RequestID: i.RequestID, AttemptID: i.AttemptID, IntentSHA256: capacity.GuestRetirementSHA(i), Phase: "before_start", PolicyID: i.PolicyID, PolicyChecksum: i.PolicyChecksum, WorkflowID: i.WorkflowID, WorkflowChecksum: i.WorkflowChecksum, Generation: i.Generation, Fence: i.Fence, LeaseOwner: i.LeaseOwner, CoreSourceCommit: e.Statement.CoreAuthoritySourceCommit, IssuedAt: at.Add(1500 * time.Millisecond), OriginalDeadline: at.Add(6500 * time.Millisecond)}
	ch.Signature, _ = capacity.GuestLifecycleSignature(core, ch)
	snap := model.CapacityGuestRuntimeSnapshot{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: ch.ChallengeID, ChallengeSHA256: capacity.GuestRetirementSHA(ch), PreregistrationID: ch.PreregistrationID, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, ProfileManifestSHA256: sha, EnrollmentSHA256: ch.EnrollmentSHA256, Tuple: i.Tuple, Actor: life, Runtime: life, Writers: e.Statement.Writers, WriterRosterSHA256: e.Statement.WriterRosterSHA256, OriginalReadStartedAt: at.Add(2 * time.Second), OriginalReadReturnedAt: at.Add(2500 * time.Millisecond), OriginalReadsReturned: true, OriginalClosesReturned: true, HoldReasons: []string{}, Reader: life, ObservedAt: at.Add(2600 * time.Millisecond), ProtectedCensus: model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: failedInstalledLegacyGuestSource, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: writer.PID, StartTicks: writer.StartTicks}}, RawCensusSHA256: sha, ObservedAt: at.Add(2400 * time.Millisecond)}}
	snap.Signature, _ = capacity.GuestLifecycleSignature(observer, snap)
	reply := mustRecoveryJSON(t, snap)
	tr := prejournalSnapshotTransport{ReadID: uuid.NewString(), Stage: "snapshot", OriginalDeadline: ch.OriginalDeadline, StartedAt: at.Add(1600 * time.Millisecond), DoStartedAt: at.Add(1700 * time.Millisecond), DoReturnedAt: at.Add(2700 * time.Millisecond), ReadReturnedAt: at.Add(2800 * time.Millisecond), CloseReturnedAt: at.Add(2900 * time.Millisecond), DriverReturnedAt: at.Add(3 * time.Second), Status: 200, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, ResponseSHA256: capacity.BusinessCreationSHA256(reply), ReceivedBodyBytes: len(reply), RetainedPrefixBytes: len(reply), RetainedPrefixSHA256: capacity.BusinessCreationSHA256(reply)}
	if capacity.GuestRuntimeSnapshot(ch, e, i, snap, tr.DriverReturnedAt) != nil {
		t.Fatal("signed declared fixture refused")
	}
	return stored, c, ch, tr, reply, ch.IssuedAt
}

func TestD15PrejournalRefusalEvidenceBoundaries(t *testing.T) {
	stored, c, ch, tr, reply, possible := prejournalSignedFixture(t)
	for _, kind := range []string{"exact", "generic409", "unknown_body", "body_not_closed", "read_failed", "status200", "late", "wrong_attempt", "persisted_body", "context_failed"} {
		t.Run("caller/"+kind, func(t *testing.T) {
			v := c
			switch kind {
			case "generic409":
				v.ResponseSHA256 = strings.Repeat("f", 64)
			case "unknown_body":
				v.ResponseBodyScope = capacity.GuestOriginalBodyIncompleteRead
			case "body_not_closed":
				v.CloseReturnedAt = time.Time{}
			case "read_failed":
				v.ReadFailed = true
			case "status200":
				v.Status = 200
			case "late":
				v.DriverReturnedAt = v.OriginalDeadline
			case "wrong_attempt":
				v.AttemptID = uuid.NewString()
			case "persisted_body":
				v.BodyPersisted = true
			case "context_failed":
				v.OriginalContextFailed = true
			}
			if prejournalCallerClosedRefusal(v, stored.Request.Intent) != (kind == "exact") {
				t.Fatal("generic/unknown refusal admitted")
			}
		})
	}
	for _, kind := range []string{"exact", "foreign_read", "wrong_stage", "HTTP409", "prefix_only", "bad_hash", "changed_deadline", "late", "context_failed", "missing_body"} {
		t.Run("nested/"+kind, func(t *testing.T) {
			v := tr
			b := reply
			switch kind {
			case "foreign_read":
				v.ReadID = uuid.NewString()
			case "wrong_stage":
				v.Stage = "journal"
			case "HTTP409":
				v.Status = 409
			case "prefix_only":
				v.RetainedPrefixBytes--
			case "bad_hash":
				v.ResponseSHA256 = strings.Repeat("f", 64)
			case "changed_deadline":
				v.OriginalDeadline = v.OriginalDeadline.Add(time.Nanosecond)
			case "late":
				v.DriverReturnedAt = ch.OriginalDeadline
			case "context_failed":
				v.OriginalContextFailed = true
			case "missing_body":
				b = nil
			}
			if prejournalSnapshotClosed(v, b, c, tr.ReadID, possible, ch.OriginalDeadline) != (kind == "exact") {
				t.Fatal("incomplete/foreign nested read admitted")
			}
		})
	}
	for _, kind := range []string{"exact", "second_read", "extra_observation", "another_recovery", "not_expired", "bad_signature", "wrong_Guest", "wire_mismatch"} {
		t.Run("actual_helper/"+kind, func(t *testing.T) {
			s := stored
			ch1 := ch
			tr1 := tr
			reply1 := append([]byte(nil), reply...)
			now := time.Now().UTC()
			counts := []int{1, 1, 1, 1, 1, 0, 0}
			ordinal := 1
			consistent := true
			switch kind {
			case "second_read":
				counts[2] = 2
			case "extra_observation":
				counts[5] = 1
			case "another_recovery":
				counts[6] = 1
			case "not_expired":
				now = stored.Request.Intent.OriginalDeadline.Add(-time.Nanosecond)
			case "bad_signature":
				reply1 = bytes.Replace(reply1, []byte(`"signature":"`), []byte(`"signature":"AAAA`), 1)
				tr1.ResponseSHA256 = capacity.BusinessCreationSHA256(reply1)
				tr1.RetainedPrefixSHA256 = tr1.ResponseSHA256
				tr1.ReceivedBodyBytes = len(reply1)
				tr1.RetainedPrefixBytes = len(reply1)
			case "wrong_Guest":
				s.Binding.GuestSourceCommit = strings.Repeat("a", 40)
			case "wire_mismatch":
				consistent = false
			}
			db, m, _ := sqlmock.New()
			defer db.Close()
			m.ExpectBegin()
			tx, _ := db.Begin()
			defer tx.Rollback()
			if kind != "wrong_Guest" {
				m.ExpectQuery("SELECT original_deadline").WillReturnRows(sqlmock.NewRows([]string{"deadline", "canonical"}).AddRow(stored.Request.Intent.OriginalDeadline.Truncate(time.Microsecond), stored.Request.Intent.OriginalDeadline.Format(time.RFC3339Nano)))
				if kind != "not_expired" {
					m.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"a", "b", "c", "d", "e", "f", "g"}).AddRow(counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6]))
					if counts[2] == 1 && counts[5] == 0 && counts[6] == 0 {
						cw := mustRecoveryJSON(t, c)
						chw := mustRecoveryJSON(t, ch1)
						tw := mustRecoveryJSON(t, tr1)
						m.ExpectQuery("SELECT c.original_wire").WillReturnRows(sqlmock.NewRows([]string{"cw", "cs", "a", "r", "p", "o", "at", "d", "ch", "chs", "t", "ts", "reply", "ok"}).AddRow(cw, capacity.BusinessCreationSHA256(cw), c.AttemptID, tr.ReadID, "before_start", ordinal, possible.Truncate(time.Microsecond), ch.OriginalDeadline.Truncate(time.Microsecond), chw, capacity.BusinessCreationSHA256(chw), tw, capacity.BusinessCreationSHA256(tw), reply1, consistent))
					}
				}
			}
			_, err := retirementPrejournalRefusedTx(context.Background(), tx, s, now)
			if (err == nil) != (kind == "exact") {
				t.Fatal("causal helper guard", kind, err)
			}
			if err = m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// PG tests prove append-only80, linear63, cross79 and immutable78 continuation.
// Their storage fixture is deliberately NOT an authenticated production Guest.
func TestD15PrejournalRefusalRecoveryPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	var exists bool
	if err := db.QueryRow(`SELECT to_regclass('public.capacity_guest_prejournal_refusal_recoveries') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		b, e := os.ReadFile(filepath.Join("..", "db", "migrations", "00080_failed_installed_prejournal_refusal_recovery.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(strings.Split(string(b), "-- +goose Down")[0]); e != nil {
			t.Fatal(e)
		}
	}
	t.Run("stage_chain_and_CAS", func(t *testing.T) { testPrejournalRefusalStageCAS(t, db, policy) })
	t.Run("scheduled_reachability", func(t *testing.T) { testPrejournalRefusalSchedulerReachability(t, db, policy) })
	t.Run("storage_linear_new_operation_preserves_old_possible_send", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f, parent, old, disposal, base := recoveryStorageFixture(t, tx, ctx, policy)
		r := prejournalStorageEvidence(t, tx, ctx, f, parent, base)
		before := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)
		admission, err := insertPrejournalRefusalRecoveryTx(ctx, tx, r)
		if err != nil {
			t.Fatal(err)
		}
		next := recoveryNextStorage(old, base, admission)
		next.FailedInstalledDisposal.RetirementRecoveryID = ""
		next.FailedInstalledDisposal.RetirementRecoveryAdmissionSHA256 = ""
		next.FailedInstalledDisposal.RetirementRefusalRecoveryID = r.ID
		next.FailedInstalledDisposal.RetirementRefusalRecoveryAdmissionSHA256 = admission
		r.Stage = "claimed"
		r.AdmissionSHA256 = admission
		r.ClaimedIntent = &next
		if _, err = insertPrejournalRefusalRecoveryTx(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
			t.Fatal(err)
		}
		fresh, _ := recoveryFreshSignedDTO(t, parent, next)
		r.Stage = "issued"
		r.SuccessorIntent = &fresh.Intent
		if _, err = insertPrejournalRefusalRecoveryTx(ctx, tx, r); err != nil {
			t.Fatal(err)
		}
		recoveryInsertIntent(t, tx, ctx, f.pre.PreregistrationID, fresh)
		effective, err := effectiveFailedInstalledClaimTx(ctx, tx, disposal, next)
		if err != nil {
			t.Fatal(err)
		}
		q := effective
		q.Stage = "quiescent"
		q.RetirementRequestID = fresh.Intent.RequestID
		q.NativePoweroffSHA256 = strings.Repeat("f", 64)
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, q); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)) {
			t.Fatal("historical originals changed")
		}
		third, _ := recoveryFreshSignedDTO(t, parent, next)
		recoveryRefusal(t, tx, ctx, func() error { return recoveryInsertIntentError(tx, ctx, f.pre.PreregistrationID, third) })
		recoveryRefusal(t, tx, ctx, func() error { _, e := insertRetirementRecoveryTx(ctx, tx, base); return e })
		for _, table := range []string{"capacity_guest_prejournal_refusal_recoveries", "capacity_vm_retirement_intents", "capacity_guest_failed_installed_disposals"} {
			id := r.ID
			if table == "capacity_vm_retirement_intents" {
				id = parent.RequestID
			}
			if table == "capacity_guest_failed_installed_disposals" {
				id = disposal.ID
			}
			guestOriginalExpectedSQLRefusal(t, tx, ctx, `DELETE FROM public.`+table+` WHERE id=$1`, id)
		}
	})
	for _, kind := range []string{"missing_evidence", "wrong_first_read", "HTTP200caller", "unknownHTTPbody", "nestedHTTP409", "missing_reply", "authority_return", "snapshot_return", "extra_read", "native_off", "wrong_original_hash", "wrong_source", "second_admission"} {
		t.Run("SQL_refuses/"+kind, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f, parent, _, _, base := recoveryStorageFixture(t, tx, ctx, policy)
			r := prejournalStorageEvidence(t, tx, ctx, f, parent, base, kind)
			switch kind {
			case "missing_evidence":
				r.RefusalEvidence = RetirementPrejournalRefusalEvidence{}
			case "wrong_first_read":
				r.RefusalEvidence.AuthorityReadID = uuid.NewString()
			case "wrong_original_hash":
				r.ParentIntentSHA256 = strings.Repeat("f", 64)
			case "wrong_source":
				r.RefusalEvidence.CausalGuestSource = strings.Repeat("a", 40)
			case "second_admission":
				if _, e := insertPrejournalRefusalRecoveryTx(ctx, tx, r); e != nil {
					t.Fatal(e)
				}
			case "authority_return":
				_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_returns(read_id,authority_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,'{}','{}',clock_timestamp())`, r.RefusalEvidence.AuthorityReadID, strings.Repeat("d", 64))
				if e != nil {
					t.Fatal(e)
				}
			case "snapshot_return":
				_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_returns(challenge_id,return_sha256,original_wire,original_record,recorded_at) SELECT id,$2,'{}','{}',clock_timestamp() FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1`, parent.RequestID, strings.Repeat("d", 64))
				if e != nil {
					t.Fatal(e)
				}
			case "extra_read":
				_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at)VALUES($1,$2,'before_start',2,$3,$4)`, uuid.NewString(), parent.RequestID, parent.OriginalDeadline, parent.IssuedAt)
				if e != nil {
					t.Fatal(e)
				}
			case "native_off":
				recoveryOldEvidence(t, tx, ctx, "native_poweroff", f, parent)

			}
			recoveryRefusal(t, tx, ctx, func() error { _, e := insertPrejournalRefusalRecoveryTx(ctx, tx, r); return e })
		})
	}
	t.Run("never_sent79_cannot_be_relabelled80", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f, parent, _, _, base := recoveryStorageFixture(t, tx, ctx, policy)
		if _, e := insertRetirementRecoveryTx(ctx, tx, base); e != nil {
			t.Fatal(e)
		}
		r := prejournalStorageEvidence(t, tx, ctx, f, parent, base)
		recoveryRefusal(t, tx, ctx, func() error { _, e := insertPrejournalRefusalRecoveryTx(ctx, tx, r); return e })
	})
}

func prejournalStorageEvidence(t *testing.T, tx *sql.Tx, ctx context.Context, f guestOriginalStorageFixture, parent model.CapacityGuestRetirementIntent, base FailedInstalledRetirementRecovery, kinds ...string) FailedInstalledPrejournalRefusalRecovery {
	t.Helper()
	kind := ""
	if len(kinds) > 0 {
		kind = kinds[0]
	}
	_, c, _, tr, reply, _ := prejournalSignedFixture(t)
	at := parent.IssuedAt
	c.RequestID = parent.RequestID
	c.AttemptID = parent.AttemptID
	c.OriginalDeadline = parent.OriginalDeadline
	c.StartedAt = at.Add(100 * time.Millisecond)
	c.DoStartedAt = at.Add(200 * time.Millisecond)
	c.DoReturnedAt = at.Add(4 * time.Second)
	c.ReadReturnedAt = at.Add(4100 * time.Millisecond)
	c.CloseReturnedAt = at.Add(4200 * time.Millisecond)
	c.DriverReturnedAt = at.Add(4300 * time.Millisecond)
	if kind == "HTTP200caller" {
		c.Status = 200
	}
	if kind == "unknownHTTPbody" {
		c.ResponseBodyScope = capacity.GuestOriginalBodyIncompleteRead
	}
	cw := mustRecoveryJSON(t, c)
	readID := uuid.NewString()
	possible := at.Add(300 * time.Millisecond)
	deadline := at.Add(5 * time.Second)
	ch := model.CapacityGuestRuntimeSnapshotChallenge{ChallengeID: uuid.NewString(), IssuedAt: possible, OriginalDeadline: deadline}
	chw := mustRecoveryJSON(t, ch)
	tr.ReadID = readID
	tr.OriginalDeadline = deadline
	tr.StartedAt = at.Add(400 * time.Millisecond)
	tr.DoStartedAt = at.Add(500 * time.Millisecond)
	tr.DoReturnedAt = at.Add(2 * time.Second)
	tr.ReadReturnedAt = at.Add(2100 * time.Millisecond)
	tr.CloseReturnedAt = at.Add(2200 * time.Millisecond)
	tr.DriverReturnedAt = at.Add(2300 * time.Millisecond)
	if kind == "nestedHTTP409" {
		tr.Status = 409
	}
	var replyArg any = reply
	if kind == "missing_reply" {
		replyArg = nil
	}
	tw := mustRecoveryJSON(t, tr)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline)VALUES($1,$2,$3,'declared-storage-no-native',$4,$5)`, []any{parent.RequestID, parent.AttemptID, strings.Repeat("a", 64), c.DoStartedAt, parent.OriginalDeadline}},
		{`INSERT INTO public.capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4::jsonb,$5)`, []any{parent.RequestID, capacity.BusinessCreationSHA256(cw), cw, string(cw), c.DriverReturnedAt}},
		{`INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at)VALUES($1,$2,'before_start',1,$3,$4)`, []any{readID, parent.RequestID, deadline, possible}},
		{`INSERT INTO public.capacity_guest_runtime_snapshot_challenges(id,intent_id,phase,ordinal,challenge_sha256,original_wire,original_record,original_deadline,recorded_at)VALUES($1,$2,'before_start',1,$3,$4,$5::jsonb,$6,$7)`, []any{ch.ChallengeID, parent.RequestID, capacity.BusinessCreationSHA256(chw), chw, string(chw), deadline, possible}},
		{`INSERT INTO public.capacity_guest_original_authority_transport_returns(read_id,native_stage,return_sha256,original_wire,original_record,original_reply_wire,recorded_at)VALUES($1,'snapshot',$2,$3,$4::jsonb,$5,$6)`, []any{readID, capacity.BusinessCreationSHA256(tw), tw, string(tw), replyArg, tr.DriverReturnedAt}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	return FailedInstalledPrejournalRefusalRecovery{Schema: "failed_installed_prejournal_refusal_recovery_v1", ID: uuid.NewString(), Stage: "requested", DisposalID: base.DisposalID, PreregistrationID: base.PreregistrationID, ParentIntentID: base.ParentIntentID, ParentIntentSHA256: base.ParentIntentSHA256, OriginalClaimSHA256: base.OriginalClaimSHA256, Issuer: base.Issuer, ActualCoreSource: base.ActualCoreSource, FailedRun: base.FailedRun, OriginalClaimedIntent: base.OriginalClaimedIntent, PossibleBusinessEffectsPreserved: true, RefusalEvidence: RetirementPrejournalRefusalEvidence{CausalGuestSource: failedInstalledLegacyGuestSource, SourceOrder: "guest548_first_authority_before_journal_v1", OriginalCallerSHA256: capacity.BusinessCreationSHA256(cw), AuthorityReadID: readID, SnapshotChallengeSHA256: capacity.BusinessCreationSHA256(chw), SnapshotTransportSHA256: capacity.BusinessCreationSHA256(tw), AuthenticatedSnapshotSHA256: capacity.BusinessCreationSHA256(reply)}}
}

func testPrejournalRefusalSchedulerReachability(t *testing.T, db *sql.DB, policy model.Manifest) {
	for _, kind := range []string{"no_admission_waits", "requested_reaches_claim", "foreign_fence_refused", "claimed_still_waits"} {
		t.Run(kind, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f, parent, old, disposal, base := recoveryStorageFixture(t, tx, ctx, policy)
			r := prejournalStorageEvidence(t, tx, ctx, f, parent, base)
			current := old
			if kind != "no_admission_waits" {
				sha, e := insertPrejournalRefusalRecoveryTx(ctx, tx, r)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "claimed_still_waits" {
					next := recoveryNextStorage(old, base, sha)
					next.FailedInstalledDisposal.RetirementRecoveryID = ""
					next.FailedInstalledDisposal.RetirementRecoveryAdmissionSHA256 = ""
					next.FailedInstalledDisposal.RetirementRefusalRecoveryID = r.ID
					next.FailedInstalledDisposal.RetirementRefusalRecoveryAdmissionSHA256 = sha
					r.Stage = "claimed"
					r.AdmissionSHA256 = sha
					r.ClaimedIntent = &next
					if _, e = insertPrejournalRefusalRecoveryTx(ctx, tx, r); e != nil {
						t.Fatal(e)
					}
					current = next
				}
			}
			if kind == "foreign_fence_refused" {
				current.FencingToken++
			}
			store := CapacityStore{guestReconcile: &guestReconcileSource{step: model.WorkflowStepSpec{Use: model.WorkflowStepUseSpec{Operation: capacity.PlanOriginalGuestOperation}}}}
			got, waiting, err := store.failedInstalledGuestDisposalWaitingTx(ctx, tx, current, "")
			switch kind {
			case "requested_reaches_claim":
				if err != nil || waiting || got.ID != disposal.ID {
					t.Fatal("requested80 unreachable", waiting, err)
				}
				if _, _, eligible, e := store.claimPrejournalRefusalRecoveryTx(ctx, tx, policy, model.CapacityPolicySpec{}, old, model.CapacityAssessment{}, time.Now().UTC()); e == nil || eligible {
					t.Fatal("collection bypassed full claim")
				}
			case "foreign_fence_refused":
				if err == nil {
					t.Fatal("foreign fence adopted")
				}
			default:
				if err != nil || !waiting {
					t.Fatal("claimed original released", err)
				}
			}
			var issued int
			if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_prejournal_refusal_recoveries WHERE id=$1 AND stage='issued'`, r.ID).Scan(&issued); e != nil || issued != 0 {
				t.Fatal("waiting created Guest authority", e)
			}
		})
	}
}

func testPrejournalRefusalStageCAS(t *testing.T, db *sql.DB, policy model.Manifest) {
	tx, ctx := guestOriginalStorageTx(t, db)
	f, parent, old, _, base := recoveryStorageFixture(t, tx, ctx, policy)
	r := prejournalStorageEvidence(t, tx, ctx, f, parent, base)
	sha, e := insertPrejournalRefusalRecoveryTx(ctx, tx, r)
	if e != nil {
		t.Fatal(e)
	}
	next := recoveryNextStorage(old, base, sha)
	next.FailedInstalledDisposal.RetirementRecoveryID = ""
	next.FailedInstalledDisposal.RetirementRecoveryAdmissionSHA256 = ""
	next.FailedInstalledDisposal.RetirementRefusalRecoveryID = r.ID
	next.FailedInstalledDisposal.RetirementRefusalRecoveryAdmissionSHA256 = sha
	for _, kind := range []string{"same_fence", "same_lease", "same_run", "wrong_admission", "changed_evidence", "changed_parent", "new_effects_flag"} {
		t.Run(kind, func(t *testing.T) {
			bad := r
			bad.Stage = "claimed"
			bad.AdmissionSHA256 = sha
			clone := next
			marker := *next.FailedInstalledDisposal
			clone.FailedInstalledDisposal = &marker
			bad.ClaimedIntent = &clone
			switch kind {
			case "same_fence":
				clone.FencingToken = old.FencingToken
			case "same_lease":
				clone.LeaseOwner = old.LeaseOwner
			case "same_run":
				marker.RunID = old.FailedInstalledDisposal.RunID
			case "wrong_admission":
				bad.AdmissionSHA256 = strings.Repeat("f", 64)
			case "changed_evidence":
				bad.RefusalEvidence.AuthenticatedSnapshotSHA256 = strings.Repeat("f", 64)
			case "changed_parent":
				bad.ParentIntentID = uuid.NewString()
			case "new_effects_flag":
				bad.PossibleBusinessEffectsPreserved = false
			}
			recoveryRefusal(t, tx, ctx, func() error { _, e := insertPrejournalRefusalRecoveryTx(ctx, tx, bad); return e })
		})
	}
	r.Stage = "claimed"
	r.AdmissionSHA256 = sha
	r.ClaimedIntent = &next
	if _, e = insertPrejournalRefusalRecoveryTx(ctx, tx, r); e != nil {
		t.Fatal(e)
	}
	if e = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); e != nil {
		t.Fatal(e)
	}
	if persistFailedInstalledDisposalIntentTx(ctx, tx, old, next) == nil {
		t.Fatal("same old CAS reused")
	}
}
