package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These are actual PG79 storage/authentication/transaction tests, not a
// production Guest signature or quiescence fixture. No provider, transport,
// business creation, original runtime or cleanup is run or qualified here.
func TestD14PresendRetirementRecoveryPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	t.Run("linear_typed_successor_context_and_originals", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		f, parent, old, disposal, recovery := recoveryStorageFixture(t, tx, ctx, policy)
		if err := retirementNeverSentTx(ctx, tx, parent.RequestID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if id, err := singleFailedCreateRetirementTx(ctx, tx, f.pre.OriginalCreateGrantID); err != nil || id != parent.RequestID {
			t.Fatal("single original ambiguous", err)
		}
		before := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID)
		admissionSHA, err := insertRetirementRecoveryTx(ctx, tx, recovery)
		if err != nil {
			t.Fatal(err)
		}
		requested, sha, err := loadRetirementRecoveryTx(ctx, tx, recovery.ID, "requested")
		if err != nil || sha != admissionSHA || !bytes.Equal(mustRecoveryJSON(t, requested), mustRecoveryJSON(t, recovery)) {
			t.Fatal("requested raw identity", err)
		}
		next := recoveryClaimStorage(t, tx, ctx, old, recovery, admissionSHA)
		// A scheduler/issue rollback must not leave a new current epoch or ledger.
		if _, err = tx.ExecContext(ctx, `SAVEPOINT before_successor_issue`); err != nil {
			t.Fatal(err)
		}
		request, contextDeadline := recoveryFreshSignedDTO(t, parent, next)
		if err = issueNeverSentSuccessorTx(ctx, tx, next, request.Intent, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		recoveryInsertIntent(t, tx, ctx, f.pre.PreregistrationID, request)
		recoveryInsertContextAndIssuer(t, tx, ctx, policy, next, request.Intent, contextDeadline)
		var durable []byte
		if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_retirement_intents WHERE id=$1`, request.Intent.RequestID).Scan(&durable); err != nil {
			t.Fatal(err)
		}
		var stored model.CapacityGuestRetirementRequest
		if err = capacity.DecodeGuestLifecycle(durable, &stored); err != nil || stored.Intent != request.Intent || stored.Signature != request.Signature || stored.Nonce != "" {
			t.Fatal("unchanged strict Reserve intent/signature equality", err)
		}
		var contextMatches, issuerMatches bool
		if err = tx.QueryRowContext(ctx, `SELECT original_context_deadline=$2 AND executor_id::text=$3 FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, request.Intent.RequestID, contextDeadline, next.LeaseExecutorID).Scan(&contextMatches); err != nil {
			t.Fatal(err)
		}
		if err = tx.QueryRowContext(ctx, `SELECT issued_wire_sha256=$2 AND executor_id::text=$3 FROM public.capacity_guest_authority_issues WHERE issue_kind='retirement_intent' AND issue_id=$1`, request.Intent.RequestID, capacity.GuestRetirementSHA(request.Intent), next.LeaseExecutorID).Scan(&issuerMatches); err != nil || !contextMatches || !issuerMatches {
			t.Fatal("actual SQL context64/atomic77 join", err)
		}
		if _, err = singleFailedCreateRetirementTx(ctx, tx, f.pre.OriginalCreateGrantID); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("compensation chose an arbitrary original", err)
		}
		derived, err := effectiveFailedInstalledClaimTx(ctx, tx, disposal, next)
		if err != nil || derived.ClaimedIntent.FencingToken != 16 || disposal.ClaimedIntent.FencingToken != 15 {
			t.Fatal("continuation confused original and successor", err)
		}
		q := derived
		q.Stage = "quiescent"
		q.RetirementRequestID = request.Intent.RequestID
		q.NativePoweroffSHA256 = strings.Repeat("f", 64)
		if _, err = insertFailedInstalledDisposalTx(ctx, tx, q); err != nil {
			t.Fatal("new79 claim does not join immutable78 continuation", err)
		}
		// SQL shape storage does not establish original runtime/off authority.
		if _, _, _, err = loadFailedInstalledQuiescentTx(ctx, tx, q.PreregistrationID, q.ID, ""); err == nil {
			t.Fatal("unsigned storage seam qualified native cleanup")
		}
		if got := recoveryOriginals(t, tx, ctx, parent.RequestID, disposal.ID); !bytes.Equal(before, got) {
			t.Fatal("old intent/context/issuer/claimed rows changed")
		}
		third, _ := recoveryFreshSignedDTO(t, parent, next)
		recoveryRefusal(t, tx, ctx, func() error { return recoveryInsertIntentError(tx, ctx, f.pre.PreregistrationID, third) })
		recoveryRefusal(t, tx, ctx, func() error { _, e := insertRetirementRecoveryTx(ctx, tx, recovery); return e })
		for _, table := range []string{"capacity_guest_presend_retirement_recoveries", "capacity_vm_retirement_intents", "capacity_guest_failed_installed_disposals"} {
			key := recovery.ID
			if table == "capacity_vm_retirement_intents" {
				key = parent.RequestID
			}
			if table == "capacity_guest_failed_installed_disposals" {
				key = disposal.ID
			}
			guestOriginalExpectedSQLRefusal(t, tx, ctx, `DELETE FROM public.`+table+` WHERE id=$1`, key)
		}
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT before_successor_issue`); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1)+(SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries WHERE id=$2 AND stage='issued')`, f.pre.PreregistrationID, recovery.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("rolled-back issue left new authority", count, err)
		}
	})
	for _, kind := range []string{"possible_caller", "caller_return", "snapshot_read", "authority_read", "Guest_observation", "delete_binding", "native_poweroff"} {
		t.Run("old_"+kind+"_forbids_admission_and_issue", func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f, parent, old, _, r := recoveryStorageFixture(t, tx, ctx, policy)
			sha, err := insertRetirementRecoveryTx(ctx, tx, r)
			if err != nil {
				t.Fatal(err)
			}
			next := recoveryClaimStorage(t, tx, ctx, old, r, sha)
			recoveryOldEvidence(t, tx, ctx, kind, f, parent)
			if retirementNeverSentTx(ctx, tx, parent.RequestID, time.Now().UTC()) == nil {
				t.Fatal("old possible-send/read/result ignored")
			}
			fresh, _ := recoveryFreshSignedDTO(t, parent, next)
			if issueNeverSentSuccessorTx(ctx, tx, next, fresh.Intent, time.Now().UTC()) == nil {
				t.Fatal("issue ignored newly observed old evidence")
			}
			// Direct SQL cannot bypass the same zero-send check either.
			recoveryRefusal(t, tx, ctx, func() error {
				r.Stage = "issued"
				r.AdmissionSHA256 = sha
				r.ClaimedIntent = &next
				r.SuccessorIntent = &fresh.Intent
				_, e := insertRetirementRecoveryTx(ctx, tx, r)
				return e
			})
		})
	}
	t.Run("stale_fence_lease_run_and_parent_refused", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		_, parent, old, disposal, r := recoveryStorageFixture(t, tx, ctx, policy)
		sha, err := insertRetirementRecoveryTx(ctx, tx, r)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"same_fence", "same_lease", "same_run", "different_parent_hash", "different_old_claim", "wrong_admission"} {
			t.Run(kind, func(t *testing.T) {
				bad := r
				bad.Stage = "claimed"
				bad.AdmissionSHA256 = sha
				next := recoveryNextStorage(old, r, sha)
				bad.ClaimedIntent = &next
				switch kind {
				case "same_fence":
					next.FencingToken = old.FencingToken
				case "same_lease":
					next.LeaseOwner = old.LeaseOwner
				case "same_run":
					next.FailedInstalledDisposal.RunID = old.FailedInstalledDisposal.RunID
				case "different_parent_hash":
					bad.ParentIntentSHA256 = strings.Repeat("e", 64)
				case "different_old_claim":
					bad.OriginalClaimedIntent.FencingToken++
				case "wrong_admission":
					bad.AdmissionSHA256 = strings.Repeat("f", 64)
				}
				recoveryRefusal(t, tx, ctx, func() error { _, e := insertRetirementRecoveryTx(ctx, tx, bad); return e })
			})
		}
		next := recoveryClaimStorage(t, tx, ctx, old, r, sha)
		stale := next
		stale.FencingToken++
		if _, err = effectiveFailedInstalledClaimTx(ctx, tx, disposal, stale); err == nil {
			t.Fatal("stale current fence adopted")
		}
		fresh, _ := recoveryFreshSignedDTO(t, parent, next)
		fresh.Intent.LeaseOwner = uuid.NewString()
		if issueNeverSentSuccessorTx(ctx, tx, next, fresh.Intent, time.Now().UTC()) == nil {
			t.Fatal("foreign issue lease accepted")
		}
		if persistFailedInstalledDisposalIntentTx(ctx, tx, old, next) == nil {
			t.Fatal("same old current intent claimed twice")
		}
	})
	t.Run("expired_original_not_renewed_by_clock_precision", func(t *testing.T) {
		tx, ctx := guestOriginalStorageTx(t, db)
		_, parent, _, _, _ := recoveryStorageFixture(t, tx, ctx, policy)
		if retirementNeverSentTx(ctx, tx, parent.RequestID, parent.OriginalDeadline.Add(-time.Nanosecond)) == nil {
			t.Fatal("native microseconds adopted before original nanos expired")
		}
		if err := retirementNeverSentTx(ctx, tx, parent.RequestID, parent.OriginalDeadline.Add(time.Microsecond)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("prior_actual_D13_b5_and_unknown_map", func(t *testing.T) { testGuestAuthorityHistoricalMapPostgres(t, db, policy) })
}

func mustRecoveryJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func recoveryStorageFixture(t *testing.T, tx *sql.Tx, ctx context.Context, policy model.Manifest) (guestOriginalStorageFixture, model.CapacityGuestRetirementIntent, model.CapacityIntent, FailedInstalledGuestDisposal, FailedInstalledRetirementRecovery) {
	t.Helper()
	f := guestOriginalStorageRecords(t)
	guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, f.pre.PreregistrationID, capacity.BusinessCreationSHA256([]byte(uuid.NewString())), capacity.BusinessCreationSHA256([]byte(uuid.NewString())), strings.Repeat("e", 64), f.pre.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	oldExpiry := time.Now().Add(-time.Minute).UTC()
	old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, Environment: "production", Domain: "notify", Dimension: "recovery-storage-" + uuid.NewString(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: 15, Phase: "draining", LeaseOwner: uuid.NewString(), LeaseExecutorID: uuid.NewString(), LeaseExpiresAt: &oldExpiry, UpdatedAt: oldExpiry}
	d := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: old.Namespace, Environment: old.Environment, Domain: old.Domain, Dimension: old.Dimension, PreregistrationID: f.pre.PreregistrationID, Issuer: "declared-local-storage-only", ActualCoreSource: strings.Repeat("a", 40), OriginalRun: `{"status":"failed","ACK":true}`, LastFailedRun: `{"status":"failed","ACK":true}`, InstallationSHA256: strings.Repeat("b", 64), EnrollmentSHA256: strings.Repeat("c", 64), BlockedGuestSource: failedInstalledLegacyGuestSource, BlockedProfileSHA256: strings.Repeat("e", 64), BusinessEffectsPreserved: true, RetirementMode: failedInstalledLegacyV1Mode}
	admission, e := insertFailedInstalledDisposalTx(ctx, tx, d)
	if e != nil {
		t.Fatal(e)
	}
	old.FailedInstalledDisposal = &model.CapacityFailedInstalledDisposal{ID: d.ID, Stage: "claimed", PreregistrationID: f.pre.PreregistrationID, RunID: uuid.NewString(), Fence: 15, AdmissionSHA256: admission}
	d.Stage = "claimed"
	d.AdmissionSHA256 = admission
	d.ClaimedIntent = &old
	claimSHA, e := insertFailedInstalledDisposalTx(ctx, tx, d)
	if e != nil {
		t.Fatal(e)
	}
	parent := model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, RequestID: f.intentID, AttemptID: uuid.NewString(), NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: policy.ID.String(), WorkflowChecksum: policy.Checksum, Generation: 6, Fence: 15, LeaseOwner: old.LeaseOwner, OriginalDeadline: f.pre.OriginalDeadline, IssuedAt: f.pre.ReservedAt}
	request := model.CapacityGuestRetirementRequest{Intent: parent, Signature: "declared-unqualified-storage-signature"}
	recoveryInsertIntent(t, tx, ctx, f.pre.PreregistrationID, request)
	recoveryInsertContextAndIssuer(t, tx, ctx, policy, old, parent, parent.OriginalDeadline)
	_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent)VALUES($1,$2,$3,$4,$5::jsonb)`, old.Namespace, old.Environment, old.Domain, old.Dimension, string(mustRecoveryJSON(t, old)))
	if e != nil {
		t.Fatal(e)
	}
	r := FailedInstalledRetirementRecovery{Schema: "failed_installed_never_sent_retirement_recovery_v1", ID: uuid.NewString(), Stage: "requested", DisposalID: d.ID, PreregistrationID: f.pre.PreregistrationID, ParentIntentID: parent.RequestID, ParentIntentSHA256: capacity.GuestRetirementSHA(parent), OriginalClaimSHA256: claimSHA, Issuer: "declared-local-storage-only", ActualCoreSource: strings.Repeat("b", 40), FailedRun: `{"status":"failed","ACK":true,"retire-original-guest":"failed"}`, OriginalClaimedIntent: old}
	return f, parent, old, d, r
}
func recoveryNextStorage(old model.CapacityIntent, r FailedInstalledRetirementRecovery, sha string) model.CapacityIntent {
	next := old
	next.FencingToken++
	next.LeaseOwner = uuid.NewString()
	next.LeaseExecutorID = uuid.NewString()
	expiry := time.Now().Add(time.Minute).UTC()
	next.LeaseExpiresAt = &expiry
	next.UpdatedAt = time.Now().UTC()
	m := *old.FailedInstalledDisposal
	m.RunID = uuid.NewString()
	m.Fence = next.FencingToken
	m.RetirementRecoveryID = r.ID
	m.RetirementRecoveryAdmissionSHA256 = sha
	next.FailedInstalledDisposal = &m
	return next
}
func recoveryClaimStorage(t *testing.T, tx *sql.Tx, ctx context.Context, old model.CapacityIntent, r FailedInstalledRetirementRecovery, sha string) model.CapacityIntent {
	t.Helper()
	next := recoveryNextStorage(old, r, sha)
	r.Stage = "claimed"
	r.AdmissionSHA256 = sha
	r.ClaimedIntent = &next
	if _, e := insertRetirementRecoveryTx(ctx, tx, r); e != nil {
		t.Fatal(e)
	}
	if e := persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); e != nil {
		t.Fatal(e)
	}
	return next
}
func recoveryFreshSignedDTO(t *testing.T, parent model.CapacityGuestRetirementIntent, next model.CapacityIntent) (model.CapacityGuestRetirementRequest, time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	deadline, e := capacity.GuestOriginalRetirementDeadline(ctx, now, *next.LeaseExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	contextDeadline, _ := ctx.Deadline()
	intent := parent
	intent.RequestID = uuid.NewString()
	intent.AttemptID = uuid.NewString()
	intent.NonceSHA256 = capacity.BusinessCreationSHA256([]byte(uuid.NewString()))
	intent.Generation = uint64(next.Generation)
	intent.Fence = uint64(next.FencingToken)
	intent.LeaseOwner = next.LeaseOwner
	intent.IssuedAt = now
	intent.OriginalDeadline = deadline
	intent.WithdrawOperationID = uuid.NewString()
	intent.DrainOperationID = uuid.NewString()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signature, e := capacity.GuestLifecycleSignature(key, intent)
	if e != nil {
		t.Fatal(e)
	}
	return model.CapacityGuestRetirementRequest{Intent: intent, Signature: signature, Nonce: "declared-local-no-transport"}, contextDeadline
}
func recoveryInsertIntentError(tx *sql.Tx, ctx context.Context, pre string, r model.CapacityGuestRetirementRequest) error {
	durable := r
	durable.Nonce = ""
	wire, e := json.Marshal(durable)
	if e != nil {
		return e
	}
	intent, e := json.Marshal(r.Intent)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at,original_wire)VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, r.Intent.RequestID, pre, r.Intent.AttemptID, r.Intent.NonceSHA256, capacity.GuestRetirementSHA(r.Intent), string(intent), r.Intent.OriginalDeadline, r.Intent.IssuedAt, wire)
	return e
}
func recoveryInsertIntent(t *testing.T, tx *sql.Tx, ctx context.Context, pre string, r model.CapacityGuestRetirementRequest) {
	t.Helper()
	if e := recoveryInsertIntentError(tx, ctx, pre, r); e != nil {
		t.Fatal(e)
	}
}
func recoveryInsertContextAndIssuer(t *testing.T, tx *sql.Tx, ctx context.Context, policy model.Manifest, current model.CapacityIntent, i model.CapacityGuestRetirementIntent, deadline time.Time) {
	t.Helper()
	actual := "3d570162ba51967ee791316c23c5b45419993f1b"
	_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_retirement_contexts(intent_id,executor_id,original_step_id,original_step_timeout_seconds,original_context_deadline,core_actual_source_commit,recorded_at)VALUES($1,$2,'declared-local-retire-step',30,$3,$4,$5)`, i.RequestID, current.LeaseExecutorID, deadline, actual, i.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	record := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "retirement_intent", "issue_id": i.RequestID, "issuer_actual_source_commit": actual, "protocol_authority_source_commit": capacity.GuestD11ProtocolAuthority, "compatibility_map_sha256": capacity.GuestProtocolCompatibilityMapSHA256(), "profile": "notify-aws-elastic", "policy_id": policy.ID.String(), "workflow_id": policy.ID.String(), "executor_id": current.LeaseExecutorID, "issued_wire_sha256": capacity.GuestRetirementSHA(i)}
	wire := mustRecoveryJSON(t, record)
	_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES('retirement_intent',$1,$2,$3,$4,'notify-aws-elastic',$5,$5,$6,$7,$8,$9::jsonb)`, i.RequestID, actual, capacity.GuestD11ProtocolAuthority, capacity.GuestProtocolCompatibilityMapSHA256(), policy.ID, current.LeaseExecutorID, capacity.GuestRetirementSHA(i), wire, string(wire))
	if e != nil {
		t.Fatal(e)
	}
}
func recoveryOriginals(t *testing.T, tx *sql.Tx, ctx context.Context, parent, disposal string) []byte {
	t.Helper()
	var raw string
	e := tx.QueryRowContext(ctx, `SELECT jsonb_build_array((SELECT row_to_json(r) FROM public.capacity_vm_retirement_intents r WHERE id=$1),(SELECT row_to_json(c) FROM public.capacity_guest_original_retirement_contexts c WHERE intent_id=$1),(SELECT row_to_json(i) FROM public.capacity_guest_authority_issues i WHERE issue_kind='retirement_intent' AND issue_id=$1),(SELECT row_to_json(d) FROM public.capacity_guest_failed_installed_disposals d WHERE id=$2 AND stage='claimed'))::text`, parent, disposal).Scan(&raw)
	if e != nil {
		t.Fatal(e)
	}
	return []byte(raw)
}
func recoveryRefusal(t *testing.T, tx *sql.Tx, ctx context.Context, f func() error) {
	t.Helper()
	if _, e := tx.ExecContext(ctx, `SAVEPOINT recovery_refusal`); e != nil {
		t.Fatal(e)
	}
	if e := f(); e == nil {
		t.Fatal("invalid recovery accepted")
	}
	if _, e := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT recovery_refusal`); e != nil {
		t.Fatal(e)
	}
}
func recoveryOldEvidence(t *testing.T, tx *sql.Tx, ctx context.Context, kind string, f guestOriginalStorageFixture, i model.CapacityGuestRetirementIntent) {
	t.Helper()
	var e error
	switch kind {
	case "possible_caller", "caller_return":
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline)VALUES($1,$2,$3,'declared-storage', $4,$5)`, i.RequestID, i.AttemptID, strings.Repeat("a", 64), i.IssuedAt, i.OriginalDeadline)
		if e == nil && kind == "caller_return" {
			_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,'{}'::jsonb,$4)`, i.RequestID, strings.Repeat("b", 64), []byte(`{}`), i.IssuedAt)
		}
	case "snapshot_read":
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_challenges(id,intent_id,phase,ordinal,challenge_sha256,original_wire,original_record,original_deadline,recorded_at)VALUES($1,$2,'before_start',1,$3,$4,jsonb_build_object('original_deadline',$5::timestamptz,'issued_at',$6::timestamptz),$5,$6)`, uuid.NewString(), i.RequestID, strings.Repeat("a", 64), []byte(`{}`), i.OriginalDeadline, i.OriginalDeadline.Add(-time.Second))
	case "authority_read":
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at)VALUES($1,$2,'before_start',1,$3,$4)`, uuid.NewString(), i.RequestID, i.OriginalDeadline, i.IssuedAt)
	case "Guest_observation":
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at)VALUES($1,1,'declared-storage','',$2,'{}'::jsonb,$3)`, i.RequestID, strings.Repeat("a", 64), i.IssuedAt)
	case "delete_binding":
		guestOriginalStorageGrant(t, tx, ctx, f.destroyGrantID)
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_delete_bindings(destroy_grant_id,intent_id,eligibility_sha256,original_eligibility_record,recorded_at)VALUES($1,$2,$3,'{}'::jsonb,$4)`, f.destroyGrantID, i.RequestID, strings.Repeat("a", 64), i.IssuedAt)
	case "native_poweroff":
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at)VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, uuid.NewString(), i.RequestID, strings.Repeat("a", 64), []byte(`{}`), i.IssuedAt)
	}
	if e != nil {
		t.Fatal(e)
	}
}
