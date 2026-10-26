package repository

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Build a new declared signed history before its first persistence. Retained
// transport/challenge bytes are never normalized to their SQL projections.
func partialPrecisionDeadlines(t *testing.T, f partialFixture, fractionalNanoseconds int64) partialFixture {
	t.Helper()
	for n := range f.reads {
		rd := &f.reads[n]
		rd.deadline = rd.deadline.Truncate(time.Second).Add(time.Second + time.Duration(fractionalNanoseconds))
		if !rd.deadline.Before(f.stored.Request.Intent.OriginalDeadline) {
			t.Fatal("fixture read exceeded its unchanged original four-second lease")
		}
		for k := range rd.stages {
			v := &rd.stages[k]
			v.t.OriginalDeadline = rd.deadline
			if v.challenge != nil {
				v.challenge.OriginalDeadline = rd.deadline
				v.challenge.Signature = ""
				var err error
				v.challenge.Signature, err = capacity.GuestLifecycleSignature(f.core, *v.challenge)
				if err != nil {
					t.Fatal(err)
				}
				var snapshot model.CapacityGuestRuntimeSnapshot
				if err = json.Unmarshal(v.snapshot, &snapshot); err != nil {
					t.Fatal(err)
				}
				snapshot.ChallengeSHA256 = capacity.GuestRetirementSHA(*v.challenge)
				snapshot.Signature = ""
				snapshot.Signature, err = capacity.GuestLifecycleSignature(f.observer, snapshot)
				if err != nil {
					t.Fatal(err)
				}
				v.reply = mustRecoveryJSON(t, snapshot)
				v.snapshot = v.reply
				v.t.ResponseSHA256 = capacity.BusinessCreationSHA256(v.reply)
				v.t.RetainedPrefixSHA256 = v.t.ResponseSHA256
				v.t.ReceivedBodyBytes = len(v.reply)
				v.t.RetainedPrefixBytes = len(v.reply)
			}
		}
	}
	return f
}

func TestPartialNativeOffHistoricalReadDeadlinePrecisionPostgres(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	for _, tc := range []struct {
		name     string
		nanos    int64
		roundsUp bool
	}{
		{"below_half_microsecond", 123456499, false},
		{"above_half_microsecond", 123456501, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f, parent, old, _, recovery := recoveryStorageFixture(t, tx, ctx, policy)
			admission, err := insertRetirementRecoveryTx(ctx, tx, recovery)
			if err != nil {
				t.Fatal(err)
			}
			next := recoveryNextStorage(old, recovery, admission)
			// Preserve the same real four-second expiry used by the full81 test.
			expiry := time.Now().Add(4 * time.Second).UTC().Truncate(time.Microsecond)
			next.LeaseExpiresAt = &expiry
			recovery.Stage, recovery.AdmissionSHA256, recovery.ClaimedIntent = "claimed", admission, &next
			if _, err = insertRetirementRecoveryTx(ctx, tx, recovery); err != nil {
				t.Fatal(err)
			}
			if err = persistFailedInstalledDisposalIntentTx(ctx, tx, old, next); err != nil {
				t.Fatal(err)
			}
			request, _ := recoveryFreshSignedDTO(t, parent, next)
			request.Intent.IssuedAt = request.Intent.IssuedAt.Truncate(time.Microsecond)
			signed := partialSignedFixtureWith(t, &request.Intent, f.pre.PreregistrationID, 10)
			signed = partialPrecisionDeadlines(t, signed, tc.nanos)
			request.Intent = signed.stored.Request.Intent
			if err = issueNeverSentSuccessorTx(ctx, tx, next, request.Intent, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			recoveryInsertIntent(t, tx, ctx, f.pre.PreregistrationID, request)
			recoveryInsertContextAndIssuer(t, tx, ctx, policy, next, request.Intent, request.Intent.OriginalDeadline)
			partialStoreHistory(t, tx, ctx, signed)
			for _, rd := range signed.reads {
				projected := rd.deadline.Truncate(time.Microsecond)
				if tc.roundsUp {
					projected = projected.Add(time.Microsecond)
				}
				for _, v := range rd.stages {
					var got time.Time
					var canonical bool
					var original []byte
					err = tx.QueryRowContext(ctx, `SELECT r.original_deadline,r.original_deadline=(v.original_record->>'original_deadline')::timestamptz,v.original_wire FROM capacity_guest_original_authority_reads r JOIN capacity_guest_original_authority_transport_returns v ON v.read_id=r.id WHERE r.id=$1 AND v.native_stage=$2`, rd.id, v.stage).Scan(&got, &canonical, &original)
					if err != nil || !canonical || !got.Equal(projected) || got.Equal(rd.deadline) || !bytes.Equal(original, mustRecoveryJSON(t, v.t)) {
						t.Fatal("native SQL projection or original transport bytes", err)
					}
					if v.challenge != nil {
						if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM capacity_guest_runtime_snapshot_challenges WHERE id=$1`, v.challenge.ChallengeID).Scan(&original); err != nil || !bytes.Equal(original, mustRecoveryJSON(t, *v.challenge)) {
							t.Fatal("signed challenge bytes were rewritten", err)
						}
					}
				}
			}
			// Expire once without any retained-record UPDATE or deadline renewal.
			timer := time.NewTimer(time.Until(expiry) + 20*time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
			if _, err = partialNativeOffEvidenceTx(ctx, tx, signed.stored, time.Now().UTC()); err != nil {
				t.Fatal("exact signed history must survive SQL microsecond projection", err)
			}
		})
	}
}

func TestPartialNativeOffTransportKeepsExactOriginalNanosecondDeadline(t *testing.T) {
	f := partialSignedFixture(t)
	rd := f.reads[0]
	v := rd.stages[0]
	deadline := v.t.OriginalDeadline
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		transport := v.t
		transport.DriverReturnedAt = deadline.Add(delta)
		if partialNativeTransportClosed(transport, v.stage, v.reply, f.caller, rd.id, rd.possible, deadline) != (delta < 0) {
			t.Fatal("original nanosecond boundary changed", delta)
		}
	}
	transport := v.t
	transport.OriginalDeadline = deadline.Add(time.Nanosecond)
	if partialNativeTransportClosed(transport, v.stage, v.reply, f.caller, rd.id, rd.possible, deadline) {
		t.Fatal("distinct original deadlines in one SQL bucket were equated")
	}
}
