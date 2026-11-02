package repository

import (
	"context"
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

// ADR-0092 storage histories shaped like production disposal 8ef5f76c
// (Hetzner gen8, fence 21, retirement intent fc853776: nonce + possible_start,
// one closed caller 409 without a retained body, no native poweroff read).
// Explicitly isolated Unix-socket database (schema86). The rows are synthetic
// SQL operands, never a signed Guest record, a real caller, a provider read or
// a compiled production approval; no provider or Guest call is exercised.
// The positive acceptance is proven at the migration86 guards; the Go path is
// exercised up to its refusals (a storage-only policy is never a valid Guest
// policy) and through the terminal lineage selector.

type v2RefusedOptions struct {
	caller200         bool
	persistedBody     bool
	callerTransport   bool
	thirdJournalRow   bool
	writerQuiescent   bool
	activeLease       bool
	legacyMode        bool
	priorNativeRead   bool
	poweroffAuthority bool
	deadlineOpen      bool
	recoveryOwned     bool
}

type v2RefusedFixture struct {
	db          *sql.DB
	ns          string
	scope       model.CapacityPolicySpec
	pre         string
	retirement  string
	attempt     string
	intentSHA   string
	callerSHA   string
	returns     [2]string
	source      string
	claimed     FailedInstalledGuestDisposal
	claimSHA    string
	current     model.CapacityIntent
	runWire     string
	tuple       model.CapacityGuestNativeTuple
	deadline    time.Time
	nativeReads int
}

func v2RefusedPGFixture(t *testing.T, db *sql.DB, o v2RefusedOptions) v2RefusedFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	must := func(q string, a ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := v2RefusedFixture{db: db, ns: "v2-refused-" + uuid.NewString(), source: externalCauseHex(40)}
	if o.legacyMode {
		f.source = failedInstalledLegacyGuestSource
	}
	f.scope = model.CapacityPolicySpec{Environment: "production", Domain: "notify", Dimension: "hetzner-vm-members-" + externalCauseHex(8)}
	disposed := externalCausePre(t, tx, ctx, f.ns, f.scope, f.source)
	f.pre = disposed.pre.PreregistrationID
	must(`INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at) VALUES($1,$2,$3,$4,'{}'::jsonb,$5)`, f.pre, externalCauseHex(64), externalCauseHex(64), externalCauseHex(64), disposed.pre.ReservedAt)

	f.runWire = `{"id":"` + uuid.NewString() + `","status":"failed"}`
	mode := failedInstalledV2Mode
	if o.legacyMode {
		mode = failedInstalledLegacyV1Mode
	}
	r := FailedInstalledGuestDisposal{Schema: "failed_installed_guest_disposal_v1", ID: uuid.NewString(), Stage: "requested", Namespace: f.ns, Environment: f.scope.Environment, Domain: f.scope.Domain, Dimension: f.scope.Dimension, PreregistrationID: f.pre, Issuer: "v2-refused-storage-test", ActualCoreSource: externalCauseHex(40), OriginalRun: f.runWire, LastFailedRun: f.runWire, InstallationSHA256: externalCauseHex(64), EnrollmentSHA256: externalCauseHex(64), BlockedGuestSource: f.source, BlockedProfileSHA256: disposed.binding.ProfileManifestSHA256, BusinessEffectsPreserved: true, RetirementMode: mode}
	requestedSHA, err := insertFailedInstalledDisposalTx(ctx, tx, r)
	if err != nil {
		t.Fatal("requested", err)
	}
	lease := now.Add(-5 * time.Minute)
	if o.activeLease {
		lease = now.Add(10 * time.Minute)
	}
	owner := uuid.NewString()
	f.current = model.CapacityIntent{Namespace: f.ns, Environment: f.scope.Environment, Domain: f.scope.Domain, Dimension: f.scope.Dimension, PolicyID: uuid.New(), PolicyChecksum: externalCauseHex(64), Generation: 8, FencingToken: 21, Phase: "draining", LeaseOwner: owner, LeaseExecutorID: uuid.NewString(), LeaseExpiresAt: &lease,
		FailedInstalledDisposal: &model.CapacityFailedInstalledDisposal{ID: r.ID, AdmissionSHA256: requestedSHA, PreregistrationID: f.pre, Stage: "claimed", RunID: uuid.NewString(), Fence: 21},
		Decision:                model.CapacityDecision{Action: "drain", Units: 1, Reason: "failed_installed_disposal"}}
	r.Stage = "claimed"
	r.AdmissionSHA256 = requestedSHA
	claimed := f.current
	r.ClaimedIntent = &claimed
	if f.claimSHA, err = insertFailedInstalledDisposalTx(ctx, tx, r); err != nil {
		t.Fatal("claimed", err)
	}
	f.claimed = r
	intentRaw, _ := json.Marshal(f.current)
	must(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent) VALUES($1,$2,$3,$4,$5::jsonb)`, f.ns, f.scope.Environment, f.scope.Domain, f.scope.Dimension, string(intentRaw))

	// The expired V2 retirement intent of the claimed epoch.
	f.retirement, f.attempt = uuid.NewString(), uuid.NewString()
	issued := now.Add(-11 * time.Minute)
	f.deadline = now.Add(-10 * time.Minute)
	if o.deadlineOpen {
		f.deadline = now.Add(10 * time.Minute)
	}
	f.tuple = model.CapacityGuestNativeTuple{Provider: "hetzner", Profile: "notify-hetzner", Slot: 1, ResourceID: "172592998", CreatedAt: issued.Add(-24 * time.Hour).Format(time.RFC3339)}
	intentRecord, _ := json.Marshal(map[string]any{"schema": capacity.GuestRetirementV2IntentSchema, "request_id": f.retirement, "attempt_id": f.attempt, "preregistration_id": f.pre, "generation": 8, "fence": 21, "lease_owner": owner, "slot": 1, "tuple": f.tuple, "issued_at": issued, "original_deadline": f.deadline})
	f.intentSHA = capacity.BusinessCreationSHA256(intentRecord)
	must(`INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id,attempt_id,nonce_sha256,intent_sha256,intent_record,original_deadline,created_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, f.retirement, f.pre, f.attempt, externalCauseHex(64), f.intentSHA, string(intentRecord), f.deadline, issued)

	// Journal: production_clock_nonce_v2 then an unquiesced possible_start.
	nonce := []byte(`{"schema":"original_core_guest_retirement_nonce_return_v2","storage_only":true}`)
	f.returns[0] = capacity.BusinessCreationSHA256(nonce)
	must(`INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,1,'production_clock_nonce_v2','',$2,$3::jsonb,$4,$5)`, f.retirement, f.returns[0], string(nonce), issued.Add(time.Second), nonce)
	observed := model.CapacityGuestRetirementObservationV2{Schema: capacity.GuestRetirementV2ObservationSchema, JournalComplete: true, HoldReasons: []string{}, ObservedAt: issued.Add(3 * time.Second), Record: model.CapacityGuestRetirementRecordV2{Schema: capacity.GuestRetirementV2RecordSchema, Sequence: 1, State: "possible_start", WriterQuiescenceEvidence: o.writerQuiescent, WriterQuiescenceScope: "enrolled_roster_only"}}
	observed.RecordSHA256 = externalCauseHex(64)
	possible, _ := json.Marshal(observed)
	f.returns[1] = observed.RecordSHA256
	must(`INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,2,'production_retirement_v2:possible_start','',$2,$3::jsonb,$4,$5)`, f.retirement, f.returns[1], string(possible), issued.Add(3*time.Second), possible)
	if o.thirdJournalRow {
		third := observed
		third.Record.Sequence, third.Record.State, third.Record.WriterQuiescenceEvidence = 2, "quiescent", true
		third.RecordSHA256 = externalCauseHex(64)
		raw, _ := json.Marshal(third)
		must(`INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,3,'production_retirement_v2:quiescent',$2,$3,$4::jsonb,$5,$6)`, f.retirement, f.returns[1], third.RecordSHA256, string(raw), issued.Add(4*time.Second), raw)
	}

	// The single possible send and its closed caller answer.
	must(`INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,'v2-refused-storage',$4,$5)`, f.retirement, f.attempt, externalCauseHex(64), issued.Add(2*time.Second), f.deadline)
	callerBodySHA := externalCauseHex(64)
	caller := GuestOriginalCallerReturn{RequestID: f.retirement, AttemptID: f.attempt, StartedAt: issued.Add(2 * time.Second), DoStartedAt: issued.Add(2 * time.Second), DoReturnedAt: issued.Add(4 * time.Second), ReadReturnedAt: issued.Add(4 * time.Second), CloseReturnedAt: issued.Add(4 * time.Second), DriverReturnedAt: issued.Add(4 * time.Second), OriginalDeadline: f.deadline, Status: 409, Body: []byte{}, ReceivedBodyBytes: 194, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, ResponseSHA256: callerBodySHA, RetainedPrefixBytes: 194, RetainedPrefixSHA256: callerBodySHA}
	if o.caller200 {
		caller.Status = 200
	}
	if o.persistedBody {
		caller.BodyPersisted = true
		caller.Body = []byte(`{"storage_only":true}`)
	}
	if o.callerTransport {
		caller.ReadFailed = true
	}
	callerWire, _ := json.Marshal(caller)
	f.callerSHA = capacity.BusinessCreationSHA256(callerWire)
	must(`INSERT INTO public.capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, f.retirement, f.callerSHA, callerWire, string(callerWire), issued.Add(5*time.Second))
	if o.poweroffAuthority {
		must(`INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at) VALUES($1,$2,'before_poweroff',1,$3,$4)`, uuid.New(), f.retirement, issued.Add(10*time.Second), issued.Add(3*time.Second))
	}
	if o.priorNativeRead {
		wire := []byte(`{"schema":"original_core_guest_native_poweroff_read_challenge_v2","storage_only":true}`)
		must(`INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6)`, uuid.New(), f.retirement, capacity.BusinessCreationSHA256(wire), wire, string(wire), issued.Add(6*time.Second))
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f v2RefusedFixture) evidence() V2RefusedNativeOffEvidence {
	return V2RefusedNativeOffEvidence{Order: v2RefusedNativeOffOrder, GuestSource: f.source, IntentSHA256: f.intentSHA, ObservationSHA256: f.returns, CallerSHA256: f.callerSHA, CallerStatus: 409}
}

func (f v2RefusedFixture) admission() FailedInstalledV2RefusedNativeOff {
	return FailedInstalledV2RefusedNativeOff{Schema: v2RefusedNativeOffSchema, ID: uuid.NewString(), Stage: "admitted", DisposalID: f.claimed.ID, PreregistrationID: f.pre, RetirementRequestID: f.retirement, Issuer: "collaborator:" + uuid.NewString(), ActualCoreSource: externalCauseHex(40), OriginalClaimSHA256: f.claimSHA, OriginalClaimedIntent: f.current, FailedRun: f.runWire, Evidence: f.evidence()}
}

func (f v2RefusedFixture) exec(t *testing.T, write func(context.Context, *sql.Tx) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Writers hold the scope lock first, as Go's lockMutationScope does.
	if err = lockMutationScope(ctx, tx, f.ns, f.scope); err != nil {
		return err
	}
	if err = write(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (f v2RefusedFixture) insertLineage(t *testing.T, r FailedInstalledV2RefusedNativeOff) (string, error) {
	t.Helper()
	var sha string
	err := f.exec(t, func(ctx context.Context, tx *sql.Tx) error {
		var e error
		sha, e = insertV2RefusedNativeOffTx(ctx, tx, r)
		return e
	})
	return sha, err
}

// nativeRead writes one challenge and its return (a storage-only Hetzner
// plan with the given server status) and returns the return row id and hash.
func (f v2RefusedFixture) nativeRead(t *testing.T, status string, callerSHA string) (string, string) {
	t.Helper()
	issued := time.Now().UTC()
	challenge := GuestNativePoweroffReadV2{Schema: v2NativePoweroffChallengeSchema, ReadID: uuid.NewString(), IntentSHA256: externalCauseHex(64), IntentID: f.retirement, OriginalCallerSHA256: callerSHA, MutationBindingSHA256: externalCauseHex(64), AdapterSourceCommit: externalCauseHex(40), Tuple: f.tuple, IssuedAtCore: issued, OriginalDeadlineCore: issued.Add(5 * time.Second)}
	cw, _ := json.Marshal(challenge)
	server := &model.CapacityVMServerObservation{Status: status}
	returned := GuestNativePoweroffReturnV2{Schema: v2NativePoweroffReturnSchema, Challenge: challenge, Status: "observed", Plan: &model.CapacityVMFleetPlan{Server: server}, StartedAtCore: issued.Add(10 * time.Millisecond), OriginalReturnedAtCore: issued.Add(time.Second)}
	rw, _ := json.Marshal(returned)
	id := uuid.NewString()
	if err := f.exec(t, func(ctx context.Context, tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, challenge.ReadID, f.retirement, capacity.BusinessCreationSHA256(cw), cw, string(cw)); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,original_native_join_wire,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,clock_timestamp())`, id, f.retirement, capacity.BusinessCreationSHA256(rw), rw, string(rw), cw)
		return e
	}); err != nil {
		t.Fatal("storage native read", err)
	}
	return id, capacity.BusinessCreationSHA256(rw)
}

// nativeReturns writes one challenge and then one return per status for that
// same challenge, in order, and returns each return's id and hash. The
// storage table does not make returns unique per challenge, so only the
// migration 86 guard keeps an older OFF return from qualifying.
func (f v2RefusedFixture) nativeReturns(t *testing.T, callerSHA string, statuses ...string) [][2]string {
	t.Helper()
	issued := time.Now().UTC()
	challenge := GuestNativePoweroffReadV2{Schema: v2NativePoweroffChallengeSchema, ReadID: uuid.NewString(), IntentSHA256: externalCauseHex(64), IntentID: f.retirement, OriginalCallerSHA256: callerSHA, MutationBindingSHA256: externalCauseHex(64), AdapterSourceCommit: externalCauseHex(40), Tuple: f.tuple, IssuedAtCore: issued, OriginalDeadlineCore: issued.Add(5 * time.Second)}
	cw, _ := json.Marshal(challenge)
	if err := f.exec(t, func(ctx context.Context, tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, challenge.ReadID, f.retirement, capacity.BusinessCreationSHA256(cw), cw, string(cw))
		return e
	}); err != nil {
		t.Fatal("storage native challenge", err)
	}
	out := make([][2]string, 0, len(statuses))
	for n, status := range statuses {
		returned := GuestNativePoweroffReturnV2{Schema: v2NativePoweroffReturnSchema, Challenge: challenge, Status: "observed", Plan: &model.CapacityVMFleetPlan{Server: &model.CapacityVMServerObservation{Status: status}}, StartedAtCore: issued.Add(10 * time.Millisecond), OriginalReturnedAtCore: issued.Add(time.Duration(n+1) * time.Second)}
		rw, _ := json.Marshal(returned)
		id := uuid.NewString()
		if err := f.exec(t, func(ctx context.Context, tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_native_poweroff_reads(id,intent_id,observation_sha256,original_wire,original_record,original_native_join_wire,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,clock_timestamp())`, id, f.retirement, capacity.BusinessCreationSHA256(rw), rw, string(rw), cw)
			return e
		}); err != nil {
			t.Fatal("storage native return", err)
		}
		out = append(out, [2]string{id, capacity.BusinessCreationSHA256(rw)})
	}
	return out
}

func (f v2RefusedFixture) quiescent(t *testing.T, nativeSHA string) error {
	t.Helper()
	r := f.claimed
	r.Stage = "quiescent"
	r.RetirementRequestID = f.retirement
	r.NativePoweroffSHA256 = nativeSHA
	return f.exec(t, func(ctx context.Context, tx *sql.Tx) error {
		_, e := insertFailedInstalledDisposalTx(ctx, tx, r)
		return e
	})
}

func (f v2RefusedFixture) lineageRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1 OR preregistration_id=$2`, f.claimed.ID, f.pre).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f v2RefusedFixture) nativeReadRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1`, f.retirement).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func v2RefusedSchema86(t *testing.T, db *sql.DB) {
	t.Helper()
	var schema int64
	if err := db.QueryRow(`SELECT max(version_id) FROM public.goose_db_version WHERE is_applied`).Scan(&schema); err != nil || schema != 86 {
		t.Fatal("owning schema86 required", schema, err)
	}
}

func TestFailedInstalledV2RefusedNativeOffMigration86Guards(t *testing.T) {
	db := originalDispositionPG(t)
	v2RefusedSchema86(t, db)
	t.Run("admits_qualifies_and_quiesces_the_exact_refused_history_once", func(t *testing.T) {
		f := v2RefusedPGFixture(t, db, v2RefusedOptions{})
		admission := f.admission()
		sha, err := f.insertLineage(t, admission)
		if err != nil {
			t.Fatal("exact admission refused", err)
		}
		again := f.admission()
		if _, err = f.insertLineage(t, again); err == nil {
			t.Fatal("second admission for one disposal accepted")
		}
		// Without its qualified lineage an admitted disposal cannot be quiesced.
		if err = f.quiescent(t, externalCauseHex(64)); err == nil {
			t.Fatal("admitted disposal quiesced without qualified lineage")
		}
		// A failed (non-OFF) read is retained and cannot qualify.
		runningID, runningSHA := f.nativeRead(t, "running", f.callerSHA)
		running := admission
		running.Stage, running.AdmissionSHA256, running.NativeReadID, running.NativeOffSHA256 = "qualified", sha, runningID, runningSHA
		if _, err = f.insertLineage(t, running); err == nil {
			t.Fatal("non-OFF native observation qualified")
		}
		readID, offSHA := f.nativeRead(t, "off", f.callerSHA)
		qualified := admission
		qualified.Stage, qualified.AdmissionSHA256, qualified.NativeReadID, qualified.NativeOffSHA256 = "qualified", sha, readID, offSHA
		forged := qualified
		forged.NativeOffSHA256 = externalCauseHex(64)
		if _, err = f.insertLineage(t, forged); err == nil {
			t.Fatal("qualification with a forged native hash accepted")
		}
		changed := qualified
		changed.Issuer = "collaborator:" + uuid.NewString()
		if _, err = f.insertLineage(t, changed); err == nil {
			t.Fatal("qualification rewrote its admission")
		}
		if _, err = f.insertLineage(t, qualified); err != nil {
			t.Fatal("exact newest OFF read refused", err)
		}
		if err = f.quiescent(t, externalCauseHex(64)); err == nil {
			t.Fatal("quiescent with a native hash other than the qualified read accepted")
		}
		if err = f.quiescent(t, offSHA); err != nil {
			t.Fatal("quiescent from the qualified lineage refused", err)
		}
		for _, q := range []string{
			`UPDATE public.capacity_guest_v2_refused_nativeoff_quiescences SET recorded_at=recorded_at WHERE disposal_id=$1`,
			`DELETE FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=$1`,
		} {
			if _, err = db.Exec(q, f.claimed.ID); err == nil {
				t.Fatal("immutable lineage rewritten", q)
			}
		}
		if f.lineageRows(t) != 2 {
			t.Fatal("lineage row count changed")
		}
		// The terminal selector accepts only this disposal's own lineage.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		other := f.claimed
		other.RetirementRequestID = uuid.NewString()
		if refused, e := v2RefusedNativeOffQualifiedTx(ctx, tx, other, GuestRetirementOriginalV2{}); !refused || e == nil {
			t.Fatal("admitted disposal accepted another retirement as quiescent", refused, e)
		}
	})
	t.Run("refuses_forged_admission_facts", func(t *testing.T) {
		for name, mutate := range map[string]func(*FailedInstalledV2RefusedNativeOff){
			"forged_caller_hash":   func(a *FailedInstalledV2RefusedNativeOff) { a.Evidence.CallerSHA256 = externalCauseHex(64) },
			"forged_caller_status": func(a *FailedInstalledV2RefusedNativeOff) { a.Evidence.CallerStatus = 500 },
			"swapped_journal": func(a *FailedInstalledV2RefusedNativeOff) {
				a.Evidence.ObservationSHA256[0], a.Evidence.ObservationSHA256[1] = a.Evidence.ObservationSHA256[1], a.Evidence.ObservationSHA256[0]
			},
			"forged_intent_hash":        func(a *FailedInstalledV2RefusedNativeOff) { a.Evidence.IntentSHA256 = externalCauseHex(64) },
			"forged_guest_source":       func(a *FailedInstalledV2RefusedNativeOff) { a.Evidence.GuestSource = externalCauseHex(40) },
			"forged_order":              func(a *FailedInstalledV2RefusedNativeOff) { a.Evidence.Order = "guest_quiesced" },
			"foreign_claim":             func(a *FailedInstalledV2RefusedNativeOff) { a.OriginalClaimSHA256 = externalCauseHex(64) },
			"changed_epoch":             func(a *FailedInstalledV2RefusedNativeOff) { a.OriginalClaimedIntent.FencingToken++ },
			"admission_with_native_off": func(a *FailedInstalledV2RefusedNativeOff) { a.NativeOffSHA256 = externalCauseHex(64) },
		} {
			t.Run(name, func(t *testing.T) {
				f := v2RefusedPGFixture(t, db, v2RefusedOptions{})
				a := f.admission()
				mutate(&a)
				if _, err := f.insertLineage(t, a); err == nil {
					t.Fatal("forged admission accepted", name)
				}
				if f.lineageRows(t) != 0 {
					t.Fatal("refused admission wrote a row", name)
				}
			})
		}
	})
	t.Run("refuses_histories_outside_the_refused_shape", func(t *testing.T) {
		for name, o := range map[string]v2RefusedOptions{
			"caller_200":                      {caller200: true},
			"persisted_caller_body":           {persistedBody: true},
			"caller_transport_failure":        {callerTransport: true},
			"third_journal_row":               {thirdJournalRow: true},
			"writer_quiescence_claimed":       {writerQuiescent: true},
			"active_lease":                    {activeLease: true},
			"legacy_mode":                     {legacyMode: true},
			"earlier_native_poweroff_read":    {priorNativeRead: true},
			"poweroff_authority_read":         {poweroffAuthority: true},
			"retirement_deadline_not_expired": {deadlineOpen: true},
		} {
			t.Run(name, func(t *testing.T) {
				f := v2RefusedPGFixture(t, db, o)
				a := f.admission()
				if o.caller200 || o.persistedBody || o.callerTransport {
					// Declared as the production refusal; the guard reads the row.
					a.Evidence.CallerStatus = 409
				}
				if _, err := f.insertLineage(t, a); err == nil {
					t.Fatal("unqualified history admitted", name)
				}
				if f.lineageRows(t) != 0 {
					t.Fatal("refused admission wrote a row", name)
				}
			})
		}
	})
	t.Run("refuses_a_read_bound_to_another_caller_or_predating_admission", func(t *testing.T) {
		f := v2RefusedPGFixture(t, db, v2RefusedOptions{})
		admission := f.admission()
		sha, err := f.insertLineage(t, admission)
		if err != nil {
			t.Fatal(err)
		}
		readID, offSHA := f.nativeRead(t, "off", externalCauseHex(64))
		q := admission
		q.Stage, q.AdmissionSHA256, q.NativeReadID, q.NativeOffSHA256 = "qualified", sha, readID, offSHA
		if _, err = f.insertLineage(t, q); err == nil {
			t.Fatal("read joined to another caller return qualified")
		}
		// Even a correct newer read cannot qualify while a foreign read exists.
		readID, offSHA = f.nativeRead(t, "off", f.callerSHA)
		q.NativeReadID, q.NativeOffSHA256 = readID, offSHA
		if _, err = f.insertLineage(t, q); err == nil {
			t.Fatal("qualification ignored a foreign native read of the intent")
		}
	})
	t.Run("refuses_an_off_return_that_is_not_the_only_newest_return_of_its_challenge", func(t *testing.T) {
		for name, statuses := range map[string][]string{
			"older_off_then_later_running":    {"off", "running"},
			"running_then_off_same_challenge": {"running", "off"},
		} {
			t.Run(name, func(t *testing.T) {
				f := v2RefusedPGFixture(t, db, v2RefusedOptions{})
				admission := f.admission()
				sha, err := f.insertLineage(t, admission)
				if err != nil {
					t.Fatal(err)
				}
				returns := f.nativeReturns(t, f.callerSHA, statuses...)
				off := returns[0]
				if statuses[1] == "off" {
					off = returns[1]
				}
				q := admission
				q.Stage, q.AdmissionSHA256, q.NativeReadID, q.NativeOffSHA256 = "qualified", sha, off[0], off[1]
				if _, err = f.insertLineage(t, q); err == nil {
					t.Fatal("OFF return qualified beside another return of its challenge", name)
				}
				if f.lineageRows(t) != 1 {
					t.Fatal("refused qualification wrote a row", name)
				}
			})
		}
	})
}

// The Go lane refuses before any write when the request, the disposal mode,
// the lease or the policy do not qualify. Storage-only fixtures never reach
// acceptance (their policy is not a validated Guest policy), so every case
// must leave no lineage row and no native read challenge behind.
func TestFailedInstalledV2RefusedNativeOffGoRefusalsPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	v2RefusedSchema86(t, db)
	store := CapacityStore{DB: db}
	issuer := "collaborator:" + uuid.NewString()
	prepare := func(pre, admission, retirement, who string, withDeadline bool) error {
		ctx := context.Background()
		if withDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
		}
		owner, err := store.PrepareFailedInstalledV2RefusedNativeOffRead(ctx, pre, admission, retirement, who)
		if owner != nil {
			t.Fatal("refused prepare returned an owner")
		}
		return err
	}
	f := v2RefusedPGFixture(t, db, v2RefusedOptions{})
	for name, c := range map[string][4]string{
		"bad_preregistration": {"not-a-uuid", f.claimed.ID, f.retirement, issuer},
		"bad_admission":       {f.pre, uuid.Nil.String(), f.retirement, issuer},
		"bad_retirement":      {f.pre, f.claimed.ID, "", issuer},
		"no_issuer":           {f.pre, f.claimed.ID, f.retirement, ""},
	} {
		if err := prepare(c[0], c[1], c[2], c[3], true); !errors.Is(err, ErrCapacityMutationAuthorization) {
			t.Fatal("malformed request reached storage", name, err)
		}
	}
	if err := prepare(f.pre, f.claimed.ID, f.retirement, issuer, false); !errors.Is(err, ErrCapacityMutationAuthorization) {
		t.Fatal("unbounded context accepted", err)
	}
	for name, o := range map[string]v2RefusedOptions{"storage_only_policy": {}, "legacy_mode": {legacyMode: true}, "active_lease": {activeLease: true}, "caller_200": {caller200: true}, "third_journal_row": {thirdJournalRow: true}} {
		g := v2RefusedPGFixture(t, db, o)
		for _, c := range [][3]string{{g.pre, g.claimed.ID, g.retirement}, {g.pre, g.claimed.ID, uuid.NewString()}, {uuid.NewString(), g.claimed.ID, g.retirement}, {g.pre, uuid.NewString(), g.retirement}} {
			if err := prepare(c[0], c[1], c[2], issuer, true); err == nil {
				t.Fatal("unqualified V2 refused native OFF prepared", name, c)
			}
		}
		if g.lineageRows(t) != 0 || g.nativeReadRows(t) != 0 {
			t.Fatal("refused prepare wrote lineage or a native read challenge", name)
		}
	}
	// A disposal without any admission keeps the normal V2 proof path.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	plain := f.claimed
	plain.RetirementRequestID = f.retirement
	if refused, e := v2RefusedNativeOffQualifiedTx(ctx, tx, plain, GuestRetirementOriginalV2{}); refused || e != nil {
		t.Fatal("unadmitted disposal routed away from the normal V2 proof", refused, e)
	}
	if _, _, e := (CapacityStore{}).RecordFailedInstalledV2RefusedNativeOffRead(ctx, nil, GuestNativePoweroffReturnV2{}); e == nil {
		t.Fatal("record without its prepared owner accepted")
	}
	if !strings.HasPrefix(issuer, "collaborator:") {
		t.Fatal("issuer fixture")
	}
}
