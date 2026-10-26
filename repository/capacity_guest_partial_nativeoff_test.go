package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type partialReadFixture struct {
	id, phase                    string
	ordinal                      int
	possible, deadline, recorded time.Time
	authority                    model.CapacityGuestRetirementAuthority
	stages                       []partialTransportFixture
}
type partialTransportFixture struct {
	stage     string
	t         prejournalSnapshotTransport
	reply     []byte
	challenge *model.CapacityGuestRuntimeSnapshotChallenge
	snapshot  []byte
}
type partialFixture struct {
	stored       GuestRetirementOriginal
	caller       GuestOriginalCallerReturn
	observations [3]model.CapacityGuestRetirementObservation
	reads        [4]partialReadFixture
	observer     ed25519.PrivateKey
	now          time.Time
}

func partialSignedFixture(t *testing.T) partialFixture {
	return partialSignedFixtureWith(t, nil, "", 1)
}
func partialSignedFixtureWith(t *testing.T, header *model.CapacityGuestRetirementIntent, pre string, divisor int) partialFixture {
	t.Helper()
	var f partialFixture
	f.stored, f.caller, _, _, _, _ = prejournalSignedFixture(t)
	if header != nil {
		i := &f.stored.Request.Intent
		i.RequestID, i.AttemptID, i.NonceSHA256 = header.RequestID, header.AttemptID, header.NonceSHA256
		i.PolicyID, i.PolicyChecksum, i.WorkflowID, i.WorkflowChecksum = header.PolicyID, header.PolicyChecksum, header.WorkflowID, header.WorkflowChecksum
		i.Generation, i.Fence, i.LeaseOwner = header.Generation, header.Fence, header.LeaseOwner
		i.IssuedAt, i.OriginalDeadline = header.IssuedAt, header.OriginalDeadline
		f.stored.Preregistration.PreregistrationID = pre
	}
	_, core, _ := ed25519.GenerateKey(rand.Reader)
	_, f.observer, _ = ed25519.GenerateKey(rand.Reader)
	e := &f.stored.Receipt.Enrollment
	e.Statement.ObservationPublicKey = base64.StdEncoding.EncodeToString(f.observer.Public().(ed25519.PublicKey))
	e.Statement.CoreIntentPublicKey = base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey))
	f.stored.Binding.CoreAuthoritySourceCommit = e.Statement.CoreAuthoritySourceCommit
	i := &f.stored.Request.Intent
	i.EnrollmentSHA256 = capacity.GuestRetirementSHA(*e)
	i.WithdrawOperationID = uuid.NewString()
	i.DrainOperationID = uuid.NewString()
	i.WithdrawRequestSHA256 = strings.Repeat("d", 64)
	i.DrainRequestSHA256 = strings.Repeat("e", 64)
	at := i.IssuedAt
	stamp := func(ms int) time.Time { return at.Add(time.Duration(ms) * time.Millisecond / time.Duration(divisor)) }
	f.now = at.Add(time.Minute)
	f.caller.RequestID, f.caller.AttemptID, f.caller.OriginalDeadline = i.RequestID, i.AttemptID, i.OriginalDeadline
	f.caller.StartedAt = stamp(400)
	f.caller.DoStartedAt = stamp(500)
	f.caller.DoReturnedAt = stamp(12000)
	f.caller.ReadReturnedAt = stamp(12010)
	f.caller.CloseReturnedAt = stamp(12020)
	f.caller.DriverReturnedAt = stamp(12030)
	digest := strings.Repeat("a", 64)
	census := func(ms int, processes []model.CapacityGuestRetirementNativeProcess) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: failedInstalledLegacyGuestSource, Processes: processes, RawCensusSHA256: digest, ObservedAt: stamp(ms)}
	}
	runtime := model.CapacityGuestRetirementRuntimeReturn{Schema: capacity.GuestRetirementSchema, IntentSHA256: capacity.GuestRetirementSHA(*i), AttemptID: i.AttemptID, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, WithdrawRequestSHA256: i.WithdrawRequestSHA256, DrainRequestSHA256: i.DrainRequestSHA256, UnknownWriters: []string{}, ReturnedAt: stamp(4100)}
	runtime.Withdraw = model.CapacityGuestRetirementOriginalOperation{OperationID: i.WithdrawOperationID, RequestSHA256: i.WithdrawRequestSHA256, ResultSHA256: digest, StartedAt: stamp(3300), OriginalReturnedAt: stamp(3400), Outcome: "returned"}
	runtime.Drain = model.CapacityGuestRetirementOriginalOperation{OperationID: i.DrainOperationID, RequestSHA256: i.DrainRequestSHA256, ResultSHA256: digest, StartedAt: stamp(3500), OriginalReturnedAt: stamp(3900), Outcome: "returned"}
	w := e.Statement.Writers[0]
	runtime.CensusBefore = census(3250, []model.CapacityGuestRetirementNativeProcess{{PID: w.Lifetime.PID, StartTicks: w.Lifetime.StartTicks}})
	runtime.CensusAfter = census(4000, []model.CapacityGuestRetirementNativeProcess{})
	runtime.Writers = []model.CapacityGuestRetirementWriterReturn{{Writer: w, AdmissionClosedAt: stamp(3240), OriginalWithdrawReturnedAt: stamp(3400), OriginalWorkersJoinedAt: stamp(3800), OriginalConnectionsJoinedAt: stamp(3850), OriginalResultSHA256: digest, Outcome: "joined"}}
	operation := model.CapacityGuestRetirementOperationReturn{StartedAt: stamp(3200), PID: 200, StartTicks: 201, WaitReturnedAt: stamp(4200), ExitCode: 0, BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	r := model.CapacityGuestRetirementRecord{Schema: capacity.GuestRetirementSchema, Sequence: 1, State: "possible_start", Intent: *i, IntentSHA256: capacity.GuestRetirementSHA(*i), EnrollmentSHA256: capacity.GuestRetirementSHA(*e), PossibleStartAt: stamp(1900), RecordedAt: stamp(1910), WriterQuiescenceScope: "enrolled_roster_only"}
	for n := range f.observations {
		if n > 0 {
			r.PreviousSHA256 = f.observations[n-1].RecordSHA256
			r.Sequence = n + 1
			r.State = []string{"", "quiescent", "poweroff_possible_start"}[n]
			r.RuntimeOperation = &operation
			r.RuntimeReturn = &runtime
			r.WriterQuiescenceEvidence = true
			r.RecordedAt = stamp(4500)
			if n == 2 {
				p := stamp(6500)
				r.PoweroffPossibleStartAt = &p
				r.RecordedAt = p
			}
		}
		o := model.CapacityGuestRetirementObservation{Schema: capacity.GuestRetirementSchema, Record: r, RecordSHA256: capacity.GuestRetirementSHA(r), JournalComplete: true, HoldReasons: []string{}, ActiveAttemptID: i.AttemptID, ActiveIntentSHA256: capacity.GuestRetirementSHA(*i), Reader: e.Statement.Actor, ObservedAt: stamp([]int{2750, 5250, 7250}[n])}
		o.Signature, _ = capacity.GuestLifecycleSignature(f.observer, o)
		f.observations[n] = o
	}
	for n := range f.reads {
		phase, ordinal, ms := "before_start", n+1, []int{1000, 2000, 5000, 7000}[n]
		if n >= 2 {
			phase, ordinal = "before_poweroff", n-1
		}
		rd := partialReadFixture{id: uuid.NewString(), phase: phase, ordinal: ordinal, possible: stamp(ms), deadline: stamp(ms + 5000), recorded: stamp(ms + 810)}
		if n == 1 {
			rd.recorded = stamp(3010)
		}
		rd.authority = model.CapacityGuestRetirementAuthority{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, Phase: phase, IntentSHA256: capacity.GuestRetirementSHA(*i), AttemptID: i.AttemptID, NonceSHA256: i.NonceSHA256, EnrollmentSHA256: i.EnrollmentSHA256, State: "authorized", SourceCommit: e.Statement.CoreAuthoritySourceCommit, OriginalDeadline: i.OriginalDeadline, ObservedAt: rd.recorded.Add(-time.Millisecond)}
		stages := []string{"journal"}
		if phase == "before_start" {
			stages = []string{"snapshot"}
			if ordinal == 2 {
				stages = append(stages, "journal")
			}
		}
		for _, stage := range stages {
			start := ms + 100
			if stage == "journal" && n == 1 {
				start = ms + 600
			}
			v := partialTransportFixture{stage: stage}
			v.t = prejournalSnapshotTransport{ReadID: rd.id, Stage: stage, OriginalDeadline: rd.deadline, StartedAt: stamp(start), DoStartedAt: stamp(start + 50), DoReturnedAt: stamp(start + 200), ReadReturnedAt: stamp(start + 250), CloseReturnedAt: stamp(start + 300), DriverReturnedAt: stamp(start + 350), Status: 200, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead}
			if stage == "snapshot" {
				ch := model.CapacityGuestRuntimeSnapshotChallenge{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: uuid.NewString(), BindingName: i.BindingName, Slot: i.Slot, PreregistrationID: f.stored.Preregistration.PreregistrationID, PreregistrationNonceSHA256: digest, OriginalRegistrationSHA256: digest, OriginalCreateWitnessSHA256: digest, EnrollmentSHA256: i.EnrollmentSHA256, ProfileManifestSHA256: digest, Tuple: i.Tuple, RequestID: i.RequestID, AttemptID: i.AttemptID, IntentSHA256: capacity.GuestRetirementSHA(*i), Phase: phase, PolicyID: i.PolicyID, PolicyChecksum: i.PolicyChecksum, WorkflowID: i.WorkflowID, WorkflowChecksum: i.WorkflowChecksum, Generation: i.Generation, Fence: i.Fence, LeaseOwner: i.LeaseOwner, CoreSourceCommit: e.Statement.CoreAuthoritySourceCommit, IssuedAt: rd.possible, OriginalDeadline: rd.deadline}
				ch.Signature, _ = capacity.GuestLifecycleSignature(core, ch)
				v.challenge = &ch
				snap := model.CapacityGuestRuntimeSnapshot{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: ch.ChallengeID, ChallengeSHA256: capacity.GuestRetirementSHA(ch), PreregistrationID: ch.PreregistrationID, OriginalRegistrationSHA256: digest, OriginalCreateWitnessSHA256: digest, ProfileManifestSHA256: digest, EnrollmentSHA256: i.EnrollmentSHA256, Tuple: i.Tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: e.Statement.Writers, WriterRosterSHA256: e.Statement.WriterRosterSHA256, ProtectedCensus: census(start+50, []model.CapacityGuestRetirementNativeProcess{{PID: w.Lifetime.PID, StartTicks: w.Lifetime.StartTicks}}), OriginalReadStartedAt: stamp(start + 20), OriginalReadReturnedAt: stamp(start + 100), OriginalReadsReturned: true, OriginalClosesReturned: true, HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: stamp(start + 130)}
				snap.Signature, _ = capacity.GuestLifecycleSignature(f.observer, snap)
				v.reply = mustRecoveryJSON(t, snap)
				v.snapshot = v.reply
			} else {
				k := 0
				if phase == "before_poweroff" {
					k = ordinal
				}
				v.reply = mustRecoveryJSON(t, f.observations[k])
			}
			v.t.ResponseSHA256 = capacity.BusinessCreationSHA256(v.reply)
			v.t.RetainedPrefixSHA256 = v.t.ResponseSHA256
			v.t.ReceivedBodyBytes = len(v.reply)
			v.t.RetainedPrefixBytes = len(v.reply)
			rd.stages = append(rd.stages, v)
		}
		f.reads[n] = rd
	}
	return f
}
func expectPartialEvidence(t *testing.T, m sqlmock.Sqlmock, f partialFixture) {
	t.Helper()
	i := f.stored.Request.Intent
	m.ExpectQuery("SELECT original_deadline.*FOR UPDATE").WithArgs(i.RequestID).WillReturnRows(sqlmock.NewRows([]string{"deadline"}).AddRow(i.OriginalDeadline))
	m.ExpectQuery("SELECT[\\s\\S]*count\\(\\*\\)[\\s\\S]*capacity_guest_original_caller_attempts").WithArgs(i.RequestID).WillReturnRows(sqlmock.NewRows([]string{"a", "c", "o", "ar", "av", "s", "sv", "t", "f"}).AddRow(1, 1, 3, 4, 4, 2, 2, 5, 0))
	c := mustRecoveryJSON(t, f.caller)
	m.ExpectQuery("SELECT c.original_wire,c.return_sha256").WithArgs(i.RequestID).WillReturnRows(sqlmock.NewRows([]string{"wire", "sha", "consistent", "attempt"}).AddRow(c, capacity.BusinessCreationSHA256(c), true, i.AttemptID))
	for n, o := range f.observations {
		m.ExpectQuery("SELECT sequence,kind,original_wire").WithArgs(i.RequestID, n+1).WillReturnRows(sqlmock.NewRows([]string{"sequence", "kind", "wire", "sha", "consistent"}).AddRow(n+1, o.Record.State, mustRecoveryJSON(t, o), o.RecordSHA256, true))
	}
	for _, r := range f.reads {
		b := mustRecoveryJSON(t, r.authority)
		m.ExpectQuery("SELECT r.id::text,r.possible_read_at").WithArgs(i.RequestID, r.phase, r.ordinal).WillReturnRows(sqlmock.NewRows([]string{"id", "possible", "deadline", "wire", "sha", "recorded", "consistent"}).AddRow(r.id, r.possible, r.deadline, b, capacity.BusinessCreationSHA256(b), r.recorded, true))
		for _, v := range r.stages {
			b = mustRecoveryJSON(t, v.t)
			m.ExpectQuery("SELECT original_wire,return_sha256,original_reply_wire").WithArgs(r.id, v.stage).WillReturnRows(sqlmock.NewRows([]string{"wire", "sha", "reply", "consistent"}).AddRow(b, capacity.BusinessCreationSHA256(b), v.reply, true))
			if v.stage == "snapshot" {
				ch := mustRecoveryJSON(t, v.challenge)
				m.ExpectQuery("SELECT c.original_wire,c.challenge_sha256").WithArgs(i.RequestID, r.phase, r.ordinal).WillReturnRows(sqlmock.NewRows([]string{"cwire", "csha", "wire", "sha", "consistent"}).AddRow(ch, capacity.BusinessCreationSHA256(ch), v.snapshot, capacity.BusinessCreationSHA256(v.snapshot), true))
			}
		}
	}
}
func TestPartialNativeOffHistoricalEvidence(t *testing.T) {
	for _, kind := range []string{"exact_three", "bad_signature", "unknown_census", "foreign_authority", "late_nested", "caller200", "fourth_record_state"} {
		t.Run(kind, func(t *testing.T) {
			f := partialSignedFixture(t)
			switch kind {
			case "bad_signature":
				f.observations[2].Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "unknown_census":
				r := f.observations[2].Record
				rr := *r.RuntimeReturn
				rr.CensusAfter.Processes = []model.CapacityGuestRetirementNativeProcess{{PID: 999, StartTicks: 999}}
				r.RuntimeReturn = &rr
				f.observations[2].Record = r
				f.observations[2].RecordSHA256 = capacity.GuestRetirementSHA(r)
				f.observations[2].Signature = ""
				f.observations[2].Signature, _ = capacity.GuestLifecycleSignature(f.observer, f.observations[2])
				v := &f.reads[3].stages[0]
				v.reply = mustRecoveryJSON(t, f.observations[2])
				v.t.ResponseSHA256 = capacity.BusinessCreationSHA256(v.reply)
				v.t.RetainedPrefixSHA256 = v.t.ResponseSHA256
				v.t.ReceivedBodyBytes = len(v.reply)
				v.t.RetainedPrefixBytes = len(v.reply)
			case "foreign_authority":
				f.reads[3].authority.AttemptID = uuid.NewString()
			case "late_nested":
				f.reads[3].stages[0].t.DriverReturnedAt = f.reads[3].deadline
			case "caller200":
				f.caller.Status = 200
			case "fourth_record_state":
				f.observations[2].Record.State = "poweroff_command_returned"
			}
			db, m, e := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			m.ExpectBegin()
			tx, e := db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			expectPartialEvidence(t, m, f)
			_, e = partialNativeOffEvidenceTx(context.Background(), tx, f.stored, f.now)
			if (e == nil) != (kind == "exact_three") {
				t.Fatal("partial evidence boundary", kind, e)
			}
			if kind == "exact_three" {
				if e = m.ExpectationsWereMet(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestPartialNativeOffReadKeepsFiveSecondsAndOriginalFailure(t *testing.T) {
	at := time.Now().UTC()
	read := PartialNativeOffRead{Schema: "partial_guest548_native_off_read_v1", IssuedAt: at, OriginalDeadline: at.Add(5 * time.Second)}
	o := &PartialNativeOffOwner{read: read}
	for _, kind := range []string{"timely", "late", "call_failed", "context_failed", "missing_plan", "changed_read"} {
		t.Run(kind, func(t *testing.T) {
			v := PartialNativeOffReturn{Schema: "partial_guest548_native_off_return_v1", Read: read, Status: "observed", Plan: &model.CapacityVMFleetPlan{}, StartedAt: at.Add(time.Millisecond), ReturnedAt: at.Add(time.Second)}
			switch kind {
			case "late":
				v.ReturnedAt = read.OriginalDeadline
			case "call_failed":
				v.CallFailed = true
			case "context_failed":
				v.ContextFailed = true
			case "missing_plan":
				v.Plan = nil
			case "changed_read":
				v.Read.ReadID = uuid.NewString()
			}
			if partialNativeOffContent(v, o) != (kind == "timely") {
				t.Fatal("failed read normalized or deadline extended")
			}
		})
	}
	if PartialNativeOffMaximumReads != 3 {
		t.Fatal("finite original-read census changed")
	}
}
