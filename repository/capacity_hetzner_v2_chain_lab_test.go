//go:build recoveryfixture && !nativequalification

package repository

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declared test-only operations. These facts are deliberately synthetic and
// have no relationship to a real Guest, process, native VM or authority.
func labSyntheticV2Chain(i model.CapacityGuestRetirementIntentV2, e model.CapacityGuestRetirementEnrollment) ([]model.CapacityGuestRetirementObservationV2, error) {
	if len(e.Statement.Writers) != 1 {
		return nil, fmt.Errorf("one synthetic writer required")
	}
	begin := time.Now().UTC()
	at := func(ms int) time.Time { return begin.Add(time.Duration(ms) * time.Millisecond) }
	mono := i.GuestNonce.IssuedMonotonicNS + 1
	clock := model.CapacityGuestRetirementClockV2{Schema: capacity.GuestRetirementV2ClockSchema, BootID: e.Statement.Actor.BootID, GuestNonceSHA256: capacity.GuestRetirementSHA(i.GuestNonce), ExpiresMonotonicNS: i.GuestExpiresMonotonicNS, StartedMonotonicNS: mono, ReturnedMonotonicNS: mono + int64(25*time.Millisecond), GuestLocalStartedAt: begin, GuestLocalDeadline: begin.Add(time.Duration(i.GuestExpiresMonotonicNS - mono))}
	digest := strings.Repeat("a", 64)
	writer := e.Statement.Writers[0]
	census := func(ms int, processes []model.CapacityGuestRetirementNativeProcess) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: processes, RawCensusSHA256: digest, ObservedAt: at(ms)}
	}
	runtime := model.CapacityGuestRetirementRuntimeReturnV2{Schema: capacity.GuestRetirementV2RuntimeSchema, IntentSHA256: capacity.GuestRetirementSHA(i), AttemptID: i.AttemptID, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, WithdrawRequestSHA256: i.WithdrawRequestSHA256, DrainRequestSHA256: i.DrainRequestSHA256, UnknownWriters: []string{}, ReturnedAt: at(14), Clock: clock}
	runtime.Withdraw = model.CapacityGuestRetirementOriginalOperation{OperationID: i.WithdrawOperationID, RequestSHA256: i.WithdrawRequestSHA256, ResultSHA256: digest, StartedAt: at(6), OriginalReturnedAt: at(7), Outcome: "returned"}
	runtime.Drain = model.CapacityGuestRetirementOriginalOperation{OperationID: i.DrainOperationID, RequestSHA256: i.DrainRequestSHA256, ResultSHA256: digest, StartedAt: at(8), OriginalReturnedAt: at(12), Outcome: "returned"}
	runtime.CensusBefore = census(5, []model.CapacityGuestRetirementNativeProcess{{PID: writer.Lifetime.PID, StartTicks: writer.Lifetime.StartTicks}})
	runtime.CensusAfter = census(13, []model.CapacityGuestRetirementNativeProcess{})
	runtime.Writers = []model.CapacityGuestRetirementWriterReturn{{Writer: writer, AdmissionClosedAt: at(5), OriginalWithdrawReturnedAt: at(7), OriginalWorkersJoinedAt: at(11), OriginalConnectionsJoinedAt: at(11), OriginalResultSHA256: digest, Outcome: "joined"}}
	op := model.CapacityGuestRetirementOperationReturn{StartedAt: at(4), PID: 200, StartTicks: 201, WaitReturnedAt: at(15), ExitCode: 0, BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	offStart := at(18)
	power := model.CapacityGuestRetirementOperationReturn{StartedAt: at(21), PID: 210, StartTicks: 211, WaitReturnedAt: at(22), ExitCode: 0, BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	record := model.CapacityGuestRetirementRecordV2{Schema: capacity.GuestRetirementV2RecordSchema, Sequence: 1, State: "possible_start", Intent: i, IntentSHA256: capacity.GuestRetirementSHA(i), EnrollmentSHA256: capacity.GuestRetirementSHA(e), PossibleStartAt: at(1), RecordedAt: at(2), WriterQuiescenceScope: "enrolled_roster_only", Clock: clock}
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	var observations []model.CapacityGuestRetirementObservationV2
	for n := 1; n <= 4; n++ {
		if n > 1 {
			record.PreviousSHA256 = observations[n-2].RecordSHA256
			record.Sequence = n
			record.RuntimeOperation = &op
			record.RuntimeReturn = &runtime
			record.WriterQuiescenceEvidence = true
			record.RecordedAt = at(16)
			record.State = "quiescent"
		}
		if n >= 3 {
			record.State = "poweroff_possible_start"
			record.PoweroffPossibleStartAt = &offStart
			record.RecordedAt = at(19)
		}
		if n == 4 {
			record.State = "poweroff_command_returned"
			record.PoweroffOperation = &power
			record.PoweroffCommandReturned = true
			record.RecordedAt = at(23)
		}
		o := model.CapacityGuestRetirementObservationV2{Schema: capacity.GuestRetirementV2ObservationSchema, Record: record, RecordSHA256: capacity.GuestRetirementSHA(record), JournalComplete: true, HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: at([]int{3, 17, 20, 24}[n-1]), Clock: clock}
		var err error
		o.Signature, err = capacity.GuestLifecycleSignature(observer, o)
		if err != nil {
			return nil, err
		}
		if err = capacity.GuestRetirementV2Observation(o, e, i, false); err != nil {
			return nil, fmt.Errorf("synthetic record %d: %w", n, err)
		}
		if n > 1 && !capacity.GuestRetirementV2RecordSuccessor(observations[n-2].Record, o.Record) {
			return nil, fmt.Errorf("synthetic chain mismatch %d", n)
		}
		observations = append(observations, o)
	}
	time.Sleep(time.Until(at(30)))
	return observations, nil
}

// Offline unit check of declared fixture facts; it cannot reach a database or
// a provider and is not Guest-quiescence evidence.
func TestLABSyntheticV2ChainLocal(t *testing.T) {
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Skip("explicit test fixture only")
	}
	_, _, reg, receipt, _ := capacity.RecoveryFixtureInstalled(t)
	pre := reg.Result.ProductionClock.Authority.Preregistration
	e := receipt.Enrollment
	now := time.Now().UTC()
	rawNonce := strings.Repeat("f", 64)
	intent := model.CapacityGuestRetirementIntentV2{CapacityGuestRetirementIntent: model.CapacityGuestRetirementIntent{Schema: capacity.GuestRetirementV2IntentSchema, Purpose: capacity.GuestRetirementV2Purpose, BindingName: e.Statement.BindingName, Slot: pre.Slot, RequestID: uuid.NewString(), AttemptID: uuid.NewString(), NonceSHA256: capacity.BusinessCreationSHA256([]byte(rawNonce)), EnrollmentSHA256: capacity.GuestRetirementSHA(e), Tuple: e.Statement.Tuple, Actor: e.Statement.Actor, PolicyID: pre.PolicyID, PolicyChecksum: pre.PolicyChecksum, WorkflowID: pre.WorkflowID, WorkflowChecksum: pre.WorkflowChecksum, Generation: uint64(pre.Generation), Fence: uint64(pre.Fence), LeaseOwner: pre.LeaseOwner, WithdrawOperationID: uuid.NewString(), WithdrawRequestSHA256: strings.Repeat("d", 64), DrainOperationID: uuid.NewString(), DrainRequestSHA256: strings.Repeat("e", 64), IssuedAt: now, OriginalDeadline: now.Add(3 * time.Second)}, PreregistrationID: pre.PreregistrationID, ProfileManifestSHA256: pre.ProfileManifestSHA256, CoreSourceCommit: e.Statement.CoreAuthoritySourceCommit, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256}
	nonce := model.CapacityGuestRetirementNonceV2{Schema: capacity.GuestRetirementV2NonceSchema, RequestID: intent.RequestID, AttemptID: intent.AttemptID, PreflightSHA256: capacity.GuestRetirementV2PreflightSHA(intent), EnrollmentSHA256: capacity.GuestRetirementSHA(e), Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, NonceSHA256: strings.Repeat("2", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 4000000000}
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	nonce.Signature, _ = capacity.GuestLifecycleSignature(observer, nonce)
	intent.GuestNonce = nonce
	intent.GuestExpiresMonotonicNS = nonce.ExpiresMonotonicNS - 1000000
	request := model.CapacityGuestRetirementRequestV2{Intent: intent, Nonce: rawNonce}
	request.Signature, _ = capacity.GuestLifecycleSignature(ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32))), intent)
	if err := capacity.ValidateGuestRetirementV2Request(request, e, time.Now().UTC(), true); err != nil {
		t.Fatal("synthetic request", err)
	}
	chain, err := labSyntheticV2Chain(intent, e)
	if err != nil || len(chain) != 4 {
		t.Fatal("synthetic chain", err)
	}
}
