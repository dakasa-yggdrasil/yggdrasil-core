//go:build recoveryfixture && !nativequalification

package capacity

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type recoveryFixtureTransport func(*http.Request) (*http.Response, error)

func (f recoveryFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func RecoveryFixtureRetirementNonceClient(t *testing.T, r model.CapacityGuestRetirementRequestV2, e model.CapacityGuestRetirementEnrollment) *GuestOriginalHTTPClient {
	t.Helper()
	RecoveryFixtureApprovalScope(t)
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	return &GuestOriginalHTTPClient{origin: "https://signed-fixture.invalid", client: &http.Client{Transport: recoveryFixtureTransport(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != model.GuestRetirementV2NoncePath {
			t.Fatal("fixture attempted non-nonce transport")
		}
		n := model.CapacityGuestRetirementNonceV2{Schema: GuestRetirementV2NonceSchema, RequestID: r.Intent.RequestID, AttemptID: r.Intent.AttemptID, PreflightSHA256: GuestRetirementV2PreflightSHA(r.Intent), EnrollmentSHA256: GuestRetirementSHA(e), Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, NonceSHA256: BusinessCreationSHA256([]byte("retirement-fixture:" + r.Intent.RequestID)), IssuedMonotonicNS: int64(time.Second), ExpiresMonotonicNS: int64(time.Second) + int64(r.Intent.OriginalDeadline.Sub(r.Intent.IssuedAt))}
		n.Signature, _ = GuestLifecycleSignature(observer, n)
		wire, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(wire)))}, nil
	})}}
}

func RecoveryFixtureRetirementJournal(t *testing.T, i model.CapacityGuestRetirementIntentV2, e model.CapacityGuestRetirementEnrollment) []model.CapacityGuestRetirementObservationV2 {
	t.Helper()
	RecoveryFixtureApprovalScope(t)
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	start := time.Now().UTC()
	at := func(ms int) time.Time { return start.Add(time.Duration(ms) * time.Millisecond) }
	mono := i.GuestNonce.IssuedMonotonicNS + int64(time.Millisecond)
	clock := func(ms int) model.CapacityGuestRetirementClockV2 {
		return model.CapacityGuestRetirementClockV2{Schema: GuestRetirementV2ClockSchema, BootID: e.Statement.Actor.BootID, GuestNonceSHA256: GuestRetirementSHA(i.GuestNonce), ExpiresMonotonicNS: i.GuestExpiresMonotonicNS, StartedMonotonicNS: mono, ReturnedMonotonicNS: mono + int64(time.Duration(ms)*time.Millisecond), GuestLocalStartedAt: start, GuestLocalDeadline: start.Add(time.Duration(i.GuestExpiresMonotonicNS - mono))}
	}
	digest := strings.Repeat("a", 64)
	writer := e.Statement.Writers[0]
	census := func(ms int, processes []model.CapacityGuestRetirementNativeProcess) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: processes, RawCensusSHA256: digest, ObservedAt: at(ms)}
	}
	runtime := model.CapacityGuestRetirementRuntimeReturnV2{Schema: GuestRetirementV2RuntimeSchema, IntentSHA256: GuestRetirementSHA(i), AttemptID: i.AttemptID, Runtime: e.Statement.Runtime, WriterRosterSHA256: e.Statement.WriterRosterSHA256, WithdrawRequestSHA256: i.WithdrawRequestSHA256, DrainRequestSHA256: i.DrainRequestSHA256, UnknownWriters: []string{}, ReturnedAt: at(41), Clock: clock(41)}
	runtime.Withdraw = model.CapacityGuestRetirementOriginalOperation{OperationID: i.WithdrawOperationID, RequestSHA256: i.WithdrawRequestSHA256, ResultSHA256: digest, StartedAt: at(33), OriginalReturnedAt: at(34), Outcome: "returned"}
	runtime.Drain = model.CapacityGuestRetirementOriginalOperation{OperationID: i.DrainOperationID, RequestSHA256: i.DrainRequestSHA256, ResultSHA256: digest, StartedAt: at(35), OriginalReturnedAt: at(39), Outcome: "returned"}
	runtime.CensusBefore = census(32, []model.CapacityGuestRetirementNativeProcess{{PID: writer.Lifetime.PID, StartTicks: writer.Lifetime.StartTicks}})
	runtime.CensusAfter = census(40, []model.CapacityGuestRetirementNativeProcess{})
	runtime.Writers = []model.CapacityGuestRetirementWriterReturn{{Writer: writer, AdmissionClosedAt: at(32), OriginalWithdrawReturnedAt: at(34), OriginalWorkersJoinedAt: at(38), OriginalConnectionsJoinedAt: at(38), OriginalResultSHA256: digest, Outcome: "joined"}}
	op := model.CapacityGuestRetirementOperationReturn{StartedAt: at(31), PID: 200, StartTicks: 201, WaitReturnedAt: at(42), BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	offStart := at(65)
	power := model.CapacityGuestRetirementOperationReturn{StartedAt: at(66), PID: 210, StartTicks: 211, WaitReturnedAt: at(69), BodyJoined: true, CloseReturned: true, Outcome: "returned"}
	record := model.CapacityGuestRetirementRecordV2{Schema: GuestRetirementV2RecordSchema, Sequence: 1, State: "possible_start", Intent: i, IntentSHA256: GuestRetirementSHA(i), EnrollmentSHA256: GuestRetirementSHA(e), PossibleStartAt: at(19), RecordedAt: at(20), WriterQuiescenceScope: "enrolled_roster_only", Clock: clock(25)}
	var observations []model.CapacityGuestRetirementObservationV2
	for n := 1; n <= 4; n++ {
		if n > 1 {
			record.PreviousSHA256 = observations[n-2].RecordSHA256
			record.Sequence = n
			record.RuntimeOperation = &op
			record.RuntimeReturn = &runtime
			record.WriterQuiescenceEvidence = true
			record.RecordedAt = at(45)
			record.State = "quiescent"
			record.Clock = clock(50)
		}
		if n >= 3 {
			record.State = "poweroff_possible_start"
			record.PoweroffPossibleStartAt = &offStart
			record.RecordedAt = at(65)
			record.Clock = clock(68)
		}
		if n == 4 {
			record.State = "poweroff_command_returned"
			record.PoweroffOperation = &power
			record.PoweroffCommandReturned = true
			record.RecordedAt = at(70)
			record.Clock = clock(75)
		}
		observed := model.CapacityGuestRetirementObservationV2{Schema: GuestRetirementV2ObservationSchema, Record: record, RecordSHA256: GuestRetirementSHA(record), JournalComplete: true, HoldReasons: []string{}, ActiveAttemptID: i.AttemptID, ActiveIntentSHA256: GuestRetirementSHA(i), Reader: e.Statement.Actor, ObservedAt: at([]int{25, 50, 68, 75}[n-1]), Clock: record.Clock}
		observed.Signature, _ = GuestLifecycleSignature(observer, observed)
		if err := GuestRetirementV2Observation(observed, e, i, true); err != nil {
			t.Fatal("signed V2 retirement fixture", n, err)
		}
		observations = append(observations, observed)
	}
	return observations
}

func RecoveryFixtureNativeOffPlan(t *testing.T, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration, tuple model.CapacityGuestNativeTuple) model.CapacityVMFleetPlan {
	t.Helper()
	RecoveryFixtureApprovalScope(t)
	b := p.MutationBindings[0]
	slot := b.Slots[pre.Slot-1]
	spec := *slot.DesiredSpec
	spec.Capability, spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = VMObserveServer, tuple.ResourceID, tuple.CreatedAt
	wire, err := canonicalMutationProjection(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: tuple.ResourceID, CreatedAt: tuple.CreatedAt}, Name: spec.NativeName, Status: "off", PhysicalSpecVerified: true, ObservedAt: now, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": vmLabelDigest(b.ScopeChecksum), "yggdrasil.io/spec": vmLabelDigest(spec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": strconv.Itoa(pre.Slot), "yggdrasil.io/intent": pre.OriginalCreateGrantID}}
	return model.CapacityVMFleetPlan{DesiredSpec: spec, RequestSHA256: BusinessCreationSHA256(wire), Protected: pre.Slot <= b.ProtectedSlots, Server: &s, ObservedAt: now}
}
