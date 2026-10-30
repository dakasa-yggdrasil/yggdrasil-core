package repository

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Cryptographic/transport semantic operands only. This creates no production
// enrollment, native publisher/consumer snapshot or accepted business authority.
func closedCanaryReturnUnit(t *testing.T, at time.Time) (model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestRetirementEnrollment, capacity.GuestOriginalHTTPReturn) {
	t.Helper()
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	sha, source := strings.Repeat("a", 64), strings.Repeat("b", 40)
	life := func(pid int) model.CapacityGuestRetirementLifetime {
		return model.CapacityGuestRetirementLifetime{BootID: "11111111-1111-4111-8111-111111111111", ProcessNonceSHA256: sha, PID: pid, StartTicks: uint64(pid * 10), SourceCommit: source, BinarySHA256: sha, ServiceInvocationID: strings.Repeat("c", 32)}
	}
	tuple := model.CapacityGuestNativeTuple{Provider: "aws", ResourceID: "i-1234567890abcdef0", CreatedAt: at.Add(-time.Hour).Format(time.RFC3339Nano), Slot: 2}
	e := model.CapacityGuestRetirementEnrollment{Statement: model.CapacityGuestRetirementEnrollmentStatement{BindingName: "unit-notify", Tuple: tuple, Actor: life(101), Runtime: life(102), Writers: []model.CapacityGuestRetirementWriter{{ID: "notify", Lifetime: life(103)}}, ObservationPublicKey: base64.StdEncoding.EncodeToString(observer.Public().(ed25519.PublicKey)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey)), CoreAuthoritySourceCommit: source}}
	e.Statement.WriterRosterSHA256 = capacity.GuestRetirementSHA(e.Statement.Writers)
	c := model.CapacityGuestNotifyCanaryChallenge{Schema: capacity.GuestNotifyCanaryChallengeSchema, Purpose: capacity.GuestNotifyCanaryReadPurpose, ChallengeID: "22222222-2222-4222-8222-222222222222", RecordChallengeID: "33333333-3333-4333-8333-333333333333", NonceSHA256: sha, UsageClass: "before_retirement_floor", BindingName: e.Statement.BindingName, Slot: 2, PreregistrationID: "44444444-4444-4444-8444-444444444444", PreregistrationNonceSHA256: sha, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, EnrollmentSHA256: capacity.GuestRetirementSHA(e), ProfileManifestSHA256: sha, Tuple: tuple, PolicyID: "55555555-5555-4555-8555-555555555555", PolicyChecksum: sha, WorkflowID: "66666666-6666-4666-8666-666666666666", WorkflowChecksum: sha, Generation: 2, Fence: 3, LeaseOwner: "unit-lease-owner", CoreSourceCommit: source, IssuedAt: at.Add(-4 * time.Second), OriginalDeadline: at.Add(100 * time.Millisecond)}
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: "read", PreflightSHA256: capacity.GuestNotifyPreflightSHA(c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: strings.Repeat("d", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
	c.GuestNonce.Signature, _ = capacity.GuestLifecycleSignature(observer, c.GuestNonce)
	c.Signature, _ = capacity.GuestLifecycleSignature(core, c)
	census := func(when time.Time) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: 103, StartTicks: 1030}}, RawCensusSHA256: sha, ObservedAt: when}
	}
	r := model.CapacityGuestNotifyCanaryRead{Schema: capacity.GuestNotifyCanaryReadSchema, Purpose: capacity.GuestNotifyCanaryReadPurpose, ChallengeID: c.ChallengeID, ChallengeSHA256: capacity.GuestRetirementSHA(c), PreregistrationID: c.PreregistrationID, EnrollmentSHA256: c.EnrollmentSHA256, Tuple: tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256, CensusBefore: census(at.Add(-7 * time.Millisecond)), CensusAfter: census(at.Add(-500 * time.Microsecond)), OriginalReadStartedAt: at.Add(-8 * time.Millisecond), OriginalRequestWriteReturnedAt: at.Add(-6 * time.Millisecond), OriginalFrameReadReturnedAt: at.Add(-time.Millisecond), HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: at, NotifyOriginalReturn: []byte("{}\n")}
	r.NotifyOriginalReturnSHA256 = capacity.BusinessCreationSHA256(r.NotifyOriginalReturn)
	r.Signature, _ = capacity.GuestLifecycleSignature(observer, r)
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	digest := capacity.BusinessCreationSHA256(wire)
	returned := capacity.GuestOriginalHTTPReturn{StartedAt: at.Add(-10 * time.Millisecond), DoStartedAt: at.Add(-9 * time.Millisecond), DoReturnedAt: at.Add(time.Millisecond), ReadReturnedAt: at.Add(2 * time.Millisecond), CloseReturnedAt: at.Add(3 * time.Millisecond), DriverReturnedAt: at.Add(4 * time.Millisecond), Status: 200, Body: wire, ReceivedBodyBytes: len(wire), ResponseSHA256: digest, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(wire), RetainedPrefixSHA256: digest}
	return c, e, returned
}

func TestGuestNotifyClosedOriginalReturnUsesOriginalClock(t *testing.T) {
	c, e, returned := closedCanaryReturnUnit(t, time.Now().UTC().Add(-time.Second))
	deadline, wire := c.OriginalDeadline, append([]byte(nil), returned.Body...)
	var body model.CapacityGuestNotifyCanaryRead
	if !time.Now().After(deadline) || guestNotifyClosedOriginalEnvelope(c, e, returned, &body) != "" {
		t.Fatal("completed original return must survive later retention")
	}
	if capacity.ValidateGuestNotifyCanaryEnvelope(c, e, body, time.Now().UTC()) == nil {
		t.Fatal("old wall-clock check must reproduce expired-retention refusal")
	}
	if c.OriginalDeadline != deadline || !bytes.Equal(returned.Body, wire) {
		t.Fatal("original clock/wire changed")
	}
}

func TestGuestNotifyClosedOriginalReturnStillRefusesLateOrIncomplete(t *testing.T) {
	for _, name := range []string{"driver_at_deadline", "read_at_deadline", "close_at_deadline", "context_failed", "do_failed", "incomplete_body", "body_changed", "signed_envelope_changed"} {
		t.Run(name, func(t *testing.T) {
			c, e, returned := closedCanaryReturnUnit(t, time.Now().UTC().Add(-time.Second))
			switch name {
			case "driver_at_deadline":
				returned.DriverReturnedAt = c.OriginalDeadline
			case "read_at_deadline":
				returned.ReadReturnedAt = c.OriginalDeadline
			case "close_at_deadline":
				returned.CloseReturnedAt = c.OriginalDeadline
			case "context_failed":
				returned.OriginalContextFailed = true
			case "do_failed":
				returned.DoFailed = true
			case "incomplete_body":
				returned.ResponseBodyScope = capacity.GuestOriginalBodyIncompleteRead
				returned.ReadFailed = true
			case "body_changed":
				returned.Body = append(returned.Body, ' ')
			case "signed_envelope_changed":
				var body model.CapacityGuestNotifyCanaryRead
				if json.Unmarshal(returned.Body, &body) != nil {
					t.Fatal("fixture decode")
				}
				body.Actor.PID++
				returned.Body, _ = json.Marshal(body)
				returned.ReceivedBodyBytes, returned.RetainedPrefixBytes = len(returned.Body), len(returned.Body)
				returned.ResponseSHA256 = capacity.BusinessCreationSHA256(returned.Body)
				returned.RetainedPrefixSHA256 = returned.ResponseSHA256
			}
			var body model.CapacityGuestNotifyCanaryRead
			if guestNotifyClosedOriginalEnvelope(c, e, returned, &body) == "" {
				t.Fatal("late/incomplete/inauthentic original accepted")
			}
		})
	}
}

func TestGuestNotifyClosedDiagnosticPreservesTransportAndErasesBody(t *testing.T) {
	_, _, returned := closedCanaryReturnUnit(t, time.Now().UTC())
	for _, stage := range []string{"original_transport", "original_body_decode", "original_envelope", "publication_facts", "load_original_publication", "business_join", "accepted"} {
		wire, err := guestNotifyReturnDiagnostic(returned, stage)
		if err != nil {
			t.Fatal(err)
		}
		var oldReader capacity.GuestOriginalHTTPReturn
		if json.Unmarshal(wire, &oldReader) != nil {
			t.Fatal("existing non-strict transport reader")
		}
		want := returned
		want.Body = nil
		if !reflect.DeepEqual(oldReader, want) {
			t.Fatal("original transport fields changed")
		}
		var projection map[string]json.RawMessage
		if json.Unmarshal(wire, &projection) != nil || string(projection["CanaryReturnValidationStage"]) != `"`+stage+`"` || string(projection["Body"]) != "null" {
			t.Fatal("closed stage/body erasure")
		}
		delete(projection, "CanaryReturnValidationStage")
		old, _ := json.Marshal(want)
		var original map[string]json.RawMessage
		if json.Unmarshal(old, &original) != nil || !reflect.DeepEqual(projection, original) {
			t.Fatal("diagnostic changed more than one closed field")
		}
	}
}
