//go:build recoveryfixture && !nativequalification

package capacity

import (
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These helpers produce declared signed test responses for the real repository
// nonce/send/return joins. Their test keys are absent from the production map.
func RecoveryFixtureCanaryNonce(t *testing.T, c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment) model.CapacityGuestNotifyCanaryChallenge {
	t.Helper()
	RecoveryFixtureApprovalScope(t)
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	phase := "read"
	if GuestNotifyCanaryPublication(c) {
		phase = "publish"
	}
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: phase, PreflightSHA256: GuestNotifyPreflightSHA(c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: BusinessCreationSHA256([]byte("fixture-nonce:" + c.ChallengeID)), IssuedMonotonicNS: int64(time.Second), ExpiresMonotonicNS: int64(time.Second) + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
	c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
	c.Signature = ""
	c.Signature, _ = GuestLifecycleSignature(core, c)
	if err := ValidateGuestNotifyCanaryChallenge(c, e, time.Now().UTC()); err != nil {
		t.Fatal("signed fixture nonce", err)
	}
	return c
}

func RecoveryFixtureCanaryResponse(t *testing.T, p model.CapacityPolicySpec, c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, publication *GuestNotifyPublicationReply) (model.CapacityGuestNotifyCanaryRead, *GuestNotifyPublicationReply) {
	t.Helper()
	RecoveryFixtureApprovalScope(t)
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	start := time.Now().UTC()
	at := func(ms int) time.Time { return start.Add(time.Duration(ms) * time.Millisecond) }
	wire := func(v any) []byte {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	life := e.Statement.Writers[0].Lifetime
	identity := GuestNotifyIdentity{life.SourceCommit, life.BinarySHA256, life.PID, life.StartTicks, life.BootID, life.ServiceInvocationID}
	admit := func(when time.Time) GuestNotifyAdmission {
		return GuestNotifyAdmission{Schema: "notify_original_guest_admission_v1", EnrollmentSHA256: c.EnrollmentSHA256, Identity: identity, RootsOpen: true, ObservedAt: when}
	}
	census := func(when time.Time) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: life.PID, StartTicks: life.StartTicks}}, RawCensusSHA256: strings.Repeat("4", 64), ObservedAt: when}
	}
	frame := GuestNotifyOriginalFrame{Schema: "notify_original_guest_writer_v1", Kind: "creation_canary", NonceSHA256: life.ProcessNonceSHA256, Identity: identity, EnrollmentSHA256: c.EnrollmentSHA256, OperationID: c.ChallengeID, RequestSHA256: GuestRetirementSHA(c), ReturnedAt: at(35), Roster: append([]string(nil), guestNotifyRoster...), CanaryInstalled: true, Healthy: true, RecordChallengeID: c.RecordChallengeID}
	r := model.CapacityGuestNotifyCanaryRead{Schema: GuestNotifyCanaryReadSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: c.ChallengeID, ChallengeSHA256: GuestRetirementSHA(c), PreregistrationID: c.PreregistrationID, EnrollmentSHA256: c.EnrollmentSHA256, Tuple: c.Tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256, CensusBefore: census(at(3)), CensusAfter: census(at(42)), OriginalReadStartedAt: at(1), OriginalRequestWriteReturnedAt: at(4), OriginalFrameReadReturnedAt: at(40), HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: at(45)}
	users := []string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}
	var out *GuestNotifyPublicationReply
	if GuestNotifyCanaryPublication(c) {
		r.Schema, r.Purpose = GuestNotifyCanaryPublicationSchema, GuestNotifyCanaryPublicationPurpose
		frame.Kind = "creation_canary_publication"
		payload := guestNotifyPayload{UserIDs: users, Title: "Capacity canary", Message: "Original two-recipient creation", Route: "/home", Persistent: true, ExpireIn: 1, DedupeKey: GuestNotifyRecord(c.ChallengeID)}
		push, inApp := false, true
		payload.Delivery.Push, payload.Delivery.InApp = &push, &inApp
		body := wire(payload)
		published, committed := at(15), at(20)
		pub := GuestNotifyPublicationReply{Schema: "notify_original_guest_canary_publication_return_v1", Source: p.GuestNotifyCanaryBinding.NotifySourceCommit, EnrollmentSHA256: c.EnrollmentSHA256, ChallengeID: c.ChallengeID, RecordSHA256: BusinessCreationSHA256([]byte(GuestNotifyRecord(c.ChallengeID))), BodySHA256: BusinessCreationSHA256(body), QueueSHA256: BusinessCreationSHA256([]byte(GuestNotifyQueue(p.GuestRetirementBinding.ProfileManifest.NotifyCanaryTopology, c.Tuple.Provider, c.Slot))), NativeBody: body, PreparationBefore: admit(at(10)), PreparationAfter: admit(at(25)), StartedAt: at(5), PublishReturnedAt: &published, CommitReturnedAt: &committed, OutboxXID: "101", BackendPID: 1001, BackendStart: start.Add(-time.Hour)}
		frame.CanaryPublication, frame.CanaryPublicationSHA256 = wire(pub), BusinessCreationSHA256(wire(pub))
		ps, pe, deadline := at(5), at(30), c.OriginalDeadline
		frame.CanaryPublicationStartedAt, frame.CanaryPublicationReturnedAt, frame.CanaryPublicationDeadline = &ps, &pe, &deadline
		out = &pub
	} else {
		if publication == nil {
			t.Fatal("read fixture requires its real retained publication")
		}
		b := *p.GuestNotifyCanaryBinding
		commit := publication.CommitReturnedAt.Add(time.Millisecond)
		nativeFrame := wire(admit(commit.Add(-time.Microsecond)))
		witness := &guestNotifyWitness{MessageSHA: publication.RecordSHA256, BodySHA: publication.BodySHA256, Source: b.NotifySourceCommit, EnrollmentSHA256: c.EnrollmentSHA256, BinarySHA256: identity.Binary, PID: identity.PID, StartTicks: strconv.FormatUint(identity.StartTicks, 10), BootID: identity.BootID, Invocation: identity.Invocation, NativeFrame: nativeFrame, NativeFrameSHA256: BusinessCreationSHA256(nativeFrame), BackendPID: 1002, BackendStart: start.Add(-time.Hour), OriginalXID: "102", RecipientSHA: b.RecipientSHA256, RecipientCount: 2, XID: "102", Commit: &commit}
		notificationID := "99999999-9999-4999-8999-999999999999"
		snapshot := guestNotifySnapshot{Schema: "notify_guest_capacity_creation_canary_read_v2", Database: b.Database, DatabaseOID: b.DatabaseOID, SystemID: b.SystemID, Track: "on", WitnessOID: b.TableOIDs[0], InboxOID: b.TableOIDs[1], NotificationOID: b.TableOIDs[2], StateOID: b.TableOIDs[3], Observed: at(20), Witness: witness, Inbox: &businessInbox{ID: GuestNotifyRecord(c.RecordChallengeID), XID: "102", Commit: &commit}, Notifications: []businessNotification{{ID: notificationID, UserIDs: users, Dedupe: GuestNotifyRecord(c.RecordChallengeID), XID: "102", Commit: &commit, States: []businessState{{NotificationID: notificationID, UserID: users[0], XID: "102", Commit: &commit}, {NotificationID: notificationID, UserID: users[1], XID: "102", Commit: &commit}}}}}
		reply := GuestNotifyBusinessReply{Schema: "notify_guest_capacity_creation_canary_response_v2", Source: b.NotifySourceCommit, Query: b.QuerySHA256, PreparationBefore: admit(at(10)), NativeRaw: wire(snapshot), PreparationAfter: admit(at(30))}
		frame.CanaryBody = wire(reply)
		frame.CanaryBodySHA256 = BusinessCreationSHA256(frame.CanaryBody)
		rs, re, deadline := at(5), at(30), c.OriginalDeadline
		frame.CanaryReadStartedAt, frame.CanaryReadReturnedAt, frame.CanaryReadDeadline = &rs, &re, &deadline
	}
	r.NotifyOriginalReturn = append(wire(frame), '\n')
	r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
	r.Signature, _ = GuestLifecycleSignature(observer, r)
	if err := ValidateGuestNotifyCanaryEnvelope(c, e, r, at(50)); err != nil {
		t.Fatal("signed fixture canary envelope", err)
	}
	return r, out
}
