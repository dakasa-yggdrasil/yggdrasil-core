package repository

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	. "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
)

// Adapted from source-owned guestNotifyUnit and guestNotifyBusinessUnit. These
// are signed unit operands only, never real Guest or production evidence.
var guestNotifyRoster = []string{"http_listener", "http_requests", "relay_app", "relay_critical", "push_maintenance", "broadcast_expander", "push_digests", "push_delivery", "consumers", "broker_monitor"}

type recoveryGuestNotifyPayload struct {
	ID              string   `json:"id"`
	UserIDs         []string `json:"userIds"`
	Title           string   `json:"title"`
	Message         string   `json:"message"`
	Route           string   `json:"route"`
	Persistent      bool     `json:"persistent"`
	ExpireIn        int      `json:"expireIn"`
	RepeatAfter     int      `json:"repeatAfter"`
	ExcludeOpenedIn int      `json:"excludeOpenedIn"`
	ImagePreview    string   `json:"imagePreview"`
	Category        string   `json:"category,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	ActionURL       string   `json:"actionUrl,omitempty"`
	DedupeKey       string   `json:"dedupeKey,omitempty"`
	Delivery        struct {
		Push  *bool `json:"push,omitempty"`
		InApp *bool `json:"inApp,omitempty"`
	} `json:"delivery,omitempty"`
	ActorAvatar string `json:"actorAvatar,omitempty"`
	ActorName   string `json:"actorName,omitempty"`
	ActorID     string `json:"actorId,omitempty"`
	ChatID      string `json:"chatId,omitempty"`
	RoomID      string `json:"roomId,omitempty"`
}

func recoveryGuestNotifyUnit(t *testing.T) (model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestRetirementEnrollment, model.CapacityGuestNotifyCanaryRead, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	core := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
	observer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("o", 32)))
	sha := strings.Repeat("a", 64)
	source := originalReadCoreSource
	life := func(pid int) model.CapacityGuestRetirementLifetime {
		return model.CapacityGuestRetirementLifetime{BootID: "11111111-1111-4111-8111-111111111111", ProcessNonceSHA256: sha, PID: pid, StartTicks: uint64(pid * 10), SourceCommit: source, BinarySHA256: sha, ServiceInvocationID: strings.Repeat("c", 32)}
	}
	tuple := model.CapacityGuestNativeTuple{Provider: "aws", ResourceID: "i-1234567890abcdef0", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), Slot: 2}
	e := model.CapacityGuestRetirementEnrollment{Statement: model.CapacityGuestRetirementEnrollmentStatement{BindingName: "unit-notify", Tuple: tuple, Actor: life(101), Runtime: life(102), Writers: []model.CapacityGuestRetirementWriter{{ID: "notify", Lifetime: func() model.CapacityGuestRetirementLifetime {
		x := life(103)
		x.SourceCommit = originalReadNotifySource
		return x
	}()}}, ObservationPublicKey: base64.StdEncoding.EncodeToString(observer.Public().(ed25519.PublicKey)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey)), CoreAuthoritySourceCommit: source}}
	e.Statement.WriterRosterSHA256 = GuestRetirementSHA(e.Statement.Writers)
	cid := "22222222-2222-4222-8222-222222222222"
	c := model.CapacityGuestNotifyCanaryChallenge{Schema: GuestNotifyCanaryChallengeSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: cid, RecordChallengeID: "33333333-3333-4333-8333-333333333333", NonceSHA256: sha, UsageClass: "initial_useful_membership", BindingName: e.Statement.BindingName, Slot: 2, PreregistrationID: "44444444-4444-4444-8444-444444444444", PreregistrationNonceSHA256: sha, OriginalRegistrationSHA256: sha, OriginalCreateWitnessSHA256: sha, EnrollmentSHA256: GuestRetirementSHA(e), ProfileManifestSHA256: sha, Tuple: tuple, PolicyID: "55555555-5555-4555-8555-555555555555", PolicyChecksum: sha, WorkflowID: "66666666-6666-4666-8666-666666666666", WorkflowChecksum: sha, Generation: 2, Fence: 3, LeaseOwner: "unit-lease-owner", CoreSourceCommit: source, IssuedAt: now.Add(-10 * time.Millisecond), OriginalDeadline: now.Add(4 * time.Second)}
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: "read", PreflightSHA256: GuestNotifyPreflightSHA(c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: strings.Repeat("d", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
	c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
	c.Signature, _ = GuestLifecycleSignature(core, c)
	census := func(at time.Time) model.CapacityGuestRetirementProtectedCensus {
		return model.CapacityGuestRetirementProtectedCensus{Schema: "guest_retirement_protected_cgroup_v1", Scope: "fixed_protected_cgroup_v2", SourceCommit: e.Statement.Runtime.SourceCommit, Processes: []model.CapacityGuestRetirementNativeProcess{{PID: 103, StartTicks: 1030}}, RawCensusSHA256: sha, ObservedAt: at}
	}
	r := model.CapacityGuestNotifyCanaryRead{Schema: GuestNotifyCanaryReadSchema, Purpose: GuestNotifyCanaryReadPurpose, ChallengeID: cid, ChallengeSHA256: GuestRetirementSHA(c), PreregistrationID: c.PreregistrationID, EnrollmentSHA256: c.EnrollmentSHA256, Tuple: tuple, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writers: append([]model.CapacityGuestRetirementWriter(nil), e.Statement.Writers...), WriterRosterSHA256: e.Statement.WriterRosterSHA256, CensusBefore: census(now.Add(-7 * time.Millisecond)), CensusAfter: census(now.Add(-500 * time.Microsecond)), OriginalReadStartedAt: now.Add(-8 * time.Millisecond), OriginalRequestWriteReturnedAt: now.Add(-6 * time.Millisecond), OriginalFrameReadReturnedAt: now.Add(-time.Millisecond), HoldReasons: []string{}, Reader: e.Statement.Actor, ObservedAt: now}
	start, returned, deadline := now.Add(-5*time.Millisecond), now.Add(-3*time.Millisecond), c.OriginalDeadline
	f := GuestNotifyOriginalFrame{Schema: "notify_original_guest_writer_v1", Kind: "creation_canary", NonceSHA256: e.Statement.Writers[0].Lifetime.ProcessNonceSHA256, Identity: GuestNotifyIdentity{originalReadNotifySource, sha, 103, 1030, e.Statement.Actor.BootID, e.Statement.Actor.ServiceInvocationID}, EnrollmentSHA256: c.EnrollmentSHA256, OperationID: cid, RequestSHA256: GuestRetirementSHA(c), ReturnedAt: now.Add(-2 * time.Millisecond), Roster: append([]string(nil), guestNotifyRoster...), CanaryInstalled: true, Healthy: true, CanaryBody: []byte(`{"scope":"semantic unit only; no native business authority"}`), CanaryReadStartedAt: &start, CanaryReadReturnedAt: &returned, CanaryReadDeadline: &deadline, RecordChallengeID: c.RecordChallengeID}
	f.CanaryBodySHA256 = BusinessCreationSHA256(f.CanaryBody)
	raw, _ := json.Marshal(f)
	r.NotifyOriginalReturn = append(raw, '\n')
	r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
	r.Signature, _ = GuestLifecycleSignature(observer, r)
	return c, e, r, core, observer, now
}
func recoveryPublicationFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestRetirementEnrollment, model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestNotifyCanaryRead, time.Time) {
	t.Helper()
	c, e, r, core, observer, now := recoveryGuestNotifyUnit(t)
	users := []string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}
	b := model.CapacityGuestNotifyCanaryBinding{Mode: "original_guest_notify_canary_v1", Name: "unit-source-only", WriterID: "notify", NotifySourceCommit: e.Statement.Writers[0].Lifetime.SourceCommit, QuerySHA256: GuestNotifyBusinessQuerySHA256, RecipientSHA256: BusinessRecipientSHA256(users), RecipientCount: 2, Database: "unit-not-native", DatabaseOID: "10", SystemID: "20", TableOIDs: []string{"30", "40", "50", "60"}, MinimumPublicationIntervalSeconds: 10, MaximumPublicationsPerHour: 120}
	topology := &model.CapacityGuestNotifyCanaryTopology{Schema: "notify_guest_canary_topology_v1", Namespace: "dakasa-production", Binding: "unit-notify", DefinitionsSHA256: strings.Repeat("f", 64), Queues: []model.CapacityGuestNotifyCanaryQueue{{Provider: "aws", Slot: 2, Name: "notify.guest-canary.dakasa-production.unit-notify.aws.s2.q"}}}
	b.TopologySHA256 = GuestRetirementSHA(topology)
	p := model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "unit-notify", Provider: "aws"}}, MaxEvidenceAgeSeconds: 30, GuestNotifyCanaryBinding: &b, GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "owned_provisioner_original", MutationBindingName: "unit-notify", Members: []model.CapacityGuestRetirementMemberBinding{{Name: "unit-notify", Slot: 2}}, ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: "unit-notify", NotifyCanaryTopology: topology, CoverageClass: "complete_production_roster", Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "notify", SourceCommit: b.NotifySourceCommit}}}}}
	id := GuestNotifyIdentity{e.Statement.Writers[0].Lifetime.SourceCommit, e.Statement.Writers[0].Lifetime.BinarySHA256, e.Statement.Writers[0].Lifetime.PID, e.Statement.Writers[0].Lifetime.StartTicks, e.Statement.Writers[0].Lifetime.BootID, e.Statement.Writers[0].Lifetime.ServiceInvocationID}
	admit := func(at time.Time) GuestNotifyAdmission {
		return GuestNotifyAdmission{Schema: "notify_original_guest_admission_v1", EnrollmentSHA256: c.EnrollmentSHA256, Identity: id, RootsOpen: true, ObservedAt: at}
	}
	payload := recoveryGuestNotifyPayload{UserIDs: users, Title: "Capacity canary", Message: "Original two-recipient creation", Route: "/home", Persistent: true, ExpireIn: 1, DedupeKey: GuestNotifyRecord(c.RecordChallengeID)}
	push, inApp := false, true
	payload.Delivery.Push = &push
	payload.Delivery.InApp = &inApp
	// Deliberately non-Marshal wire spacing/order to exercise native JSONB wire
	// versus source-owned semantic template, without pretending to run PG.
	wire, _ := json.MarshalIndent(payload, "", " ")
	pub := GuestNotifyPublicationReply{Schema: "notify_original_guest_canary_publication_return_v1", Source: b.NotifySourceCommit, EnrollmentSHA256: c.EnrollmentSHA256, ChallengeID: c.RecordChallengeID, RecordSHA256: BusinessCreationSHA256([]byte(GuestNotifyRecord(c.RecordChallengeID))), BodySHA256: BusinessCreationSHA256(wire), QueueSHA256: BusinessCreationSHA256([]byte(GuestNotifyQueue(topology, c.Tuple.Provider, c.Slot))), NativeBody: wire, PreparationBefore: admit(now.Add(-6 * time.Millisecond)), PreparationAfter: admit(now.Add(-3500 * time.Microsecond)), StartedAt: now.Add(-7 * time.Millisecond), OutboxXID: "101", BackendPID: 1001, BackendStart: now.Add(-time.Hour)}
	published, committed := now.Add(-5*time.Millisecond), now.Add(-4*time.Millisecond)
	pub.PublishReturnedAt = &published
	pub.CommitReturnedAt = &committed
	pubC := c
	pubC.Schema = GuestNotifyCanaryPublicationChallengeSchema
	pubC.Purpose = GuestNotifyCanaryPublicationPurpose
	pubC.ChallengeID = c.RecordChallengeID
	pubC.NonceSHA256 = strings.Repeat("e", 64)
	pubC.Signature = ""
	pubC.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
	pubC.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: pubC.ChallengeID, Phase: "publish", PreflightSHA256: GuestNotifyPreflightSHA(pubC), EnrollmentSHA256: pubC.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: strings.Repeat("e", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(pubC.OriginalDeadline.Sub(pubC.IssuedAt))}
	pubC.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, pubC.GuestNonce)
	pubC.Signature, _ = GuestLifecycleSignature(core, pubC)
	pubR := r
	pubR.Schema = GuestNotifyCanaryPublicationSchema
	pubR.Purpose = GuestNotifyCanaryPublicationPurpose
	pubR.ChallengeID = pubC.ChallengeID
	pubR.ChallengeSHA256 = GuestRetirementSHA(pubC)
	var pf GuestNotifyOriginalFrame
	_ = json.Unmarshal(r.NotifyOriginalReturn, &pf)
	pf.Kind = "creation_canary_publication"
	pf.OperationID = pubC.ChallengeID
	pf.RequestSHA256 = GuestRetirementSHA(pubC)
	pf.CanaryBody = nil
	pf.CanaryBodySHA256 = ""
	pf.CanaryReadStartedAt = nil
	pf.CanaryReadReturnedAt = nil
	pf.CanaryReadDeadline = nil
	pf.CanaryPublication, _ = json.Marshal(pub)
	pf.CanaryPublicationSHA256 = BusinessCreationSHA256(pf.CanaryPublication)
	ps, pe, pd := now.Add(-7*time.Millisecond), now.Add(-3*time.Millisecond), c.OriginalDeadline
	pf.CanaryPublicationStartedAt = &ps
	pf.CanaryPublicationReturnedAt = &pe
	pf.CanaryPublicationDeadline = &pd
	frame, _ := json.Marshal(pf)
	pubR.NotifyOriginalReturn = append(frame, '\n')
	pubR.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(pubR.NotifyOriginalReturn)
	pubR.Signature = ""
	pubR.Signature, _ = GuestLifecycleSignature(observer, pubR)
	if ValidateGuestNotifyCanaryEnvelope(pubC, e, pubR, now) != nil {
		t.Fatal("signed source publication fixture invalid")
	}
	if _, err := GuestNotifyPublicationFacts(p, pubC, e, pubR); err != nil {
		_, frameErr := GuestNotifyCanaryOriginalFrame(pubC, e, pubR)
		t.Fatal("source publication facts invalid", err, "frame", frameErr, "binding", ValidateGuestNotifyCanaryBinding(p))
	}
	// A read is issued only after the accepted original publication returned.
	c.IssuedAt = now.Add(time.Millisecond)
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
	c.Signature = ""
	c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{Schema: "original_notify_canary_guest_nonce_v1", ChallengeID: c.ChallengeID, Phase: "read", PreflightSHA256: GuestNotifyPreflightSHA(c), EnrollmentSHA256: c.EnrollmentSHA256, Actor: e.Statement.Actor, Runtime: e.Statement.Runtime, Writer: e.Statement.Writers[0], NonceSHA256: strings.Repeat("d", 64), IssuedMonotonicNS: 1000000000, ExpiresMonotonicNS: 1000000000 + int64(c.OriginalDeadline.Sub(c.IssuedAt))}
	c.GuestNonce.Signature, _ = GuestLifecycleSignature(observer, c.GuestNonce)
	c.Signature, _ = GuestLifecycleSignature(core, c)
	if ValidateGuestNotifyCanaryChallenge(c, e, c.IssuedAt.Add(time.Millisecond)) != nil || !GuestNotifyCausalPair(pubC, c) {
		t.Fatal("signed source read fixture invalid")
	}
	return p, c, e, pubC, pubR, now
}

func TestHistoricalRecoverySignedSourceFixture(t *testing.T) {
	recoveryPublicationFixture(t)
}
