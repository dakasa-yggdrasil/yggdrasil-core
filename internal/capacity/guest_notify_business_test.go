package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Pure semantic operands, not native SQL/provider evidence or admission.
// A real owning PostgreSQL producer must separately supply physical coverage.
func guestNotifyBusinessUnit(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestNotifyCanaryChallenge, model.CapacityGuestRetirementEnrollment, model.CapacityGuestNotifyCanaryRead, GuestNotifyPublicationReply, time.Time) {
	t.Helper()
	c, e, r, core, observer, now := guestNotifyUnit(t)
	users := []string{"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}
	b := model.CapacityGuestNotifyCanaryBinding{Mode: "original_guest_notify_canary_v1", Name: "unit-source-only", WriterID: "notify", NotifySourceCommit: e.Statement.Writers[0].Lifetime.SourceCommit, QuerySHA256: GuestNotifyBusinessQuerySHA256, RecipientSHA256: BusinessRecipientSHA256(users), RecipientCount: 2, Database: "unit-not-native", DatabaseOID: "10", SystemID: "20", TableOIDs: []string{"30", "40", "50", "60"}, MinimumPublicationIntervalSeconds: 10, MaximumPublicationsPerHour: 120}
	topology := &model.CapacityGuestNotifyCanaryTopology{Schema: "notify_guest_canary_topology_v1", Namespace: "dakasa-production", Binding: "unit-notify", DefinitionsSHA256: strings.Repeat("f", 64), Queues: []model.CapacityGuestNotifyCanaryQueue{{Provider: "aws", Slot: 2, Name: "notify.guest-canary.dakasa-production.unit-notify.aws.s2.q"}}}
	b.TopologySHA256 = GuestRetirementSHA(topology)
	p := model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "unit-notify", Provider: "aws"}}, MaxEvidenceAgeSeconds: 30, GuestNotifyCanaryBinding: &b, GuestRetirementBinding: &model.CapacityGuestRetirementBinding{EvidenceClass: "owned_provisioner_original", MutationBindingName: "unit-notify", Members: []model.CapacityGuestRetirementMemberBinding{{Name: "unit-notify", Slot: 2}}, ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: "unit-notify", NotifyCanaryTopology: topology, CoverageClass: "complete_production_roster", Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "notify", SourceCommit: b.NotifySourceCommit}}}}}
	id := GuestNotifyIdentity{e.Statement.Writers[0].Lifetime.SourceCommit, e.Statement.Writers[0].Lifetime.BinarySHA256, e.Statement.Writers[0].Lifetime.PID, e.Statement.Writers[0].Lifetime.StartTicks, e.Statement.Writers[0].Lifetime.BootID, e.Statement.Writers[0].Lifetime.ServiceInvocationID}
	admit := func(at time.Time) GuestNotifyAdmission {
		return GuestNotifyAdmission{Schema: "notify_original_guest_admission_v1", EnrollmentSHA256: c.EnrollmentSHA256, Identity: id, RootsOpen: true, ObservedAt: at}
	}
	payload := guestNotifyPayload{UserIDs: users, Title: "Capacity canary", Message: "Original two-recipient creation", Route: "/home", Persistent: true, ExpireIn: 1, DedupeKey: GuestNotifyRecord(c.RecordChallengeID)}
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
		t.Fatal("unitpublicationenvelope")
	}
	actual, err := GuestNotifyPublicationFacts(p, pubC, e, pubR)
	if err != nil || actual.BodySHA256 != pub.BodySHA256 {
		t.Fatal("noncanonical native wire template refused", err)
	}
	commit := now.Add(-time.Second)
	observed := now.Add(-10 * time.Millisecond)
	nativeFrame, _ := json.Marshal(admit(now.Add(-time.Second)))
	w := &guestNotifyWitness{MessageSHA: pub.RecordSHA256, BodySHA: pub.BodySHA256, Source: b.NotifySourceCommit, EnrollmentSHA256: c.EnrollmentSHA256, BinarySHA256: id.Binary, PID: id.PID, StartTicks: "1030", BootID: id.BootID, Invocation: id.Invocation, NativeFrame: nativeFrame, NativeFrameSHA256: BusinessCreationSHA256(nativeFrame), BackendPID: 1002, BackendStart: now.Add(-time.Hour), OriginalXID: "102", RecipientSHA: b.RecipientSHA256, RecipientCount: 2, XID: "102", Commit: &commit}
	notificationID := "99999999-9999-4999-8999-999999999999"
	snapshot := guestNotifySnapshot{Schema: "notify_guest_capacity_creation_canary_read_v1", Database: b.Database, DatabaseOID: b.DatabaseOID, SystemID: b.SystemID, Track: "on", WitnessOID: b.TableOIDs[0], InboxOID: b.TableOIDs[1], NotificationOID: b.TableOIDs[2], StateOID: b.TableOIDs[3], Observed: observed, Witness: w, Inbox: &businessInbox{ID: GuestNotifyRecord(c.RecordChallengeID), XID: "102", Commit: &commit}, Notifications: []businessNotification{{ID: notificationID, UserIDs: users, Dedupe: GuestNotifyRecord(c.RecordChallengeID), XID: "102", Commit: &commit, States: []businessState{{NotificationID: notificationID, UserID: users[0], XID: "102", Commit: &commit}, {NotificationID: notificationID, UserID: users[1], XID: "102", Commit: &commit}}}}}
	raw, _ := json.Marshal(snapshot)
	reply := GuestNotifyBusinessReply{Schema: "notify_guest_capacity_creation_canary_response_v1", Source: b.NotifySourceCommit, Query: b.QuerySHA256, PreparationBefore: admit(now.Add(-4500 * time.Microsecond)), NativeRaw: raw, PreparationAfter: admit(now.Add(-3500 * time.Microsecond))}
	var f GuestNotifyOriginalFrame
	_ = json.Unmarshal(r.NotifyOriginalReturn, &f)
	f.CanaryBody, _ = json.Marshal(reply)
	f.CanaryBodySHA256 = BusinessCreationSHA256(f.CanaryBody)
	frame, _ = json.Marshal(f)
	r.NotifyOriginalReturn = append(frame, '\n')
	r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
	r.Signature = ""
	r.Signature, _ = GuestLifecycleSignature(observer, r)
	return p, c, e, r, pub, now
}
func TestGuestNotifyNativeBusinessJoinSeparatesSQLAndWire(t *testing.T) {
	for _, kind := range []string{"original_noncanonical_wire", "changed_body_wire", "wrong_outbox_xid", "publication_wrong_enrollment", "publication_wrong_record", "publication_wrong_template", "publication_wrong_queue", "missing_publication", "stale_pg_commit", "different_state_xid", "missing_state", "wrong_native_writer", "wrong_native_enrollment", "wrong_native_frame_hash", "wrong_source", "wrong_database", "in_recovery", "untracked_commit", "wrong_query", "wrong_recipient_set"} {
		t.Run(kind, func(t *testing.T) {
			p, c, e, r, pub, now := guestNotifyBusinessUnit(t)
			_, _, _, _, observer, _ := guestNotifyUnit(t)
			if strings.HasPrefix(kind, "publication_") || kind == "missing_publication" || kind == "changed_body_wire" || kind == "wrong_outbox_xid" {
				switch kind {
				case "changed_body_wire":
					pub.BodySHA256 = strings.Repeat("e", 64)
				case "wrong_outbox_xid":
					pub.OutboxXID = "102"
				case "publication_wrong_enrollment":
					pub.EnrollmentSHA256 = strings.Repeat("e", 64)
				case "publication_wrong_record":
					pub.ChallengeID = c.ChallengeID
				case "publication_wrong_queue":
					pub.QueueSHA256 = strings.Repeat("e", 64)
				case "publication_wrong_template":
					pub.NativeBody = []byte(`{}`)
					pub.BodySHA256 = BusinessCreationSHA256(pub.NativeBody)
				case "missing_publication":
					pub = GuestNotifyPublicationReply{}
				}
			} else if kind != "original_noncanonical_wire" {
				var f GuestNotifyOriginalFrame
				_ = json.Unmarshal(r.NotifyOriginalReturn, &f)
				var reply GuestNotifyBusinessReply
				_ = json.Unmarshal(f.CanaryBody, &reply)
				var s guestNotifySnapshot
				_ = json.Unmarshal(reply.NativeRaw, &s)
				switch kind {
				case "stale_pg_commit":
					s.Observed = s.Witness.Commit.Add(time.Minute)
				case "different_state_xid":
					s.Notifications[0].States[0].XID = "103"
				case "missing_state":
					s.Notifications[0].States = s.Notifications[0].States[:1]
				case "wrong_native_writer":
					s.Witness.PID++
				case "wrong_native_enrollment":
					s.Witness.EnrollmentSHA256 = strings.Repeat("e", 64)
				case "wrong_native_frame_hash":
					s.Witness.NativeFrameSHA256 = strings.Repeat("e", 64)
				case "wrong_source":
					s.Witness.Source = strings.Repeat("e", 40)
				case "wrong_database":
					s.Database = "foreign"
				case "in_recovery":
					s.Recovery = true
				case "untracked_commit":
					s.Track = "off"
				case "wrong_query":
					reply.Query = strings.Repeat("e", 64)
				case "wrong_recipient_set":
					s.Notifications[0].UserIDs[0] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				}
				reply.NativeRaw, _ = json.Marshal(s)
				f.CanaryBody, _ = json.Marshal(reply)
				f.CanaryBodySHA256 = BusinessCreationSHA256(f.CanaryBody)
				raw, _ := json.Marshal(f)
				r.NotifyOriginalReturn = append(raw, '\n')
				r.NotifyOriginalReturnSHA256 = BusinessCreationSHA256(r.NotifyOriginalReturn)
				r.Signature = ""
				r.Signature, _ = GuestLifecycleSignature(observer, r)
			}
			observed, err := JoinGuestNotifyBusiness(p, c, e, r, pub, now)
			if (err == nil) != (kind == "original_noncanonical_wire") {
				t.Fatalf("native creation admission %s: %v", kind, err)
			}
			if err == nil && (observed.RecipientCount != 2 || observed.Writer != e.Statement.Writers[0] || observed.BodySHA256 != pub.BodySHA256) {
				t.Fatal("original business/source identity lost")
			}
		})
	}
}
