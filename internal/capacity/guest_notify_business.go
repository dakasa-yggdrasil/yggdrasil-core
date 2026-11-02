package capacity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type GuestNotifyPublicationReply struct {
	Schema            string               `json:"schema_version"`
	Source            string               `json:"source_commit"`
	EnrollmentSHA256  string               `json:"enrollment_sha256"`
	ChallengeID       string               `json:"challenge_id"`
	RecordSHA256      string               `json:"record_sha256"`
	BodySHA256        string               `json:"body_sha256"`
	QueueSHA256       string               `json:"queue_sha256"`
	NativeBody        []byte               `json:"native_body_base64"`
	PreparationBefore GuestNotifyAdmission `json:"preparation_before"`
	PreparationAfter  GuestNotifyAdmission `json:"preparation_after"`
	StartedAt         time.Time            `json:"started_at"`
	PublishReturnedAt *time.Time           `json:"publish_returned_at"`
	CommitReturnedAt  *time.Time           `json:"commit_returned_at"`
	OutboxXID         string               `json:"outbox_xid"`
	BackendPID        int                  `json:"backend_pid"`
	BackendStart      time.Time            `json:"backend_start"`
	ContextFailed     bool                 `json:"context_failed"`
	Hold              string               `json:"hold"`
}
type GuestNotifyBusinessReply struct {
	Schema            string               `json:"schema_version"`
	Source            string               `json:"source_commit"`
	Query             string               `json:"query_sha256"`
	PreparationBefore GuestNotifyAdmission `json:"preparation_before"`
	NativeRaw         []byte               `json:"native_snapshot_base64"`
	PreparationAfter  GuestNotifyAdmission `json:"preparation_after"`
}
type guestNotifyWitness struct {
	MessageSHA        string          `json:"message_sha256"`
	BodySHA           string          `json:"raw_body_sha256"`
	Source            string          `json:"source_commit"`
	EnrollmentSHA256  string          `json:"enrollment_sha256"`
	BinarySHA256      string          `json:"native_binary_sha256"`
	PID               int             `json:"native_pid"`
	StartTicks        string          `json:"native_start_ticks"`
	BootID            string          `json:"native_boot_id"`
	Invocation        string          `json:"native_service_invocation_id"`
	NativeFrame       json.RawMessage `json:"native_frame"`
	NativeFrameSHA256 string          `json:"native_frame_sha256"`
	BackendPID        int             `json:"backend_pid"`
	BackendStart      time.Time       `json:"backend_start"`
	OriginalXID       string          `json:"original_xid"`
	RecipientSHA      string          `json:"recipient_sha256"`
	RecipientCount    int             `json:"recipient_count"`
	XID               string          `json:"xmin"`
	Commit            *time.Time      `json:"commit_at"`
}
type guestNotifySnapshot struct {
	Schema          string                 `json:"schema_version"`
	Database        string                 `json:"database"`
	DatabaseOID     string                 `json:"database_oid"`
	SystemID        string                 `json:"system_identifier"`
	Recovery        bool                   `json:"in_recovery"`
	Track           string                 `json:"track_commit_timestamp"`
	WitnessOID      string                 `json:"witness_oid"`
	InboxOID        string                 `json:"inbox_oid"`
	NotificationOID string                 `json:"notification_oid"`
	StateOID        string                 `json:"state_oid"`
	Observed        time.Time              `json:"observed_at"`
	Witness         *guestNotifyWitness    `json:"witness"`
	Inbox           *businessInbox         `json:"inbox"`
	Notifications   []businessNotification `json:"notifications"`
}

// SQL emits commit_at explicitly for all five same-transaction rows. Missing
// fields cannot masquerade as the explicit NULL of a tracking-disabled server.
func guestNotifyCommitFieldsPresent(raw []byte) bool {
	var snapshot struct {
		Witness       map[string]json.RawMessage `json:"witness"`
		Inbox         map[string]json.RawMessage `json:"inbox"`
		Notifications []struct {
			Commit json.RawMessage `json:"commit_at"`
			States []struct {
				Commit json.RawMessage `json:"commit_at"`
			} `json:"states"`
		} `json:"notifications"`
	}
	if json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Notifications) != 1 || len(snapshot.Notifications[0].States) != 2 {
		return false
	}
	if len(snapshot.Witness["commit_at"]) == 0 || len(snapshot.Inbox["commit_at"]) == 0 || len(snapshot.Notifications[0].Commit) == 0 {
		return false
	}
	for _, state := range snapshot.Notifications[0].States {
		if len(state.Commit) == 0 {
			return false
		}
	}
	return true
}

// Exact public Notify input projection. Defaults are intentional and all
// nonoptional false/zero/empty fields participate in template comparison.
type guestNotifyPayload struct {
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

func GuestNotifyRecord(id string) string {
	if !guestUUID(id) {
		return ""
	}
	return "guest-canary-" + id
}
func guestNotifyTemplate(raw []byte, record, recipientSHA string) bool {
	var actual guestNotifyPayload
	if len(raw) < 2 || len(raw) > 4096 || DecodeBusinessJSON(raw, &actual) != nil || len(actual.UserIDs) != 2 || !guestUUID(actual.UserIDs[0]) || !guestUUID(actual.UserIDs[1]) || actual.UserIDs[0] >= actual.UserIDs[1] || BusinessRecipientSHA256(actual.UserIDs) != recipientSHA {
		return false
	}
	expected := guestNotifyPayload{UserIDs: append([]string(nil), actual.UserIDs...), Title: "Capacity canary", Message: "Original two-recipient creation", Route: "/home", Persistent: true, ExpireIn: 1, DedupeKey: record}
	push, inApp := false, true
	expected.Delivery.Push = &push
	expected.Delivery.InApp = &inApp
	a, _ := json.Marshal(actual)
	e, _ := json.Marshal(expected)
	return bytes.Equal(a, e)
}

func GuestNotifyPublicationFacts(p model.CapacityPolicySpec, c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, r model.CapacityGuestNotifyCanaryRead) (GuestNotifyPublicationReply, error) {
	var out GuestNotifyPublicationReply
	if p.GuestNotifyCanaryBinding == nil || ValidateGuestNotifyCanaryBinding(p) != nil {
		return out, fmt.Errorf("approved declarative Notify canary topology required")
	}
	b := *p.GuestNotifyCanaryBinding
	queue := GuestNotifyQueue(p.GuestRetirementBinding.ProfileManifest.NotifyCanaryTopology, c.Tuple.Provider, c.Slot)
	fail := fmt.Errorf("original Notify SDK critical publication and exact fixed template required")
	f, err := GuestNotifyCanaryOriginalFrame(c, e, r)
	if err != nil || !GuestNotifyCanaryPublication(c) || DecodeBusinessJSON(f.CanaryPublication, &out) != nil {
		return out, fail
	}
	canonical, _ := json.Marshal(out)
	if queue == "" || !bytes.Equal(canonical, f.CanaryPublication) || out.Schema != "notify_original_guest_canary_publication_return_v1" || out.Source != b.NotifySourceCommit || out.EnrollmentSHA256 != c.EnrollmentSHA256 || out.ChallengeID != c.RecordChallengeID || out.RecordSHA256 != BusinessCreationSHA256([]byte(GuestNotifyRecord(c.RecordChallengeID))) || out.QueueSHA256 != BusinessCreationSHA256([]byte(queue)) || out.BodySHA256 != BusinessCreationSHA256(out.NativeBody) || !guestNotifyTemplate(out.NativeBody, GuestNotifyRecord(c.RecordChallengeID), b.RecipientSHA256) || out.StartedAt.Before(*f.CanaryPublicationStartedAt) || out.PublishReturnedAt == nil || out.CommitReturnedAt == nil || out.PublishReturnedAt.Before(out.StartedAt) || out.CommitReturnedAt.Before(*out.PublishReturnedAt) || out.CommitReturnedAt.After(*f.CanaryPublicationReturnedAt) || !businessDecimal(out.OutboxXID, 32) || out.BackendPID < 1 || out.BackendStart.IsZero() || out.ContextFailed || out.Hold != "" || !guestNotifyAdmissionMatches(out.PreparationBefore, e, out.StartedAt, *out.PublishReturnedAt) || !guestNotifyAdmissionMatches(out.PreparationAfter, e, *out.CommitReturnedAt, *f.CanaryPublicationReturnedAt) {
		return out, fail
	}
	return out, nil
}

const GuestNotifyCreationFreshnessClass = "original_challenge_publish_consume_read_v2"

// The publication and read share one original Core budget and execution. A
// later standalone read cannot refresh an old creation. This validates content;
// the repository independently joins the actual immutable executor rows.
func GuestNotifyCausalPair(publication, read model.CapacityGuestNotifyCanaryChallenge) bool {
	if !GuestNotifyCanaryPublication(publication) || GuestNotifyCanaryPublication(read) || publication.ChallengeID != read.RecordChallengeID || publication.RecordChallengeID != publication.ChallengeID || publication.IssuedAt.IsZero() || publication.OriginalDeadline.Sub(publication.IssuedAt) <= 0 || publication.OriginalDeadline.Sub(publication.IssuedAt) > 5*time.Second || read.IssuedAt.Before(publication.IssuedAt) || !read.IssuedAt.Before(publication.OriginalDeadline) || read.OriginalDeadline.After(publication.OriginalDeadline) || !read.OriginalDeadline.After(read.IssuedAt) {
		return false
	}
	normalize := func(c model.CapacityGuestNotifyCanaryChallenge) model.CapacityGuestNotifyCanaryChallenge {
		c.Schema = ""
		c.Purpose = ""
		c.ChallengeID = ""
		c.NonceSHA256 = ""
		c.IssuedAt = time.Time{}
		c.OriginalDeadline = time.Time{}
		c.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
		c.Signature = ""
		return c
	}
	return reflect.DeepEqual(normalize(publication), normalize(read))
}

// Actual publication, critical outbox consumption and same-transaction witness
// visibility occur within the SAME original five-second Core window. Native PG
// commit timestamps are optional diagnostics, never manufactured freshness.
func JoinGuestNotifyBusiness(p model.CapacityPolicySpec, c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, r model.CapacityGuestNotifyCanaryRead, publication GuestNotifyPublicationReply, publicationChallenge model.CapacityGuestNotifyCanaryChallenge, now time.Time) (model.CapacityGuestNotifyBusinessObservation, error) {
	var out model.CapacityGuestNotifyBusinessObservation
	fail := fmt.Errorf("fresh original same-transaction Notify business creation required")
	b := p.GuestNotifyCanaryBinding
	if b == nil || ValidateGuestNotifyCanaryBinding(p) != nil || !GuestNotifyCausalPair(publicationChallenge, c) || ValidateGuestNotifyCanaryChallenge(publicationChallenge, e, publicationChallenge.IssuedAt) != nil || GuestNotifyCanaryPublication(c) || ValidateGuestNotifyCanaryEnvelope(c, e, r, now) != nil {
		return out, fail
	}
	f, err := GuestNotifyCanaryOriginalFrame(c, e, r)
	if err != nil {
		return out, fail
	}
	var reply GuestNotifyBusinessReply
	if DecodeBusinessJSON(f.CanaryBody, &reply) != nil || reply.Schema != "notify_guest_capacity_creation_canary_response_v2" || reply.Source != b.NotifySourceCommit || reply.Query != b.QuerySHA256 || !guestNotifyAdmissionMatches(reply.PreparationBefore, e, *f.CanaryReadStartedAt, *f.CanaryReadReturnedAt) || !guestNotifyAdmissionMatches(reply.PreparationAfter, e, reply.PreparationBefore.ObservedAt, *f.CanaryReadReturnedAt) {
		return out, fail
	}
	var s guestNotifySnapshot
	if len(reply.NativeRaw) > 4096 || !guestNotifyCommitFieldsPresent(reply.NativeRaw) || DecodeBusinessJSON(reply.NativeRaw, &s) != nil || s.Schema != "notify_guest_capacity_creation_canary_read_v2" || s.Database != b.Database || s.DatabaseOID != b.DatabaseOID || s.SystemID != b.SystemID || s.Recovery || (s.Track != "on" && s.Track != "off") || s.WitnessOID != b.TableOIDs[0] || s.InboxOID != b.TableOIDs[1] || s.NotificationOID != b.TableOIDs[2] || s.StateOID != b.TableOIDs[3] || s.Observed.IsZero() || s.Witness == nil || s.Inbox == nil || len(s.Notifications) != 1 {
		return out, fail
	}
	w, inbox, n := s.Witness, s.Inbox, s.Notifications[0]
	record := GuestNotifyRecord(c.RecordChallengeID)
	queue := GuestNotifyQueue(p.GuestRetirementBinding.ProfileManifest.NotifyCanaryTopology, c.Tuple.Provider, c.Slot)
	writer := e.Statement.Writers[0].Lifetime
	if queue == "" || publication.QueueSHA256 != BusinessCreationSHA256([]byte(queue)) || publication.ChallengeID != c.RecordChallengeID || publication.Source != b.NotifySourceCommit || publication.EnrollmentSHA256 != c.EnrollmentSHA256 || publication.RecordSHA256 != BusinessCreationSHA256([]byte(record)) || publication.BodySHA256 != BusinessCreationSHA256(publication.NativeBody) || !guestNotifyTemplate(publication.NativeBody, record, b.RecipientSHA256) || w.BackendStart.IsZero() || !businessDecimal(w.OriginalXID, 32) || w.OriginalXID == publication.OutboxXID || !businessDecimal(publication.OutboxXID, 32) {
		return out, fail
	}
	commit := func(xid string, at *time.Time) bool {
		if !businessDecimal(xid, 32) || xid != w.OriginalXID {
			return false
		}
		if s.Track == "off" {
			return at == nil
		}
		return w.Commit != nil && !w.Commit.IsZero() && !w.Commit.After(s.Observed) && !w.BackendStart.After(*w.Commit) && at != nil && !at.IsZero() && at.Equal(*w.Commit)
	}
	if w.MessageSHA != publication.RecordSHA256 || inbox.ID != record || n.Dedupe != record || w.BodySHA != publication.BodySHA256 || w.Source != b.NotifySourceCommit || w.EnrollmentSHA256 != c.EnrollmentSHA256 || w.BinarySHA256 != writer.BinarySHA256 || w.PID != writer.PID || w.StartTicks != fmt.Sprint(writer.StartTicks) || w.BootID != writer.BootID || w.Invocation != writer.ServiceInvocationID || w.NativeFrameSHA256 != BusinessCreationSHA256(w.NativeFrame) || w.BackendPID < 1 || !commit(w.XID, w.Commit) || !commit(inbox.XID, inbox.Commit) || !commit(n.XID, n.Commit) || !guestUUID(n.ID) || w.RecipientCount != 2 || w.RecipientSHA != b.RecipientSHA256 || len(n.UserIDs) != 2 || len(n.States) != 2 {
		return out, fail
	}
	var native GuestNotifyAdmission
	if DecodeBusinessJSON(w.NativeFrame, &native) != nil || native.Schema != "notify_original_guest_admission_v1" || !native.RootsOpen || native.EnrollmentSHA256 != c.EnrollmentSHA256 || !GuestNotifyIdentityMatches(native.Identity, e.Statement.Writers[0]) || native.ObservedAt.IsZero() {
		return out, fail
	}
	expected, _ := json.Marshal(native)
	if !bytes.Equal(expected, w.NativeFrame) {
		return out, fail
	}
	users := append([]string(nil), n.UserIDs...)
	sort.Strings(users)
	if !guestUUID(users[0]) || !guestUUID(users[1]) || users[0] == users[1] || BusinessRecipientSHA256(users) != b.RecipientSHA256 {
		return out, fail
	}
	seen := map[string]bool{}
	for _, state := range n.States {
		if state.NotificationID != n.ID || seen[state.UserID] || (state.UserID != users[0] && state.UserID != users[1]) || !commit(state.XID, state.Commit) {
			return out, fail
		}
		seen[state.UserID] = true
	}
	out = model.CapacityGuestNotifyBusinessObservation{RecordChallengeID: c.RecordChallengeID, RecordSHA256: w.MessageSHA, BodySHA256: w.BodySHA, NativeSnapshotSHA256: BusinessCreationSHA256(reply.NativeRaw), NotificationSHA256: BusinessCreationSHA256([]byte(n.ID)), OriginalXID: w.OriginalXID, CreationFreshnessClass: GuestNotifyCreationFreshnessClass, CreationUpperBoundSeconds: 5, NativeCommitTimestampKnown: s.Track == "on", OriginalCommit: w.Commit, NativeObserved: s.Observed, EnrollmentSHA256: c.EnrollmentSHA256, Writer: e.Statement.Writers[0], RecipientSHA256: b.RecipientSHA256, RecipientCount: 2, OriginalReadReturnedAt: r.OriginalFrameReadReturnedAt}
	return out, nil
}
