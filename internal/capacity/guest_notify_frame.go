package capacity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type GuestNotifyIdentity struct {
	Source     string `json:"source_commit"`
	Binary     string `json:"binary_sha256"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	BootID     string `json:"boot_id"`
	Invocation string `json:"service_invocation_id"`
}
type GuestNotifyAdmission struct {
	Schema           string              `json:"schema"`
	EnrollmentSHA256 string              `json:"enrollment_sha256"`
	Identity         GuestNotifyIdentity `json:"identity"`
	RootsOpen        bool                `json:"roots_open"`
	ObservedAt       time.Time           `json:"observed_at"`
}
type GuestNotifyOriginalFrame struct {
	Schema                      string              `json:"schema"`
	Kind                        string              `json:"kind"`
	NonceSHA256                 string              `json:"nonce_sha256"`
	Identity                    GuestNotifyIdentity `json:"identity"`
	EnrollmentSHA256            string              `json:"enrollment_sha256,omitempty"`
	OperationID                 string              `json:"operation_id,omitempty"`
	RequestSHA256               string              `json:"request_sha256,omitempty"`
	AdmissionClosedAt           *time.Time          `json:"admission_closed_at,omitempty"`
	ReturnedAt                  time.Time           `json:"returned_at"`
	Roster                      []string            `json:"roster"`
	Lanes                       map[string]string   `json:"lanes,omitempty"`
	CanaryInstalled             bool                `json:"canary_installed"`
	ConnectionsClosed           bool                `json:"connections_closed"`
	Healthy                     bool                `json:"healthy"`
	CanaryBody                  []byte              `json:"canary_body_base64,omitempty"`
	CanaryBodySHA256            string              `json:"canary_body_sha256,omitempty"`
	CanaryReadStartedAt         *time.Time          `json:"canary_read_started_at,omitempty"`
	CanaryReadReturnedAt        *time.Time          `json:"canary_read_returned_at,omitempty"`
	CanaryReadDeadline          *time.Time          `json:"canary_read_deadline,omitempty"`
	CanaryPublication           []byte              `json:"canary_publication_base64,omitempty"`
	CanaryPublicationSHA256     string              `json:"canary_publication_sha256,omitempty"`
	CanaryPublicationStartedAt  *time.Time          `json:"canary_publication_started_at,omitempty"`
	CanaryPublicationReturnedAt *time.Time          `json:"canary_publication_returned_at,omitempty"`
	CanaryPublicationDeadline   *time.Time          `json:"canary_publication_deadline,omitempty"`
	RecordChallengeID           string              `json:"record_challenge_id,omitempty"`
}

var guestNotifyRoster = []string{"http_listener", "http_requests", "relay_app", "relay_critical", "push_maintenance", "broadcast_expander", "push_digests", "push_delivery", "consumers", "broker_monitor"}

func GuestNotifyIdentityMatches(i GuestNotifyIdentity, w model.CapacityGuestRetirementWriter) bool {
	l := w.Lifetime
	return i.Source == l.SourceCommit && i.Binary == l.BinarySHA256 && i.PID == l.PID && i.StartTicks == l.StartTicks && i.BootID == l.BootID && i.Invocation == l.ServiceInvocationID
}
func guestNotifyAdmissionMatches(a GuestNotifyAdmission, e model.CapacityGuestRetirementEnrollment, start, end time.Time) bool {
	return len(e.Statement.Writers) == 1 && a.Schema == "notify_original_guest_admission_v1" && a.EnrollmentSHA256 == GuestRetirementSHA(e) && GuestNotifyIdentityMatches(a.Identity, e.Statement.Writers[0]) && a.RootsOpen && !a.ObservedAt.IsZero() && !a.ObservedAt.Before(start) && !a.ObservedAt.After(end)
}
func GuestNotifyCanaryOriginalFrame(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, r model.CapacityGuestNotifyCanaryRead) (GuestNotifyOriginalFrame, error) {
	var f GuestNotifyOriginalFrame
	fail := fmt.Errorf("exact original admitted Notify application frame required")
	raw := r.NotifyOriginalReturn
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || DecodeBusinessJSON(raw[:len(raw)-1], &f) != nil {
		return f, fail
	}
	canonical, err := json.Marshal(f)
	if err != nil || string(raw) != string(append(canonical, '\n')) || len(e.Statement.Writers) != 1 || f.Schema != "notify_original_guest_writer_v1" || f.NonceSHA256 != e.Statement.Writers[0].Lifetime.ProcessNonceSHA256 || !GuestNotifyIdentityMatches(f.Identity, e.Statement.Writers[0]) || f.EnrollmentSHA256 != c.EnrollmentSHA256 || f.OperationID != c.ChallengeID || f.RequestSHA256 != GuestRetirementSHA(c) || f.RecordChallengeID != c.RecordChallengeID || f.AdmissionClosedAt != nil || !f.CanaryInstalled || f.ConnectionsClosed || !f.Healthy || f.Lanes != nil || len(f.Roster) != len(guestNotifyRoster) || f.ReturnedAt.IsZero() || f.ReturnedAt.Before(r.OriginalReadStartedAt) || f.ReturnedAt.After(r.OriginalFrameReadReturnedAt) {
		return f, fail
	}
	for n, name := range guestNotifyRoster {
		if f.Roster[n] != name {
			return f, fail
		}
	}
	body, sha, start, end, deadline := f.CanaryBody, f.CanaryBodySHA256, f.CanaryReadStartedAt, f.CanaryReadReturnedAt, f.CanaryReadDeadline
	if GuestNotifyCanaryPublication(c) {
		if f.Kind != "creation_canary_publication" || len(f.CanaryBody) != 0 || f.CanaryBodySHA256 != "" || f.CanaryReadStartedAt != nil || f.CanaryReadReturnedAt != nil || f.CanaryReadDeadline != nil {
			return f, fail
		}
		body, sha, start, end, deadline = f.CanaryPublication, f.CanaryPublicationSHA256, f.CanaryPublicationStartedAt, f.CanaryPublicationReturnedAt, f.CanaryPublicationDeadline
	} else if f.Kind != "creation_canary" || len(f.CanaryPublication) != 0 || f.CanaryPublicationSHA256 != "" || f.CanaryPublicationStartedAt != nil || f.CanaryPublicationReturnedAt != nil || f.CanaryPublicationDeadline != nil {
		return f, fail
	}
	if len(body) < 2 || len(body) > 8<<10 || sha != BusinessCreationSHA256(body) || start == nil || end == nil || deadline == nil || start.IsZero() || end.IsZero() || deadline.IsZero() || start.Before(r.OriginalReadStartedAt) || end.Before(*start) || end.After(f.ReturnedAt) || !end.Before(*deadline) || deadline.Sub(*start) > 5*time.Second {
		return f, fail
	}
	return f, nil
}
