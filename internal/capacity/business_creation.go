package capacity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const BusinessCreationPath = "/internal-runtime/capacity-creation-canary"
const BusinessCreationLimit = 1 << 20

var errBusinessCreation = errors.New("original business creation canary unresolved")
var businessSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var businessSource = regexp.MustCompile(`^[0-9a-f]{40}$`)

func BusinessCreationSHA256(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}
func BusinessRecipientSHA256(ids []string) string {
	ordered := append([]string(nil), ids...)
	sort.Strings(ordered)
	raw, _ := json.Marshal(ordered)
	return BusinessCreationSHA256(raw)
}

func businessDecimal(s string, bits int) bool {
	n, err := strconv.ParseUint(s, 10, bits)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}

// The optional policy never turns incomplete declarations into live facts.
func ValidateBusinessCreationBinding(p model.CapacityPolicySpec) error {
	b := p.BusinessCreationBinding
	if b == nil {
		return nil
	}
	u, err := url.Parse(b.ReaderURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != BusinessCreationPath || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || b.Name == "" || !strings.HasPrefix(b.ReadTokenRef, "secret://") || len(b.ReadTokenRef) > 4096 || !businessSource.MatchString(b.SourceCommit) || !businessSHA.MatchString(b.QuerySHA256) || !businessSHA.MatchString(b.BodySHA256) || !businessSHA.MatchString(b.RecordSHA256) || !businessSHA.MatchString(b.RecipientSHA256) || b.RecipientCount != 2 || b.Database == "" || !businessDecimal(b.DatabaseOID, 32) || !businessDecimal(b.SystemID, 64) || len(b.TableOIDs) != 4 || p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || b.Adapter != p.AssessmentBinding.Snapshot.Adapter || b.Pod.BindingName != p.HPAExecutionBinding.PodTerminationBinding || b.Pod.PodName == "" || !NativeProcessNonce(b.Pod.ExpectedPodUID) || b.Pod.ExpectedPodGeneration < 0 || b.Pod.ExpectedContainerID == "" || b.Pod.ExpectedContainerStartedAt.IsZero() || b.Pod.ExpectedRestartCount < 0 {
		return errBusinessCreation
	}
	seen := map[string]bool{}
	for _, oid := range b.TableOIDs {
		if !businessDecimal(oid, 32) || seen[oid] {
			return errBusinessCreation
		}
		seen[oid] = true
	}
	return nil
}

// Exact names, duplicates, nonnull required members and one closed value.
// Native raw bytes are decoded separately, so JSONB/SDK aliases never silently
// replace source identities. The caller must retain the original raw bytes.
func DecodeBusinessJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > BusinessCreationLimit {
		return errBusinessCreation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return errBusinessCreation
			}
			seen := map[string]bool{}
			for d.More() {
				if delimiter == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errBusinessCreation
					}
					seen[name] = true
				}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if walk() != nil {
		return errBusinessCreation
	}
	if _, err := d.Token(); err != io.EOF {
		return errBusinessCreation
	}
	var value any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return errBusinessCreation
	}
	var fields func(any, reflect.Type) error
	fields = func(value any, typ reflect.Type) error {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ == reflect.TypeOf(time.Time{}) || typ == reflect.TypeOf(json.RawMessage{}) {
			return nil
		}
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() != reflect.Uint8 {
			values, ok := value.([]any)
			if !ok {
				return errBusinessCreation
			}
			for _, v := range values {
				if fields(v, typ.Elem()) != nil {
					return errBusinessCreation
				}
			}
			return nil
		}
		if typ.Kind() != reflect.Struct {
			return nil
		}
		object, ok := value.(map[string]any)
		if !ok {
			return errBusinessCreation
		}
		allowed := map[string]reflect.Type{}
		var collect func(reflect.Type) error
		collect = func(t reflect.Type) error {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if f.Anonymous {
					if collect(f.Type) != nil {
						return errBusinessCreation
					}
					continue
				}
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if tag == "" || tag == "-" {
					continue
				}
				if allowed[tag] != nil {
					return errBusinessCreation
				}
				allowed[tag] = f.Type
				if _, ok := object[tag]; !ok && !strings.Contains(f.Tag.Get("json"), ",omitempty") {
					return errBusinessCreation
				}
			}
			return nil
		}
		if collect(typ) != nil {
			return errBusinessCreation
		}
		for key, v := range object {
			t, ok := allowed[key]
			if !ok || v == nil && t.Kind() != reflect.Pointer {
				return errBusinessCreation
			}
			if v != nil && fields(v, t) != nil {
				return errBusinessCreation
			}
		}
		return nil
	}
	if reflect.TypeOf(out) == nil || reflect.TypeOf(out).Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() || fields(value, reflect.TypeOf(out)) != nil {
		return errBusinessCreation
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errBusinessCreation
	}
	return nil
}

type businessInbox struct {
	ID     string     `json:"message_id"`
	XID    string     `json:"xmin"`
	Commit *time.Time `json:"commit_at"`
}
type businessState struct {
	NotificationID string     `json:"notification_id"`
	UserID         string     `json:"user_id"`
	Opened         *time.Time `json:"opened_at"`
	XID            string     `json:"xmin"`
	Commit         *time.Time `json:"commit_at"`
}
type businessNotification struct {
	ID      string          `json:"id"`
	UserIDs []string        `json:"user_ids"`
	Dedupe  string          `json:"dedupe_key"`
	XID     string          `json:"xmin"`
	Commit  *time.Time      `json:"commit_at"`
	States  []businessState `json:"states"`
}
type businessWitness struct {
	MessageSHA     string     `json:"message_sha256"`
	BodySHA        string     `json:"raw_body_sha256"`
	Source         string     `json:"source_commit"`
	Namespace      string     `json:"consumer_namespace"`
	PodUID         string     `json:"consumer_pod_uid"`
	ProcessNonce   string     `json:"consumer_process_nonce"`
	BackendPID     int        `json:"backend_pid"`
	BackendStart   time.Time  `json:"backend_start"`
	OriginalXID    string     `json:"original_xid"`
	RecipientSHA   string     `json:"recipient_sha256"`
	RecipientCount int        `json:"recipient_count"`
	XID            string     `json:"xmin"`
	Commit         *time.Time `json:"commit_at"`
}
type businessSnapshot struct {
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
	Witness         *businessWitness       `json:"witness"`
	Inbox           *businessInbox         `json:"inbox"`
	Notifications   []businessNotification `json:"notifications"`
}

// Existing independent Pod/SDK admission is bracketed around the native SQL
// read. A competing old process cannot be attributed to selected new capacity.
func JoinBusinessCreation(p model.CapacityPolicySpec, reply model.CapacityBusinessCreationReply, before, after model.AdapterCapacityPodAdmissionResponse, now time.Time) (model.CapacityBusinessCreationObservation, error) {
	var out model.CapacityBusinessCreationObservation
	if ValidateBusinessCreationBinding(p) != nil || p.BusinessCreationBinding == nil || NativeProcessAdmission(p, before, now) != nil || NativeProcessAdmission(p, after, now) != nil {
		return out, errBusinessCreation
	}
	b := p.BusinessCreationBinding
	a, z := before.Observation, after.Observation
	if a.PodUID != b.Pod.ExpectedPodUID || a.PodName != b.Pod.PodName || a.PodGeneration != b.Pod.ExpectedPodGeneration || a.ContainerID != b.Pod.ExpectedContainerID || a.StartedAt == nil || !a.StartedAt.Equal(b.Pod.ExpectedContainerStartedAt) || a.RestartCount != b.Pod.ExpectedRestartCount || z.PodUID != a.PodUID || z.PodGeneration != a.PodGeneration || z.ContainerID != a.ContainerID || z.StartedAt == nil || !z.StartedAt.Equal(*a.StartedAt) || z.RestartCount != a.RestartCount || z.WorkloadResourceVersion != a.WorkloadResourceVersion || before.Admission.State != "roots_open" || after.Admission.State != "roots_open" || before.Admission.ProcessNonce != after.Admission.ProcessNonce || before.Admission.ChallengeSHA256 != after.Admission.ChallengeSHA256 || reply.Schema != "notify_capacity_creation_canary_response_v1" || reply.Source != b.SourceCommit || reply.Query != b.QuerySHA256 {
		return out, errBusinessCreation
	}
	for _, frame := range []model.NativeProcessAdmissionObservation{reply.PreparationBefore, reply.PreparationAfter} {
		guard := model.AdapterCapacityPodAdmissionResponse{Operation: ObserveNativePodAdmission, Status: "observed", Observation: a, Admission: frame}
		if NativeProcessAdmission(p, guard, now) != nil || frame.State != "roots_open" || frame.ProcessNonce != before.Admission.ProcessNonce || frame.ChallengeSHA256 != before.Admission.ChallengeSHA256 {
			return out, errBusinessCreation
		}
	}
	var s businessSnapshot
	if DecodeBusinessJSON(reply.NativeRaw, &s) != nil || s.Schema != "notify_capacity_creation_canary_read_v1" || s.Database != b.Database || s.DatabaseOID != b.DatabaseOID || s.SystemID != b.SystemID || s.Recovery || s.Track != "on" || s.WitnessOID != b.TableOIDs[0] || s.InboxOID != b.TableOIDs[1] || s.NotificationOID != b.TableOIDs[2] || s.StateOID != b.TableOIDs[3] || s.Observed.IsZero() || s.Witness == nil || s.Inbox == nil || len(s.Notifications) != 1 {
		return out, errBusinessCreation
	}
	w, inbox, n := s.Witness, s.Inbox, s.Notifications[0]
	// Both timestamps are native to THIS same PostgreSQL system. Freshness
	// uses their native interval, never an inferred PG/Go clock offset.
	if w.Commit == nil || w.Commit.IsZero() || w.Commit.After(s.Observed) || s.Observed.Sub(*w.Commit) > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second || w.BackendStart.After(*w.Commit) {
		return out, errBusinessCreation
	}
	commit := func(xid string, at *time.Time) bool {
		return businessDecimal(xid, 32) && xid == w.OriginalXID && at != nil && w.Commit != nil && !at.IsZero() && at.Equal(*w.Commit) && !at.After(s.Observed)
	}
	if w.MessageSHA != b.RecordSHA256 || BusinessCreationSHA256([]byte(inbox.ID)) != b.RecordSHA256 || n.Dedupe != inbox.ID || w.BodySHA != b.BodySHA256 || w.Source != b.SourceCommit || !NativeProcessNonce(n.ID) || w.Namespace != a.Namespace || w.PodUID != a.PodUID || w.ProcessNonce != before.Admission.ProcessNonce || w.BackendPID < 1 || w.BackendStart.IsZero() || !commit(w.XID, w.Commit) || !commit(inbox.XID, inbox.Commit) || !commit(n.XID, n.Commit) || w.RecipientCount != 2 || w.RecipientSHA != b.RecipientSHA256 || len(n.UserIDs) != 2 || len(n.States) != 2 {
		return out, errBusinessCreation
	}
	wanted := append([]string(nil), n.UserIDs...)
	sort.Strings(wanted)
	if !NativeProcessNonce(wanted[0]) || !NativeProcessNonce(wanted[1]) || wanted[0] == wanted[1] || BusinessRecipientSHA256(wanted) != b.RecipientSHA256 {
		return out, errBusinessCreation
	}
	seen := map[string]bool{}
	for _, state := range n.States {
		if state.NotificationID != n.ID || seen[state.UserID] || (state.UserID != wanted[0] && state.UserID != wanted[1]) || !commit(state.XID, state.Commit) {
			return out, errBusinessCreation
		}
		seen[state.UserID] = true
	}
	digest := sha256.Sum256(reply.NativeRaw)
	out = model.CapacityBusinessCreationObservation{RecordSHA256: b.RecordSHA256, BodySHA256: w.BodySHA, NativeSnapshotSHA256: hex.EncodeToString(digest[:]), NotificationSHA256: BusinessCreationSHA256([]byte(n.ID)), OriginalXID: w.OriginalXID, OriginalCommit: *w.Commit, NativeObserved: s.Observed, ConsumerPodUID: w.PodUID, ConsumerProcessNonce: w.ProcessNonce, RecipientSHA256: b.RecipientSHA256, RecipientCount: 2}
	return out, nil
}
