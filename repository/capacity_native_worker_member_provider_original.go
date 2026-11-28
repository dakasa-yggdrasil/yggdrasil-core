package repository

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const nativeMemberProviderBodyLimit = 736 << 10
const nativeMemberProviderWireLimit = 1 << 20

var nativeMemberProviderAWSID = regexp.MustCompile(`^i-[a-f0-9]{17}$`)

// Exact private mirrors of the provider capture DTOs. HCloud does not carry a
// PermitID or Action in its nested body; those facts must never be invented.
type nativeMemberAWSDeleteOriginal struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	PermitID           string `json:"permit_id"`
	Action             string `json:"action"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}
type nativeMemberHCloudDeleteOriginal struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	RequestIDObserved  bool   `json:"request_id_observed"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}

func (nativeMemberAWSDeleteOriginal) String() string                  { return "[private Native provider original]" }
func (v nativeMemberAWSDeleteOriginal) GoString() string              { return v.String() }
func (nativeMemberAWSDeleteOriginal) MarshalJSON() ([]byte, error)    { return nil, errNativeMember }
func (nativeMemberHCloudDeleteOriginal) String() string               { return "[private Native provider original]" }
func (v nativeMemberHCloudDeleteOriginal) GoString() string           { return v.String() }
func (nativeMemberHCloudDeleteOriginal) MarshalJSON() ([]byte, error) { return nil, errNativeMember }

// Capture publishers include every member, including an empty request ID and
// empty body. Preserve ordinary JSON formatting/order while refusing omitted,
// null, duplicate, case-aliased, unknown or noncanonical byte members.
func nativeMemberProviderDecode(raw []byte, out any, names ...string) bool {
	if len(raw) == 0 || len(raw) > nativeMemberProviderWireLimit {
		return false
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	members, err := capacity.NativeCanonicalObject(raw, allowed)
	if err != nil || len(members) != len(names) {
		return false
	}
	for _, name := range names {
		if bytes.Equal(bytes.TrimSpace(members[name]), []byte("null")) {
			return false
		}
	}
	return capacity.DecodeNativeCapacity(json.RawMessage(raw), out) == nil
}

func nativeMemberProviderRequestID(id string, hcloud bool) bool {
	limit := 128
	if hcloud {
		limit = 256
	}
	if len(id) < 1 || len(id) > limit {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || hcloud && (c == '.' || c == '_' || c == ':') {
			continue
		}
		return false
	}
	return true
}

func nativeMemberProviderPhysicalBound(a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerAbortPermit) bool {
	if a.Physical == nil || a.Physical.CreatedAt.IsZero() || !a.Physical.CreatedAt.Equal(c.Physical.CreatedAt) {
		return false
	}
	physical, actual := c.Physical, *a.Physical
	physical.CreatedAt, actual.CreatedAt = time.Time{}, time.Time{}
	if physical != actual || physical.Region == "" || physical.Region != a.Region ||
		!capacity.ValidDigest(physical.PhysicalSpecSHA256) || physical.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 ||
		!capacity.ValidDigest(physical.LaunchSHA256) || physical.LaunchSHA256 != a.LaunchSHA256 ||
		!capacity.ValidDigest(physical.PhysicalBindingSHA256) {
		return false
	}
	switch a.Provider {
	case "aws":
		return a.ProviderIDPrefix == "aws:///" && physical.Zone != "" &&
			nativeMemberProviderAWSID.MatchString(physical.ResourceID) &&
			physical.ProviderID == "aws:///"+physical.Zone+"/"+physical.ResourceID
	case "hetzner":
		id, err := strconv.ParseInt(physical.ResourceID, 10, 64)
		return a.ProviderIDPrefix == "hcloud://" && err == nil && id > 0 &&
			strconv.FormatInt(id, 10) == physical.ResourceID && physical.AccountID == "" &&
			physical.Zone == physical.Region && physical.ProviderID == "hcloud://"+physical.ResourceID
	default:
		return false
	}
}

// This proves only complete, correctly joined private transport custody. The
// authenticated Abort.Receive already checked the original bearer and retained
// TokenSHA256 before clearing plaintext. It has no outer schema field: the
// Abort context and the nested provider DTO each carry their real schema.
//
// A complete 4xx/5xx, an empty body, or an expired historical permit is still an
// original. No status/action/body here proves effect, absence or bill closure.
// Callers must independently retain GET truth and the unchanged AbortSettled
// predicate/history. This function never changes a record or authorizes a send.
func nativeMemberProviderOriginalComplete(r nativeWorkerAbortRecord) bool {
	c, a, original := r.Context, r.Attempt, r.Original
	if original == nil || !original.CaptureComplete || original.ErrorClass != "" ||
		len(original.OriginalReturn) == 0 || len(original.OriginalReturn) > nativeMemberProviderWireLimit ||
		c.Schema != model.CapacityNativeWorkerAbortSchema || c.PermitID == uuid.Nil || a.ID == uuid.Nil ||
		c.AttemptID != a.ID || original.PermitID != c.PermitID || c.BindingName == "" ||
		c.BindingName != a.Execution.BindingName || original.BindingName != c.BindingName ||
		!nativeRuntimeCommit(r.SourceCommit) || r.SourceCommit == strings.Repeat("0", 40) || r.SourceCommit != a.SourceCommit ||
		!nativeRuntimeCommit(c.SDKSourceCommit) || c.SDKSourceCommit == strings.Repeat("0", 40) || c.SDKSourceCommit != a.Execution.SDKSourceCommit ||
		!capacity.ValidDigest(c.ExecutionScopeSHA256) || c.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 ||
		c.Capability != "destroy_native_worker" || c.Capability != a.Execution.DestroyCapability ||
		!capacity.ValidDigest(r.TokenSHA256) || original.SettlementToken != "" || c.SettlementToken != "" ||
		c.Redeemable || c.MutationPermitted || c.ExpiresAt.IsZero() ||
		c.PoolUID == "" || c.PoolUID != a.PoolUID || c.PoolEpoch < 1 || c.PoolEpoch != a.PoolEpoch ||
		c.Registry != a.Registry || !nativeMemberProviderPhysicalBound(a, c) {
		return false
	}
	switch c.State {
	case "received", "unknown", "observed":
	default:
		return false
	}
	switch a.Provider {
	case "aws":
		var wire nativeMemberAWSDeleteOriginal
		defer func() { clear(wire.Body) }()
		if !nativeMemberProviderDecode(original.OriginalReturn, &wire,
			"schema", "attempt_id", "permit_id", "action", "http_status", "request_id", "transport_completed", "body") {
			return false
		}
		return wire.Schema == "aws_native_worker_delete_original_return_v1" &&
			wire.AttemptID == a.ID.String() && wire.PermitID == c.PermitID.String() &&
			wire.Action == "TerminateInstances" && wire.HTTPStatus >= 100 && wire.HTTPStatus <= 599 &&
			wire.TransportCompleted && wire.Body != nil && len(wire.Body) <= nativeMemberProviderBodyLimit &&
			(wire.RequestID == "" || nativeMemberProviderRequestID(wire.RequestID, false))
	case "hetzner":
		var wire nativeMemberHCloudDeleteOriginal
		defer func() { clear(wire.Body) }()
		if !nativeMemberProviderDecode(original.OriginalReturn, &wire,
			"schema", "attempt_id", "http_status", "request_id", "request_id_observed", "transport_completed", "body") {
			return false
		}
		return wire.Schema == "hcloud_native_worker_delete_original_return_v1" &&
			wire.AttemptID == a.ID.String() && wire.HTTPStatus >= 100 && wire.HTTPStatus <= 599 &&
			wire.TransportCompleted && wire.Body != nil && len(wire.Body) <= nativeMemberProviderBodyLimit &&
			(!wire.RequestIDObserved && wire.RequestID == "" || wire.RequestIDObserved && nativeMemberProviderRequestID(wire.RequestID, true))
	}
	return false
}
