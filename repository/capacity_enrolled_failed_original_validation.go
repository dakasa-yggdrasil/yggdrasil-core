package repository

import (
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"regexp"
	"time"
)

// Bound only to a genuinely published dedicated observer before production
// admission. An unpublished Source always refuses; no normal supplier alias.
const enrolledFailedAWSObserverSource = "2f2273391775ff0c8c1c65db6708a59bcc747018"

func EnrolledFailedAWSObserverSource() string { return enrolledFailedAWSObserverSource }

func validateEnrolledFailedOriginalObservation(c model.CapacityOriginalCreateDispositionCandidate, o model.CapacityOriginalCreateDispositionObservation, began, now time.Time, maxAge time.Duration) error {
	return validateEnrolledFailedOriginalObservationForSource(c, o, began, now, maxAge, enrolledFailedAWSObserverSource)
}

// The production entry point supplies only its compiled observer Source. This
// internal pure seam also lets closed-record tests exercise AWS before the
// independently published observer Source exists, without enabling admission.
func validateEnrolledFailedOriginalObservationForSource(c model.CapacityOriginalCreateDispositionCandidate, o model.CapacityOriginalCreateDispositionObservation, began, now time.Time, maxAge time.Duration, observerSource string) error {
	r := c.Request
	if maxAge <= 0 {
		return ErrOriginalCreateDisposition
	}
	if maxAge > 30*time.Second {
		maxAge = 30 * time.Second
	}
	provider := originalDispositionProvider(c)
	if (provider == "hetzner" && o.AdapterSourceCommit != enrolledFailedHetznerCreator) || (provider == "aws" && ((!originalDispositionHex(observerSource, 40) || observerSource == enrolledFailedAWSCreator || observerSource == "836ef8b0a864c07761d1f5e59d11a14d03ebf823") || o.AdapterSourceCommit != observerSource)) {
		return ErrOriginalCreateDisposition
	}
	adjunct := !r.OriginalAuxiliaryInventoryComplete
	if !adjunct {
		if ((provider == "hetzner" && o.InventoryBasis != "original_accepted_auxiliary_inventory_v1") || (provider == "aws" && o.InventoryBasis != "aws_original_enrolled_failed_create_owned_auxiliary_absence_v1")) || r.OriginalCreateActionID != "" {
			return ErrOriginalCreateDisposition
		}
	} else {
		action, err := uuid.Parse(r.OriginalCreateActionID)
		if (r.OriginalAdapterSourceCommit != enrolledFailedAWSCreator) || err != nil || action == uuid.Nil || action.String() != r.OriginalCreateActionID || c.Receipt.ActionID != r.OriginalCreateActionID || len(r.AuxiliaryResources) != 0 || o.Provider != "aws" || o.InventoryBasis != "aws_original_enrolled_failed_create_owned_auxiliary_absence_v1" || len(o.AuxiliaryResources) != 2 || len(o.NativeReads) != 6 {
			return ErrOriginalCreateDisposition
		}
		if o.AuxiliaryResources[0].Kind != "aws_ebs_snapshot_descendants" || !regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`).MatchString(o.AuxiliaryResources[0].ID) || o.AuxiliaryResources[1].Kind != "aws_network_interface" || !regexp.MustCompile(`^eni-[0-9a-f]{8,17}$`).MatchString(o.AuxiliaryResources[1].ID) {
			return ErrOriginalCreateDisposition
		}
	}
	if o.Schema != model.OriginalCreateDispositionObservationSchema || (o.Provider != "aws" && o.Provider != "hetzner") || o.Provider != originalDispositionProvider(c) ||
		o.Profile != r.Profile || o.Slot != r.Slot || o.GrantID != r.GrantID || o.AttemptID != r.AttemptID || o.RequestSHA256 != r.RequestSHA256 || o.ResourceID != r.ExpectedResourceID || o.ResourceCreatedAt != r.ExpectedResourceCreatedAt || o.OriginalAdapterSourceCommit != r.OriginalAdapterSourceCommit || !originalDispositionHex(o.AdapterSourceCommit, 40) ||
		!o.ResourceAbsenceComplete || !o.AuxiliaryInventoryComplete || !o.SharedResourcesPreserved || o.NativeMutations != 0 || o.GuestAdmissionOrBusinessOrSavingsAuthority || o.AuxiliaryResources == nil || o.NativeReads == nil || len(o.NativeReads) < 1 || len(o.NativeReads) > 64 ||
		o.ObservationStartedAt.IsZero() || o.ObservedAt.Before(o.ObservationStartedAt) || o.ObservationStartedAt.Before(began.Add(-5*time.Second)) || o.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(o.ObservedAt) > maxAge || o.ObservedAt.Sub(o.ObservationStartedAt) > 60*time.Second {
		return ErrOriginalCreateDisposition
	}
	if o.ResourceState != "absent" && (o.Provider != "aws" || o.ResourceState != "terminated") {
		return ErrOriginalCreateDisposition
	}
	var expected []model.CapacityMutationAuxiliaryResource
	for _, a := range r.AuxiliaryResources {
		if a.RequiresAbsence {
			expected = append(expected, a)
		}
	}
	if adjunct {
		for _, a := range o.AuxiliaryResources {
			expected = append(expected, model.CapacityMutationAuxiliaryResource{Kind: a.Kind, ID: a.ID, RequiresAbsence: true})
		}
	}
	if len(expected) == 0 || len(expected) > 16 || len(o.AuxiliaryResources) != len(expected) {
		return ErrOriginalCreateDisposition
	}
	for i, a := range expected {
		got := o.AuxiliaryResources[i]
		at, err := time.Parse(time.RFC3339Nano, got.ObservedAt)
		if got.Kind != a.Kind || got.ID != a.ID || !got.Absent || err != nil || at.Before(o.ObservationStartedAt) || at.After(o.ObservedAt) {
			return ErrOriginalCreateDisposition
		}
	}
	serverRead := false
	covered := map[string]bool{}
	var previous time.Time
	totalBytes := int64(0)
	for _, read := range o.NativeReads {
		if read.Operation == "" || len(read.Operation) > 128 || read.ResourceKind == "" || read.ResourceID == "" || len(read.ResourceID) > 256 || read.Status < 200 || read.Status > 499 || read.Status >= 300 && read.Status != 400 && read.Status != 404 || !originalDispositionHex(read.ResponseSHA256, 64) || read.ResponseBytes < 1 || read.ResponseBytes > 64<<10 || read.CalledAt.Before(o.ObservationStartedAt) || read.ReturnedAt.Before(read.CalledAt) || read.ReturnedAt.After(o.ObservedAt) || !previous.IsZero() && read.CalledAt.Before(previous) {
			return ErrOriginalCreateDisposition
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(read.ResponseBodyBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != read.ResponseBodyBase64 || int64(len(raw)) != read.ResponseBytes || originalDispositionDigest(raw) != read.ResponseSHA256 || (read.ResponseRepresentation != "raw_http_body_v1" && read.ResponseRepresentation != "canonical_provider_SDK_result_v1" && (!adjunct || read.Operation != "LookupEvents" || read.ResponseRepresentation != "cloudtrail_lookup_events_userdata_omitted_projection_v1")) {
			return ErrOriginalCreateDisposition
		}
		if o.Provider == "aws" && read.Operation == "LookupEvents" {
			if !adjunct || read.ResponseRepresentation != "cloudtrail_lookup_events_userdata_omitted_projection_v1" || validateEnrolledFailedCloudTrailProjection(raw) != nil || validateEnrolledFailedCloudTrailIdentity(raw, read.ResourceID, r.OriginalCreateActionID) != nil {
				return ErrOriginalCreateDisposition
			}
		} else if read.ResponseRepresentation == "cloudtrail_lookup_events_userdata_omitted_projection_v1" {
			return ErrOriginalCreateDisposition
		}
		if read.ResponseRepresentation == "canonical_provider_SDK_result_v1" && !json.Valid(raw) {
			return ErrOriginalCreateDisposition
		}
		totalBytes += read.ResponseBytes
		if totalBytes > 1<<20 {
			return ErrOriginalCreateDisposition
		}
		previous = read.ReturnedAt
		if read.ResourceID == o.ResourceID && (o.Provider == "aws" && read.ResourceKind == "aws_ec2_instance" || o.Provider == "hetzner" && read.ResourceKind == "server") {
			serverRead = true
		}
		covered[read.ResourceKind+"/"+read.ResourceID] = true
	}
	if !serverRead {
		return ErrOriginalCreateDisposition
	}
	if adjunct && validateOriginalDispositionAWSAdjunctCoverage(o) != nil {
		return ErrOriginalCreateDisposition
	}
	for _, a := range expected {
		if !covered[a.Kind+"/"+a.ID] {
			return ErrOriginalCreateDisposition
		}
	}
	return nil
}

func validateEnrolledFailedCloudTrailProjection(raw []byte) error {
	if !nativeDeniedUniqueJSON(raw) {
		return ErrOriginalCreateDisposition
	}
	var projected struct {
		Schema   string                     `json:"schema"`
		Retained *bool                      `json:"original_http_body_retained"`
		Hashed   *bool                      `json:"original_http_body_hashed"`
		Closed   *bool                      `json:"original_eof_and_close"`
		Removed  *int                       `json:"user_data_fields_removed"`
		Response map[string]json.RawMessage `json:"response"`
	}
	if capacity.DecodeGuestLifecycle(raw, &projected) != nil || projected.Schema != "cloudtrail_lookup_events_userdata_omitted_projection_v1" || projected.Retained == nil || *projected.Retained || projected.Hashed == nil || *projected.Hashed || projected.Closed == nil || !*projected.Closed || projected.Removed == nil || *projected.Removed < 0 || projected.Response == nil {
		return ErrOriginalCreateDisposition
	}
	events, ok := projected.Response["Events"]
	var rows []struct {
		CloudTrailEvent string `json:"CloudTrailEvent"`
	}
	if !ok || json.Unmarshal(events, &rows) != nil {
		return ErrOriginalCreateDisposition
	}
	for _, row := range rows {
		var event map[string]json.RawMessage
		if !nativeDeniedUniqueJSON([]byte(row.CloudTrailEvent)) || json.Unmarshal([]byte(row.CloudTrailEvent), &event) != nil {
			return ErrOriginalCreateDisposition
		}
		var params map[string]json.RawMessage
		if json.Unmarshal(event["requestParameters"], &params) != nil {
			return ErrOriginalCreateDisposition
		}
		if _, exists := params["userData"]; exists {
			return ErrOriginalCreateDisposition
		}
	}
	return nil
}

// CloudTrail EventID names the retained read, whereas the accepted settlement
// ActionID is the AWS RequestID inside that event. They are different identities.
func validateEnrolledFailedCloudTrailIdentity(raw []byte, eventID, requestID string) error {
	for _, value := range []string{eventID, requestID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return ErrOriginalCreateDisposition
		}
	}
	var projected struct {
		Response struct {
			Events []struct {
				EventID         string `json:"EventId"`
				CloudTrailEvent string `json:"CloudTrailEvent"`
			} `json:"Events"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &projected) != nil {
		return ErrOriginalCreateDisposition
	}
	matched := 0
	for _, row := range projected.Response.Events {
		var event struct {
			EventID   string `json:"eventID"`
			RequestID string `json:"requestID"`
		}
		if json.Unmarshal([]byte(row.CloudTrailEvent), &event) != nil {
			return ErrOriginalCreateDisposition
		}
		if event.RequestID == requestID {
			matched++
			if row.EventID != eventID || event.EventID != eventID {
				return ErrOriginalCreateDisposition
			}
		}
	}
	if matched != 1 {
		return ErrOriginalCreateDisposition
	}
	return nil
}
