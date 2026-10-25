package repository

import (
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestEnrolledFailedAbsenceRetainsHNativeProofBoundaries(t *testing.T) {
	c, o, _ := originalDispositionObservationFixture(t)
	c.OriginalPolicy.Spec, _ = json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: c.Binding.ProfileName, Provider: "hetzner"}}})
	c.Request.OriginalAuxiliaryInventoryComplete = true
	c.Request.OriginalAdapterSourceCommit = enrolledFailedHetznerCreator
	o.Provider = "hetzner"
	o.OriginalAdapterSourceCommit = enrolledFailedHetznerCreator
	o.AdapterSourceCommit = enrolledFailedHetznerCreator
	o.ResourceState = "absent"
	o.InventoryBasis = "original_accepted_auxiliary_inventory_v1"
	for i := range o.NativeReads {
		if o.NativeReads[i].ResourceKind == "aws_ec2_instance" {
			o.NativeReads[i].ResourceKind = "server"
		}
		o.NativeReads[i].Status = 404
	}
	for _, name := range []string{"valid", "wrong_observer", "missing_body", "missing_interval", "missing_aux", "mutations", "business", "missing_original_inventory"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(o)
			var x model.CapacityOriginalCreateDispositionObservation
			_ = json.Unmarshal(raw, &x)
			candidate := c
			switch name {
			case "wrong_observer":
				x.AdapterSourceCommit = strings.Repeat("1", 40)
			case "missing_body":
				x.NativeReads[0].ResponseBodyBase64 = ""
			case "missing_interval":
				x.ObservationStartedAt = time.Time{}
			case "missing_aux":
				x.NativeReads = x.NativeReads[:1]
			case "mutations":
				x.NativeMutations = 1
			case "business":
				x.GuestAdmissionOrBusinessOrSavingsAuthority = true
			case "missing_original_inventory":
				candidate.Request.OriginalAuxiliaryInventoryComplete = false
			}
			if (validateEnrolledFailedOriginalObservation(candidate, x, o.ObservationStartedAt, o.ObservedAt, 30*time.Second) == nil) != (name == "valid") {
				t.Fatal("native H proof boundary", name)
			}
		})
	}
}
func TestEnrolledFailedCloudTrailProjectionNeverRetainsUserData(t *testing.T) {
	for _, name := range []string{"valid", "raw_retained", "raw_hashed", "not_closed", "user_data", "missing_retained", "missing_hashed", "missing_closed", "missing_removed"} {
		t.Run(name, func(t *testing.T) {
			event := map[string]any{"requestParameters": map[string]any{}}
			if name == "user_data" {
				event["requestParameters"].(map[string]any)["userData"] = "PRIVATE"
			}
			eventRaw, _ := json.Marshal(event)
			v := map[string]any{"schema": "cloudtrail_lookup_events_userdata_omitted_projection_v1", "original_http_body_retained": name == "raw_retained", "original_http_body_hashed": name == "raw_hashed", "original_eof_and_close": name != "not_closed", "user_data_fields_removed": 1, "response": map[string]any{"Events": []map[string]any{{"CloudTrailEvent": string(eventRaw)}}}}
			for _, field := range []struct{ name, key string }{{"missing_retained", "original_http_body_retained"}, {"missing_hashed", "original_http_body_hashed"}, {"missing_closed", "original_eof_and_close"}, {"missing_removed", "user_data_fields_removed"}} {
				if name == field.name {
					delete(v, field.key)
				}
			}
			raw, _ := json.Marshal(v)
			if (validateEnrolledFailedCloudTrailProjection(raw) == nil) != (name == "valid") {
				t.Fatal("projection privacy", name)
			}
		})
	}
	// Exercise the actual observation loop with closed outer records and fully
	// recomputed body/hash/extent. The production wrapper stays bound to the
	// actual published observer Source; the native history itself is declared.
	c, o, now := enrolledFailedAWSObservationFixture(t)
	if validateEnrolledFailedOriginalObservation(c, o, o.ObservationStartedAt, now, 30*time.Second) != nil {
		t.Fatal("compiled observer Source refused the declared closed-record fixture")
	}
	foreign := cloneDispositionObservation(o)
	foreign.AdapterSourceCommit = strings.Repeat("e", 40)
	if validateEnrolledFailedOriginalObservation(c, foreign, o.ObservationStartedAt, now, 30*time.Second) == nil {
		t.Fatal("foreign observer Source acquired production authority")
	}
	for _, name := range []string{"valid_distinct_event_and_request", "raw_userdata", "canonical_userdata", "projected_userdata", "duplicate_private_request_parameters", "duplicate_outer_response", "event_record_alias", "request_alias", "foreign_page_event", "duplicate_request", "state_missing"} {
		t.Run("outer/"+name, func(t *testing.T) {
			x := cloneDispositionObservation(o)
			eventID, requestID := x.NativeReads[2].ResourceID, c.Request.OriginalCreateActionID
			if eventID == requestID {
				t.Fatal("fixture must distinguish CloudTrail EventID and AWS RequestID")
			}
			if name == "request_alias" {
				requestID = eventID
			}
			body := enrolledFailedProjectedEvent(eventID, requestID, name == "raw_userdata" || name == "canonical_userdata" || name == "projected_userdata")
			if name == "duplicate_private_request_parameters" || name == "duplicate_outer_response" {
				body = enrolledFailedDuplicateProjection(eventID, requestID, name == "duplicate_outer_response")
			}
			var projection map[string]any
			_ = json.Unmarshal(body, &projection)
			page := projection["response"].(map[string]any)
			rows := page["Events"].([]any)
			switch name {
			case "raw_userdata", "canonical_userdata":
				body, _ = json.Marshal(page)
				x.NativeReads[2].ResponseRepresentation = "raw_http_body_v1"
				if name == "canonical_userdata" {
					x.NativeReads[2].ResponseRepresentation = "canonical_provider_SDK_result_v1"
				}
			case "event_record_alias":
				x.NativeReads[2].ResourceID = requestID
			case "foreign_page_event":
				rows[0].(map[string]any)["EventId"] = uuid.NewString()
				body, _ = json.Marshal(projection)
			case "duplicate_request":
				page["Events"] = append(rows, rows[0])
				body, _ = json.Marshal(projection)
			case "state_missing":
				x.ResourceState = ""
			}
			enrolledFailedRecloseNativeBody(&x.NativeReads[2], body)
			err := validateEnrolledFailedOriginalObservationForSource(c, x, o.ObservationStartedAt, now, 30*time.Second, o.AdapterSourceCommit)
			if (err == nil) != (name == "valid_distinct_event_and_request") {
				t.Fatal("outer AWS privacy and original identity boundary", name, err)
			}
		})
	}
}

func enrolledFailedRecloseNativeBody(read *model.CapacityOriginalCreateDispositionNativeRead, body []byte) {
	read.ResponseBodyBase64 = base64.StdEncoding.EncodeToString(body)
	read.ResponseBytes = int64(len(body))
	read.ResponseSHA256 = originalDispositionDigest(body)
}

func enrolledFailedProjectedEvent(eventID, requestID string, userData bool) []byte {
	params := map[string]any{}
	if userData {
		params["userData"] = "DECLARED_PRIVATE_USERDATA"
	}
	event, _ := json.Marshal(map[string]any{"eventID": eventID, "requestID": requestID, "requestParameters": params})
	projection := map[string]any{"schema": "cloudtrail_lookup_events_userdata_omitted_projection_v1", "original_http_body_retained": false, "original_http_body_hashed": false, "original_eof_and_close": true, "user_data_fields_removed": 1, "response": map[string]any{"Events": []map[string]any{{"EventId": eventID, "CloudTrailEvent": string(event)}}}}
	raw, _ := json.Marshal(projection)
	return raw
}

// Keep the malicious original JSON bytes intact: unmarshalling/remarshalling
// the whole event would erase the duplicate and hide this privacy regression.
func enrolledFailedDuplicateProjection(eventID, requestID string, outer bool) []byte {
	clean := enrolledFailedProjectedEvent(eventID, requestID, false)
	if outer {
		var private map[string]any
		_ = json.Unmarshal(enrolledFailedProjectedEvent(eventID, requestID, true), &private)
		page, _ := json.Marshal(private["response"])
		return []byte(`{"response":` + string(page) + `,` + string(clean[1:]))
	}
	event, _ := json.Marshal(eventID)
	request, _ := json.Marshal(requestID)
	duplicated := `{"eventID":` + string(event) + `,"requestID":` + string(request) + `,"requestParameters":{"userData":"DECLARED_PRIVATE_USERDATA"},"requestParameters":{}}`
	var projected map[string]any
	_ = json.Unmarshal(clean, &projected)
	projected["response"].(map[string]any)["Events"].([]any)[0].(map[string]any)["CloudTrailEvent"] = duplicated
	body, _ := json.Marshal(projected)
	return body
}

func enrolledFailedAWSObservationFixture(t *testing.T) (model.CapacityOriginalCreateDispositionCandidate, model.CapacityOriginalCreateDispositionObservation, time.Time) {
	t.Helper()
	c, o, now := originalDispositionAWSAdjunctFixture(t)
	c.Request.OriginalAdapterSourceCommit = enrolledFailedAWSCreator
	o.OriginalAdapterSourceCommit = enrolledFailedAWSCreator
	o.AdapterSourceCommit = enrolledFailedAWSObserverSource
	o.InventoryBasis = "aws_original_enrolled_failed_create_owned_auxiliary_absence_v1"
	o.NativeReads[2].ResponseRepresentation = "cloudtrail_lookup_events_userdata_omitted_projection_v1"
	enrolledFailedRecloseNativeBody(&o.NativeReads[2], enrolledFailedProjectedEvent(o.NativeReads[2].ResourceID, c.Request.OriginalCreateActionID, false))
	return c, o, now
}
