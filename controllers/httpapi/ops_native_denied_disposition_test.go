package httpapi

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeDeniedDispositionClosedOriginalIdentities(t *testing.T) {
	raw := `{"grant_id":"4497d06c-0b15-4ad1-9800-e15ce5528e51","job_id":"04742a97-f45a-46a7-9745-1123fe17f0f4"}`
	if _, _, e := decodeFailedOriginalDisposition(strings.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{strings.TrimSuffix(raw, "}") + `,"proof":true}`, strings.TrimSuffix(raw, "}") + `,"event_id":"caller-selected"}`, strings.TrimSuffix(raw, "}") + `,"grant_id":"4497d06c-0b15-4ad1-9800-e15ce5528e51"}`, `null`, raw + `{}`} {
		if _, _, e := decodeFailedOriginalDisposition(strings.NewReader(v)); e == nil {
			t.Fatal("caller proof/event/duplicate accepted")
		}
	}
}
func TestNativeDeniedDispositionRequiresOperatorBeforeDatabaseOrBroker(t *testing.T) {
	s := &Server{}
	for _, read := range []bool{false, true} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ops/capacity/native-denied-dispositions", strings.NewReader(`{}`))
		if read {
			s.handleOpsNativeDeniedDispositionRead(w, r)
		} else {
			s.handleOpsNativeDeniedDisposition(w, r)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatal(w.Code)
		}
	}
}
func TestNativeDeniedSummaryPreservesUncertaintyAndOmitsEvidenceBodies(t *testing.T) {
	v := model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedDispositionSchema, OriginalUncertainAndNullIdentitiesUnchanged: true, OriginalUnknownACKPreserved: true, WitnessEnrollmentInstallationAbsent: true, Observation: model.CapacityNativeDeniedObservation{Decision: "authorization_denied", NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{{ResponseBodyBase64: "MUST_NOT_EXPORT_NATIVE_BODY"}}}}
	s := nativeDeniedDispositionSummary(v)
	raw, e := json.Marshal(s)
	if e != nil || strings.Contains(string(raw), "MUST_NOT_EXPORT") || strings.Contains(string(raw), "response_body_base64") {
		t.Fatal("private native projection leaked", e)
	}
	if s["dispatch_state"] != "native_denied_disposed" || s["original_finalization_ack_present"] != false || s["original_HTTP_response_available"] != false || s["new_assessment_decision_and_single_use_grant_still_required"] != true || s["provider_mutations"] != 0 {
		t.Fatal("denied terminal relabelled original success")
	}
}
