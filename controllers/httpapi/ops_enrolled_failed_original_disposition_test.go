package httpapi

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnrolledFailedDispositionRequiresAuthenticatedOperator(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		s := &Server{}
		r := httptest.NewRequest(method, "/api/v1/ops/capacity/enrolled-failed-original-dispositions", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		if method == http.MethodGet {
			s.handleOpsEnrolledFailedOriginalDispositionRead(w, r)
		} else {
			s.handleOpsEnrolledFailedOriginalDisposition(w, r)
		}
		if w.Code == http.StatusOK || w.Code == http.StatusCreated {
			t.Fatal("unauthenticated terminal authority")
		}
	}
}
func TestEnrolledFailedDispositionSummaryDoesNotInventQuiescence(t *testing.T) {
	v := model.CapacityEnrolledFailedOriginalDisposition{Schema: model.EnrolledFailedOriginalDispositionSchema, OriginalAcceptedUnchanged: true, OriginalWitnessPreserved: true, OriginalEnrollmentPreserved: true, OriginalUnknownACKPreserved: true, HistoricalWriterStartState: "unknown", Observation: model.CapacityOriginalCreateDispositionObservation{NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{{ResponseBodyBase64: "PRIVATE_PROVIDER_BODY_MUST_NOT_EXPORT"}}}}
	result := enrolledFailedOriginalDispositionSummary(v)
	raw, e := json.Marshal(result)
	if e != nil || strings.Contains(string(raw), "PRIVATE_PROVIDER_BODY_MUST_NOT_EXPORT") || result["Guest_quiescence_proved"] != false || result["installation_or_serving_authority"] != false || result["dispatch_state"] != "enrolled_failed_disposed" || result["original_finalization_ack_present"] != false || result["original_enrollment_preserved"] != true {
		t.Fatal("summary promotes failure or exports native body", e)
	}
}
