package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestFailedOriginalDispositionClosedIdentityRequest(t *testing.T) {
	grant := "a12b1afc-1b7e-48b2-91dd-accfcc4713e6"
	job := "04742a97-f45a-46a7-9745-1123fe17f0f4"
	good := `{"grant_id":"` + grant + `","job_id":"` + job + `"}`
	g, j, err := decodeFailedOriginalDisposition(strings.NewReader(good))
	if err != nil || g != grant || j != job {
		t.Fatal("two original identities refused", err)
	}
	for _, raw := range []string{
		`{}`, `null`, `{"grant_id":"` + grant + `"}`,
		good + `{}`, strings.Replace(good, "job_id", "native_absent", 1),
		strings.TrimSuffix(good, "}") + `,"grant_id":"` + grant + `"}`,
		strings.TrimSuffix(good, "}") + `,"complete":true}`,
		strings.Replace(good, grant, strings.ToUpper(grant), 1),
		strings.Replace(good, `"`+job+`"`, `null`, 1),
		strings.Repeat(" ", 4097) + good,
	} {
		if _, _, e := decodeFailedOriginalDisposition(strings.NewReader(raw)); e == nil {
			t.Fatalf("untrusted request accepted: %q", raw)
		}
	}
}

func TestFailedOriginalDispositionRequiresAuthenticatedOperator(t *testing.T) {
	s := &Server{}
	for _, read := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ops/capacity/failed-original-dispositions", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		if read {
			s.handleOpsFailedOriginalDispositionRead(w, r)
		} else {
			s.handleOpsFailedOriginalDisposition(w, r)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated administrative boundary", w.Code)
		}
	}
}

func TestFailedOriginalDispositionSummaryKeepsUnknownAndPrivateEvidence(t *testing.T) {
	v := model.CapacityFailedOriginalDisposition{Schema: model.FailedOriginalDispositionSchema, OriginalAcceptedUnchanged: true, OriginalWitnessPreserved: true, OriginalUnknownACKPreserved: true, HistoricalWriterStartState: "unknown", Observation: model.CapacityOriginalCreateDispositionObservation{NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{{ResponseBodyBase64: "PRIVATE_NATIVE_BODY_MUST_NOT_EXPORT"}}}}
	summary := failedOriginalDispositionSummary(v)
	raw, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(raw), "PRIVATE_NATIVE_BODY") || strings.Contains(string(raw), "response_body_base64") {
		t.Fatal("native private evidence leaked", err)
	}
	if summary["dispatch_state"] != "failed_disposed" || summary["original_finalization_ack_present"] != false || summary["historical_writer_start_state"] != "unknown" || summary["provider_mutations"] != 0 || summary["serving_or_business_or_savings_authority"] != false {
		t.Fatal("failed terminal relabelled as original success")
	}
}
