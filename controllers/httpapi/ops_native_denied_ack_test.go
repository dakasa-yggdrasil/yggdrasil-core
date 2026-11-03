package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeDeniedReturnedACKSummaryPreservesFailedOriginal(t *testing.T) {
	ack := time.Date(2026, 10, 23, 22, 50, 14, 488281000, time.UTC)
	v := model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedReturnedACKDispositionSchema, OriginalDispatchState: "returned", OriginalFinalizationACKAt: &ack, OriginalFailedWorkflowACKPreserved: true, OriginalUncertainAndNullIdentitiesUnchanged: true, WitnessEnrollmentInstallationAbsent: true,
		Observation: model.CapacityNativeDeniedObservation{Decision: "authorization_denied", NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{{ResponseBodyBase64: "MUST_NOT_EXPORT_NATIVE_BODY"}}}}
	s := nativeDeniedDispositionSummary(v)
	raw, err := json.Marshal(s)
	if err != nil || strings.Contains(string(raw), "MUST_NOT_EXPORT") || strings.Contains(string(raw), "response_body_base64") {
		t.Fatal("native body exported", err)
	}
	if s["original_unknown_ACK_preserved"] != false || s["original_failed_workflow_ACK_preserved"] != true || s["original_dispatch_state"] != "returned" || s["original_finalization_ack_present"] != true || s["original_finalization_ack_at"] != &ack || s["original_HTTP_response_available"] != false || s["provider_mutations"] != 0 || s["serving_or_business_or_savings_authority"] != false {
		t.Fatal("known failed-workflow ACK became unknown or provider success")
	}
	v1 := nativeDeniedDispositionSummary(model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedDispositionSchema, OriginalUnknownACKPreserved: true})
	for _, k := range []string{"original_dispatch_state", "original_finalization_ack_at", "original_failed_workflow_ACK_preserved"} {
		if _, ok := v1[k]; ok {
			t.Fatal("V2 field leaked into V1", k)
		}
	}
}
