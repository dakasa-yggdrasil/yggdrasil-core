package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func failedServingHTTPBody(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(model.CapacityFailedServingGuestDisposalRequest{PreregistrationID: uuid.NewString(), PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), Generation: 9, FencingToken: 23, IntentSHA256: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFailedServingDisposalClosedCASRequest(t *testing.T) {
	good := failedServingHTTPBody(t)
	got, err := decodeFailedServingGuestDisposalRequest(strings.NewReader(good))
	if err != nil || got.Generation != 9 || got.FencingToken != 23 {
		t.Fatal("six exact CAS fields refused", err)
	}
	for name, raw := range map[string]string{
		"empty": "{}", "null": "null", "array": "[]", "trailing": good + "{}", "truncated": strings.TrimSuffix(good, "}"),
		"duplicate":         strings.TrimSuffix(good, "}") + `,"generation":9}`,
		"escaped_duplicate": strings.TrimSuffix(good, "}") + `,"\u0067eneration":9}`,
		"decimal":           strings.Replace(good, `"generation":9`, `"generation":9.0`, 1),
		"exponent":          strings.Replace(good, `"generation":9`, `"generation":9e0`, 1),
		"overflow":          strings.Replace(good, `"generation":9`, `"generation":9223372036854775808`, 1),
		"zero":              strings.Replace(good, `"generation":9`, `"generation":0`, 1),
		"negative_fence":    strings.Replace(good, `"fencing_token":23`, `"fencing_token":-1`, 1),
		"missing":           strings.Replace(good, `"generation":9,`, "", 1),
		"noncanonical_uuid": strings.Replace(good, got.PolicyID, strings.ReplaceAll(got.PolicyID, "-", ""), 1),
		"nil_uuid":          strings.Replace(good, got.PolicyID, uuid.Nil.String(), 1),
		"wrong_hash":        strings.Replace(good, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"null_field":        strings.Replace(good, `"generation":9`, `"generation":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFailedServingGuestDisposalRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed CAS accepted")
			}
		})
	}
	for _, key := range []string{"issuer", "actual_core_source", "candidate", "owner", "original_intent_wire", "historical_unknowns", "native_off", "native_off_observed", "native_absence", "inventory", "operator_native_action_ACK_claimed", "business_effects_preserved", "cause_fixed", "zero_useful", "challenge", "nonce", "deadline"} {
		t.Run("caller_authority_"+key, func(t *testing.T) {
			raw := strings.TrimSuffix(good, "}") + `,"` + key + `":true}`
			if _, err := decodeFailedServingGuestDisposalRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("caller evidence/authority accepted")
			}
		})
	}
	ids := `{"preregistration_id":"` + got.PreregistrationID + `","admission_id":"` + uuid.NewString() + `"}`
	if _, _, err = decodeFailedInstalledGuestIDs(strings.NewReader(ids), "admission_id"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{ids + ids, strings.TrimSuffix(ids, "}") + `,"native_off":true}`, strings.TrimSuffix(ids, "}") + `,"admission_id":"` + uuid.NewString() + `"}`, strings.TrimSuffix(ids, "}") + `,"nonce":"caller"}`} {
		if _, _, err = decodeFailedInstalledGuestIDs(strings.NewReader(raw), "admission_id"); err == nil {
			t.Fatal("OFF/complete caller proof accepted")
		}
	}
}

func TestFailedServingDisposalRequiresOperatorBeforeDatabaseOrBroker(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, route := range []struct {
		name, method string
		handle       func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"request", http.MethodPost, (*Server).handleOpsFailedServingGuestDisposal},
		{"off", http.MethodPost, (*Server).handleOpsFailedServingGuestNativeOff},
		{"complete", http.MethodPost, (*Server).handleOpsFailedServingGuestDisposalComplete},
		{"read", http.MethodGet, (*Server).handleOpsFailedServingGuestDisposalRead},
	} {
		t.Run(route.name, func(t *testing.T) {
			path := "/api/v1/ops/capacity/failed-serving-guest-disposals"
			w := httptest.NewRecorder()
			route.handle(&Server{}, w, httptest.NewRequest(route.method, path, strings.NewReader(`{}`)))
			if w.Code != http.StatusUnauthorized {
				t.Fatal("no-claims/warn-mode bypass", w.Code)
			}
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
			r := rbacTestRequestWithClaims(route.method, path, actor)
			r.Body = io.NopCloser(strings.NewReader(`{}`))
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("ordinary manager reached native/database path", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			// A real administrative identity still cannot send proof or malformed
			// CAS to any reader. No repository or broker expectation is provided.
			s, mock = rbacTestSetup(t)
			actor = uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
			r = rbacTestRequestWithClaims(route.method, path, actor)
			r.Body = io.NopCloser(strings.NewReader(`{"native_off":true}`))
			r.SetPathValue("preregistrationId", "not-a-uuid")
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatal("malformed operator request reached a side-effect path", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedServingDisposalSummaryClosedKeyAllowlist(t *testing.T) {
	const private = "PRIVATE_PAYLOAD_CERT_NONCE_REFERENCE_DO_NOT_EXPORT"
	r := repository.FailedServingGuestDisposal{ID: uuid.NewString(), RecordID: uuid.NewString(), PreregistrationID: uuid.NewString(), Schema: "failed_serving_guest_disposal_v1", ActualCoreSource: strings.Repeat("a", 40), OriginalIntentWire: []byte(`{"decision":{"reason":"` + private + `"}}`), HistoricalUnknowns: json.RawMessage(`[{"payload":"` + private + `"}]`), HistoricalCanaries: json.RawMessage(`[{"certificate":"` + private + `","nonce_ref":"` + private + `"}]`), BusinessEffectsPreserved: true, HistoricalAcceptedReadCount: 7, HistoricalPromotedCount: 1}
	r.Candidate.Request.ExpectedResourceID = private
	r.Candidate.OriginalPolicy.Spec = json.RawMessage(`{"private":"` + private + `"}`)
	r.Workflow.Spec = json.RawMessage(`{"private":"` + private + `"}`)
	r.Inventory = &model.CapacityVMFleetInventory{ProfileName: private}
	r.NativeOff = &model.CapacityVMFleetPlan{RequestSHA256: private}
	r.Absence = &model.CapacityOriginalCreateDispositionObservation{ResourceID: private}
	want := []string{"schema", "id", "record_id", "stage", "preregistration_id", "actual_core_source", "original_intent_sha256", "quarantine_intent_sha256", "terminal_intent_sha256", "installation_sha256", "enrollment_sha256", "original_slot_sha256", "quarantine_slot_sha256", "current_stable_event_sha256", "native_off_record_id", "historical_accepted_read_count", "historical_promoted_count", "business_effects_preserved", "Core_or_Guest_native_write_sent", "Guest_writer_drain_claimed", "native_off_observed", "native_absence_observed", "operator_native_action_ACK_claimed", "original_failure_cause_fixed_claimed", "historical_zero_useful_capacity_claimed", "replacement_requires_new_original_enrollment"}
	sort.Strings(want)
	for _, stage := range []string{"quarantined", "quiescent", "terminal"} {
		t.Run(stage, func(t *testing.T) {
			r.Stage = stage
			summary := failedServingGuestDisposalSummary(r)
			keys := make([]string, 0, len(summary))
			for key := range summary {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if !reflect.DeepEqual(keys, want) {
				t.Fatal("public API key set changed", keys)
			}
			wire, err := json.Marshal(summary)
			if err != nil || strings.Contains(string(wire), private) || strings.Contains(string(wire), "original_intent_wire") || strings.Contains(string(wire), "candidate") || strings.Contains(string(wire), "historical_unknowns") || strings.Contains(string(wire), "historical_canaries") {
				t.Fatal("private raw source escaped summary", err)
			}
			for _, key := range []string{"Core_or_Guest_native_write_sent", "Guest_writer_drain_claimed", "operator_native_action_ACK_claimed", "original_failure_cause_fixed_claimed", "historical_zero_useful_capacity_claimed"} {
				if summary[key] != false {
					t.Fatal("summary manufactured an authority or historical finality", key)
				}
			}
			if summary["native_off_observed"] != (stage == "quiescent" || stage == "terminal") || summary["native_absence_observed"] != (stage == "terminal") || summary["business_effects_preserved"] != true || summary["replacement_requires_new_original_enrollment"] != true {
				t.Fatal("summary erased past use or invented new enrollment/usefulness")
			}
		})
	}
}
