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

func TestGuestRetirementForwardClosedHistoricalCAS(t *testing.T) {
	r := model.CapacityGuestRetirementForwardRequest{PreregistrationID: uuid.NewString(), RetirementRequestID: uuid.NewString(), PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), Generation: 14, FencingToken: 28, IntentSHA256: strings.Repeat("b", 64)}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	good := string(wire)
	got, err := decodeGuestRetirementForwardRequest(strings.NewReader(good))
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("exact historical frame refused", err)
	}
	for name, raw := range map[string]string{
		"null": "null", "array": "[]", "empty": "{}", "trailing": good + "{}", "truncated": strings.TrimSuffix(good, "}"),
		"duplicate":         strings.TrimSuffix(good, "}") + `,"generation":14}`,
		"escaped_duplicate": strings.TrimSuffix(good, "}") + `,"\u0067eneration":14}`,
		"missing":           strings.Replace(good, `"generation":14,`, "", 1),
		"null_field":        strings.Replace(good, `"generation":14`, `"generation":null`, 1),
		"decimal":           strings.Replace(good, `"generation":14`, `"generation":14.0`, 1),
		"overflow":          strings.Replace(good, `"fencing_token":28`, `"fencing_token":9223372036854775808`, 1),
		"negative":          strings.Replace(good, `"fencing_token":28`, `"fencing_token":-1`, 1),
		"zero":              strings.Replace(good, `"generation":14`, `"generation":0`, 1),
		"noncanonical_uuid": strings.Replace(good, r.PreregistrationID, strings.ReplaceAll(r.PreregistrationID, "-", ""), 1),
		"nil_uuid":          strings.Replace(good, r.RetirementRequestID, uuid.Nil.String(), 1),
		"uppercase_hash":    strings.Replace(good, r.PolicyChecksum, strings.ToUpper(r.PolicyChecksum), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeGuestRetirementForwardRequest(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed current-frame CAS accepted")
			}
		})
	}
	for _, key := range []string{"issuer", "barrier", "process_started_at", "actual_core_source", "native_off", "caller_status", "observation", "retirement_forward", "root_admission_id", "parent_admission_id", "prefix_sha256", "journal", "poweroff_command_returned", "deadline", "destroy_grant_id"} {
		t.Run("caller_authority_"+key, func(t *testing.T) {
			if _, err := decodeGuestRetirementForwardRequest(strings.NewReader(strings.TrimSuffix(good, "}") + `,"` + key + `":true}`)); err == nil {
				t.Fatal("caller proof or authority accepted")
			}
		})
	}
}

func TestGuestRetirementForwardRequiresCurrentAdministrativeHuman(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, route := range []struct {
		name, method string
		handle       func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"request", http.MethodPost, (*Server).handleOpsGuestRetirementForward},
		{"stored_read", http.MethodGet, (*Server).handleOpsGuestRetirementForwardRead},
	} {
		t.Run(route.name, func(t *testing.T) {
			path := "/api/v1/ops/capacity/guest-retirement-poweroff-forwards"
			w := httptest.NewRecorder()
			route.handle(&Server{}, w, httptest.NewRequest(route.method, path, strings.NewReader(`{}`)))
			if w.Code != http.StatusUnauthorized {
				t.Fatal("warn-mode machine bypass", w.Code)
			}
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
			r := rbacTestRequestWithClaims(route.method, path, actor)
			r.Body = io.NopCloser(strings.NewReader(`{}`))
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("non-administrative manager reached repository", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			s, mock = rbacTestSetup(t)
			actor = uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
			r = rbacTestRequestWithClaims(route.method, path, actor)
			r.Body = io.NopCloser(strings.NewReader(`{"native_off":true}`))
			r.SetPathValue("preregistrationId", "not-a-uuid")
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatal("caller proof reached database", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGuestRetirementForwardSummaryPreservesFailureAndHidesOriginals(t *testing.T) {
	const private = "PRIVATE_ORIGINAL_CALLER_BODY_NONCE_CREDENTIAL_REFERENCE"
	r := repository.GuestRetirementForward{ID: uuid.NewString(), RootAdmissionID: uuid.NewString(), ParentAdmissionID: uuid.NewString(), ParentAdmissionSHA256: strings.Repeat("a", 64), PreregistrationID: uuid.NewString(), RetirementRequestID: uuid.NewString(), Mode: "historical", Namespace: private, Issuer: private, ActualCoreSource: private, OriginalIntentWire: []byte(private), FailedRun: []byte(private)}
	r.Original.Preregistration.OriginalCreateGrantID = private
	want := []string{"schema", "id", "root_admission_id", "parent_admission_id", "parent_admission_sha256", "stage", "mode", "preregistration_id", "retirement_request_id", "admission_sha256", "prefix_sha256", "original_caller_sha256", "native_off_sha256", "destroy_grant_id", "native_absence_sha256", "recorded_at", "original_failure_preserved", "normal_guest_success_claimed", "guest_command_replayed", "native_off_observed", "native_absence_observed"}
	sort.Strings(want)
	for _, stage := range []string{"requested", "admitted", "off_qualified", "terminal"} {
		t.Run(stage, func(t *testing.T) {
			r.Stage = stage
			r.NativeOffSHA256, r.NativeAbsenceSHA256 = "", ""
			if stage == "off_qualified" || stage == "terminal" {
				r.NativeOffSHA256 = strings.Repeat("b", 64)
			}
			if stage == "terminal" {
				r.NativeAbsenceSHA256 = strings.Repeat("c", 64)
			}
			summary := guestRetirementForwardSummary(r)
			keys := []string{}
			for k := range summary {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if !reflect.DeepEqual(keys, want) {
				t.Fatal("public allowlist changed", keys)
			}
			wire, err := json.Marshal(summary)
			if err != nil || strings.Contains(string(wire), private) {
				t.Fatal("private original escaped", err)
			}
			if summary["original_failure_preserved"] != true || summary["normal_guest_success_claimed"] != false || summary["guest_command_replayed"] != false || summary["native_off_observed"] != (r.NativeOffSHA256 != "") || summary["native_absence_observed"] != (r.NativeAbsenceSHA256 != "") {
				t.Fatal("summary manufactured Guest success or physical state")
			}
		})
	}
}
