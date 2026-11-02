package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Production identities of the refused V2 retirement (ADR-0092).
func v2RefusedNativeOffRequestFixture() map[string]any {
	return map[string]any{
		"preregistration_id":    "b8076d1e-2e34-4acc-8ce1-14ef4a6adc8a",
		"admission_id":          "8ef5f76c-aeec-4acb-9469-1eb3cce46f93",
		"retirement_request_id": "fc853776-491b-4959-87ed-61afca39f8e2",
	}
}

func TestFailedInstalledV2RefusedNativeOffClosedRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	fixture := v2RefusedNativeOffRequestFixture()
	good := encode(fixture)
	pre, admission, retirement, err := decodeFailedInstalledV2RefusedNativeOff(strings.NewReader(good))
	if err != nil || pre != fixture["preregistration_id"] || admission != fixture["admission_id"] || retirement != fixture["retirement_request_id"] {
		t.Fatal("exact production identities refused or changed", pre, admission, retirement, err)
	}
	for key := range v2RefusedNativeOffRequestFixture() {
		for _, absent := range []bool{false, true} {
			value := v2RefusedNativeOffRequestFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, _, _, err := decodeFailedInstalledV2RefusedNativeOff(strings.NewReader(encode(value))); err == nil {
				t.Fatal("missing/null accepted", key, absent)
			}
		}
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"native_poweroff_sha256", strings.Repeat("a", 64)},
		{"server_status", "off"}, {"force", true}, {"expected_previous_read_id", uuid.NewString()},
		{"claim_run_id", "0b482d82-99ca-4137-91f3-7ef27b9170ad"}, {"fence", 21}, {"lease_owner", "00e34a1a-5b50-4d61-bf9e-736503d20702"},
		{"caller_status", 409}, {"retirement_mode", "legacy_guest548_original_v1"},
		{"preregistration_id", strings.ToUpper(v2RefusedNativeOffRequestFixture()["preregistration_id"].(string))},
		{"admission_id", uuid.Nil.String()}, {"retirement_request_id", "not-a-uuid"}, {"retirement_request_id", 42},
		{"admission_id", v2RefusedNativeOffRequestFixture()["preregistration_id"]},
		{"retirement_request_id", v2RefusedNativeOffRequestFixture()["admission_id"]},
	} {
		value := v2RefusedNativeOffRequestFixture()
		value[mutation.key] = mutation.value
		if _, _, _, err := decodeFailedInstalledV2RefusedNativeOff(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"admission_id":"8ef5f76c-aeec-4acb-9469-1eb3cce46f93"}`
	for _, raw := range []string{"", "{}", "null", "[]", good + good, good + " {}", duplicate} {
		if _, _, _, err := decodeFailedInstalledV2RefusedNativeOff(strings.NewReader(raw)); err == nil {
			t.Fatal("empty/duplicate/trailing accepted", raw)
		}
	}
}

func TestFailedInstalledV2RefusedNativeOffRequiresAuthenticatedOperator(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	path := "/api/v1/ops/capacity/failed-installed-guest-disposals/v2-refused-native-off"
	handle := func(server *Server, method string, w http.ResponseWriter, r *http.Request) {
		if method == http.MethodPost {
			server.handleOpsFailedInstalledV2RefusedNativeOff(w, r)
		} else {
			server.handleOpsFailedInstalledV2RefusedNativeOffRead(w, r)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		response := httptest.NewRecorder()
		handle(&Server{}, method, response, httptest.NewRequest(method, path, strings.NewReader("{}")))
		if response.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated request reached repository or provider", method, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		response := httptest.NewRecorder()
		handle(server, method, response, rbacTestRequestWithClaims(method, path, actor))
		if response.Code != http.StatusForbidden {
			t.Fatal("manage_workflows alone reached repository or provider", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		request := rbacTestRequestWithClaims(method, path, actor)
		request.Body = http.NoBody
		if method == http.MethodGet {
			request.SetPathValue("preregistrationId", "invalid")
		}
		response := httptest.NewRecorder()
		handle(server, method, response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatal("god-mode malformed request reached repository or provider", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFailedInstalledV2RefusedNativeOffSummaryClaimsNoQuiescence(t *testing.T) {
	v := repository.FailedInstalledV2RefusedNativeOff{Schema: "failed_installed_v2_refused_native_off_quiescence_v1", ID: uuid.NewString(), Stage: "qualified", DisposalID: uuid.NewString(), PreregistrationID: uuid.NewString(), RetirementRequestID: uuid.NewString(), FailedRun: `{"private":"DO_NOT_EXPORT"}`, OriginalClaimSHA256: "DO_NOT_EXPORT", Issuer: "collaborator:DO_NOT_EXPORT", NativeOffSHA256: strings.Repeat("a", 64)}
	v.Evidence.CallerStatus = 409
	v.Evidence.CallerSHA256 = "DO_NOT_EXPORT"
	v.OriginalClaimedIntent.LeaseOwner = "DO_NOT_EXPORT"
	result := failedInstalledV2RefusedNativeOffSummary(v)
	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), "DO_NOT_EXPORT") {
		t.Fatal("summary leaked private lineage", err)
	}
	if result["Guest_writer_quiescence_claimed"] != false || result["original_poweroff_command_returned_or_caller200_claimed"] != false || result["new_Guest_request_or_poweroff_or_delete_sent"] != false || result["business_effects_preserved"] != true || result["quiescent_qualified"] != true || result["original_caller_status"] != 409 {
		t.Fatal("summary overstates the lane", string(raw))
	}
	v.Stage = "admitted"
	if failedInstalledV2RefusedNativeOffSummary(v)["quiescent_qualified"] != false {
		t.Fatal("admission reported as quiescent")
	}
}
