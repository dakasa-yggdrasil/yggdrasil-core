package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func abandonedDispatchCASFixture() map[string]any {
	return map[string]any{
		"job_id": "54136edb-daef-4aae-b29b-87bf84996e1f", "expected_run_id": "447458d4-28ba-42b5-bb1f-fe0375fef62e",
		"expected_envelope_sha256": strings.Repeat("a", 64), "expected_fencing_token": int64(1),
		"expected_lease_owner": "0f7c2c55-1b39-4a1f-9a55-3b8a3e6f0d11", "expected_pending_wake_count": 32,
	}
}

func TestAbandonedDispatchDispositionClosedCASRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(abandonedDispatchCASFixture())
	request, err := decodeAbandonedDispatchDisposition(strings.NewReader(good))
	if err != nil || request.ExpectedFencingToken != 1 || request.ExpectedPendingWakeCount != 32 || request.Issuer != "" ||
		request.JobID.String() != "54136edb-daef-4aae-b29b-87bf84996e1f" {
		t.Fatal("valid CAS refused or issuer synthesized", request, err)
	}
	for key := range abandonedDispatchCASFixture() {
		for _, absent := range []bool{false, true} {
			value := abandonedDispatchCASFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, err := decodeAbandonedDispatchDisposition(strings.NewReader(encode(value))); err == nil {
				t.Fatal("missing/null accepted", key, absent)
			}
		}
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"returned_at", time.Now().UTC()}, {"historical_return", "succeeded"},
		{"lease_expires_at", time.Now().UTC()}, {"process_started_at", time.Now().UTC()}, {"provider_absent", true},
		{"job_id", strings.ToUpper(abandonedDispatchCASFixture()["job_id"].(string))}, {"expected_run_id", uuid.Nil.String()},
		{"expected_lease_owner", "not-a-uuid"}, {"expected_envelope_sha256", strings.Repeat("A", 64)},
		{"expected_envelope_sha256", strings.Repeat("a", 63)}, {"expected_fencing_token", 0}, {"expected_fencing_token", -1},
		{"expected_fencing_token", int64(9007199254740992)}, {"expected_fencing_token", 1.5}, {"expected_fencing_token", "1"},
		{"expected_pending_wake_count", 0}, {"expected_pending_wake_count", 33}, {"expected_pending_wake_count", "32"},
	} {
		value := abandonedDispatchCASFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeAbandonedDispatchDisposition(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"job_id":"54136edb-daef-4aae-b29b-87bf84996e1f"}`
	for _, raw := range []string{"", "{}", "null", "[]", good + good, good + strings.Repeat(" ", 4097), duplicate} {
		if _, err := decodeAbandonedDispatchDisposition(strings.NewReader(raw)); err == nil {
			t.Fatal("empty/duplicate/trailing/oversize accepted", raw)
		}
	}
}

func TestAbandonedDispatchDispositionRequiresAuthenticatedOperator(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server := &Server{}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/api/v1/ops/capacity/abandoned-dispatch-dispositions", strings.NewReader("{}"))
		if method == http.MethodPost {
			server.handleOpsAbandonedDispatchDisposition(response, request)
		} else {
			server.handleOpsAbandonedDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated request reached repository", method, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/abandoned-dispatch-dispositions", actor)
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsAbandonedDispatchDisposition(response, request)
		} else {
			server.handleOpsAbandonedDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusForbidden {
			t.Fatal("manage_workflows alone reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/abandoned-dispatch-dispositions", actor)
		request.Body = http.NoBody
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsAbandonedDispatchDisposition(response, request)
		} else {
			request.SetPathValue("jobId", "invalid")
			server.handleOpsAbandonedDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatal("god-mode malformed request reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAbandonedDispatchDispositionSummaryKeepsHistoricalReturnUnknown(t *testing.T) {
	finished := time.Now().UTC()
	v := repository.CapacityDispatchAbandonedDisposition{ID: uuid.New(), JobID: uuid.New(), RunID: uuid.New(), State: "abandoned_disposed",
		HistoricalReturn: "unknown", RunStatus: "failed", RunError: repository.CapacityDispatchAbandonedRunError, WorkflowRunStatus: "failed",
		WorkflowRunFinishedAt: &finished, RecordedAt: finished, Reason: repository.CapacityDispatchAbandonedReason,
		EffectScan: repository.CapacityDispatchAbandonedEffectScan{Schema: repository.CapacityDispatchAbandonedScanSchema}}
	result := abandonedDispatchDispositionSummary(v)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if result["historical_return"] != "unknown" || result["returned_at"] != (*time.Time)(nil) || result["finalization_ack_at"] != (*time.Time)(nil) ||
		result["original_return_recorded"] != false || result["original_finalization_ack_present"] != false ||
		result["workflow_run_finished_at_is_original_return"] != false || result["replayed"] != false ||
		result["provider_read_performed"] != false || result["provider_quiescence_proved"] != false ||
		result["other_core_replicas_excluded"] != false || result["new_current_admission_required"] != true ||
		result["dispatch_state"] != "abandoned_disposed" {
		t.Fatal("summary invents a return, ACK, replay or provider proof", string(raw))
	}
	for _, forbidden := range []string{"envelope\"", "inputs", "metadata", "token\":\"", "bearer", "credential"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("summary exports private material", forbidden)
		}
	}
}
