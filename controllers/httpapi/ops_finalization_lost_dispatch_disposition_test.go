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

func finalizationLostDispatchCASFixture() map[string]any {
	return map[string]any{
		"job_id": "09a9fee8-4f52-4106-907d-c9b5ccc388bc", "expected_run_id": "bbb62859-0000-4000-8000-000000000001",
		"expected_envelope_sha256": strings.Repeat("a", 64), "expected_fencing_token": int64(1),
		"expected_lease_owner": "0f7c2c55-1b39-4a1f-9a55-3b8a3e6f0d11", "expected_pending_wake_count": 32,
		"finalization_evidence": "2026-11-02 08:04:17.377 UTC [177447] ERROR:  canceling statement due to user request\nSTATEMENT:  UPDATE public.workflow_runs SET status=$2 ...",
	}
}

func TestFinalizationLostDispatchDispositionClosedCASRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(finalizationLostDispatchCASFixture())
	request, err := decodeFinalizationLostDispatchDisposition(strings.NewReader(good))
	if err != nil || request.ExpectedFencingToken != 1 || request.ExpectedPendingWakeCount != 32 || request.Issuer != "" ||
		request.JobID.String() != "09a9fee8-4f52-4106-907d-c9b5ccc388bc" || request.Evidence != finalizationLostDispatchCASFixture()["finalization_evidence"] {
		t.Fatal("valid CAS refused, evidence changed or issuer synthesized", request, err)
	}
	for key := range finalizationLostDispatchCASFixture() {
		for _, absent := range []bool{false, true} {
			value := finalizationLostDispatchCASFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, err := decodeFinalizationLostDispatchDisposition(strings.NewReader(encode(value))); err == nil {
				t.Fatal("missing/null accepted", key, absent)
			}
		}
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"returned_at", time.Now().UTC()}, {"return_status", "failed"},
		{"historical_return", "failed"}, {"lease_expires_at", time.Now().UTC()}, {"process_started_at", time.Now().UTC()},
		{"effect_scan", map[string]any{}}, {"evidence_sha256", strings.Repeat("a", 64)},
		{"job_id", strings.ToUpper(finalizationLostDispatchCASFixture()["job_id"].(string))}, {"expected_run_id", uuid.Nil.String()},
		{"expected_lease_owner", "not-a-uuid"}, {"expected_envelope_sha256", strings.Repeat("A", 64)},
		{"expected_fencing_token", 0}, {"expected_fencing_token", "1"}, {"expected_pending_wake_count", 33},
		{"finalization_evidence", ""}, {"finalization_evidence", "   "}, {"finalization_evidence", strings.Repeat("x", 8193)},
		{"finalization_evidence", "log\u0000line"}, {"finalization_evidence", "bell\u0007"}, {"finalization_evidence", 42},
		{"finalization_evidence", []string{"line"}},
	} {
		value := finalizationLostDispatchCASFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeFinalizationLostDispatchDisposition(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	maximum := finalizationLostDispatchCASFixture()
	maximum["finalization_evidence"] = strings.Repeat("x", repository.CapacityDispatchFinalizationLostEvidenceMax)
	if _, err := decodeFinalizationLostDispatchDisposition(strings.NewReader(encode(maximum))); err != nil {
		t.Fatal("8 KiB evidence refused", err)
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"job_id":"09a9fee8-4f52-4106-907d-c9b5ccc388bc"}`
	for _, raw := range []string{"", "{}", "null", "[]", good + good, good + strings.Repeat(" ", finalizationLostDispatchBodyLimit), duplicate} {
		if _, err := decodeFinalizationLostDispatchDisposition(strings.NewReader(raw)); err == nil {
			t.Fatal("empty/duplicate/trailing/oversize accepted", len(raw))
		}
	}
}

func TestFinalizationLostDispatchDispositionRequiresAuthenticatedOperator(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	path := "/api/v1/ops/capacity/finalization-lost-dispatch-dispositions"
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server := &Server{}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if method == http.MethodPost {
			server.handleOpsFinalizationLostDispatchDisposition(response, request)
		} else {
			server.handleOpsFinalizationLostDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated request reached repository", method, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		request := rbacTestRequestWithClaims(method, path, actor)
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsFinalizationLostDispatchDisposition(response, request)
		} else {
			server.handleOpsFinalizationLostDispatchDispositionRead(response, request)
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
		request := rbacTestRequestWithClaims(method, path, actor)
		request.Body = http.NoBody
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsFinalizationLostDispatchDisposition(response, request)
		} else {
			request.SetPathValue("jobId", "invalid")
			server.handleOpsFinalizationLostDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatal("god-mode malformed request reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFinalizationLostDispatchDispositionSummaryKeepsHistoricalReturnUnknown(t *testing.T) {
	finished := time.Now().UTC()
	v := repository.CapacityDispatchFinalizationLostDisposition{ID: uuid.New(), JobID: uuid.New(), RunID: uuid.New(), State: "finalization_lost_disposed",
		HistoricalReturn: "unknown", ReturnObservation: repository.CapacityDispatchFinalizationLostObservation, RunStatus: "failed",
		RunError: repository.CapacityDispatchFinalizationLostRunError, WorkflowRunStatus: "failed", WorkflowRunFinishedAt: &finished,
		RecordedAt: finished, Reason: repository.CapacityDispatchFinalizationLostReason, EvidenceSHA256: strings.Repeat("b", 64), EvidenceBytes: 312}
	v.EffectScan.Schema = repository.CapacityDispatchFinalizationLostScanSchema
	result := finalizationLostDispatchDispositionSummary(v)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if result["historical_return"] != "unknown" || result["returned_at"] != (*time.Time)(nil) || result["finalization_ack_at"] != (*time.Time)(nil) ||
		result["original_return_recorded"] != false || result["original_finalization_ack_present"] != false ||
		result["workflow_run_finished_at_is_original_return"] != false || result["replayed"] != false ||
		result["provider_read_performed"] != false || result["provider_quiescence_proved"] != false ||
		result["operator_evidence_is_authority"] != false || result["other_core_replicas_excluded"] != false ||
		result["new_current_admission_required"] != true || result["dispatch_state"] != "finalization_lost_disposed" ||
		result["workflow_run_error"] != repository.CapacityDispatchFinalizationLostRunError {
		t.Fatal("summary invents a return, ACK, replay or provider proof", string(raw))
	}
	for _, forbidden := range []string{"envelope\"", "inputs", "metadata", "token\":\"", "bearer", "credential", "operator_evidence\"", "canceling statement"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("summary exports private material or the evidence body", forbidden)
		}
	}
}
