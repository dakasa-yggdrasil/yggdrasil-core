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

func unknownMaintenanceDispatchCASFixture() map[string]any {
	return map[string]any{
		"job_id": "54136edb-daef-4aae-b29b-87bf84996e1f", "expected_run_id": "447458d4-28ba-42b5-bb1f-fe0375fef62e",
		"expected_envelope_sha256": strings.Repeat("a", 64), "expected_fencing_token": int64(1),
		"expected_lease_owner": "0f7c2c55-1b39-4a1f-9a55-3b8a3e6f0d11", "expected_pending_wake_count": 32,
		"expected_returned_at": "2026-11-02T13:26:06.898975Z", "expected_run_sha256": strings.Repeat("b", 64), "expected_members_sha256": strings.Repeat("c", 64),
	}
}

func TestUnknownMaintenanceDispatchDispositionClosedCASRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(unknownMaintenanceDispatchCASFixture())
	request, err := decodeUnknownMaintenanceDispatchDisposition(strings.NewReader(good))
	if err != nil || request.ExpectedFencingToken != 1 || request.ExpectedPendingWakeCount != 32 || request.Issuer != "" ||
		request.JobID.String() != "54136edb-daef-4aae-b29b-87bf84996e1f" {
		t.Fatal("valid CAS refused or issuer synthesized", request, err)
	}
	for key := range unknownMaintenanceDispatchCASFixture() {
		for _, absent := range []bool{false, true} {
			value := unknownMaintenanceDispatchCASFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, err := decodeUnknownMaintenanceDispatchDisposition(strings.NewReader(encode(value))); err == nil {
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
		{"job_id", strings.ToUpper(unknownMaintenanceDispatchCASFixture()["job_id"].(string))}, {"expected_run_id", uuid.Nil.String()},
		{"expected_lease_owner", "not-a-uuid"}, {"expected_envelope_sha256", strings.Repeat("A", 64)},
		{"expected_envelope_sha256", strings.Repeat("a", 63)}, {"expected_fencing_token", 0}, {"expected_fencing_token", -1},
		{"expected_fencing_token", int64(9007199254740992)}, {"expected_fencing_token", 1.5}, {"expected_fencing_token", "1"},
		{"expected_returned_at", "invalid"}, {"expected_returned_at", "0001-01-01T00:00:00Z"}, {"expected_run_sha256", strings.Repeat("B", 64)}, {"expected_members_sha256", strings.Repeat("c", 63)},
		{"expected_pending_wake_count", 0}, {"expected_pending_wake_count", 33}, {"expected_pending_wake_count", "32"},
	} {
		value := unknownMaintenanceDispatchCASFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeUnknownMaintenanceDispatchDisposition(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"job_id":"54136edb-daef-4aae-b29b-87bf84996e1f"}`
	for _, raw := range []string{"", "{}", "null", "[]", good + good, good + strings.Repeat(" ", unknownMaintenanceDispatchBodyLimit+1), duplicate} {
		if _, err := decodeUnknownMaintenanceDispatchDisposition(strings.NewReader(raw)); err == nil {
			t.Fatal("empty/duplicate/trailing/oversize accepted", raw)
		}
	}
}

func TestUnknownMaintenanceDispatchDispositionRequiresAuthenticatedOperator(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server := &Server{}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/api/v1/ops/capacity/unknown-maintenance-dispatch-dispositions", strings.NewReader("{}"))
		if method == http.MethodPost {
			server.handleOpsUnknownMaintenanceDispatchDisposition(response, request)
		} else {
			server.handleOpsUnknownMaintenanceDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated request reached repository", method, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/unknown-maintenance-dispatch-dispositions", actor)
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsUnknownMaintenanceDispatchDisposition(response, request)
		} else {
			server.handleOpsUnknownMaintenanceDispatchDispositionRead(response, request)
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
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/unknown-maintenance-dispatch-dispositions", actor)
		request.Body = http.NoBody
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsUnknownMaintenanceDispatchDisposition(response, request)
		} else {
			request.SetPathValue("jobId", "invalid")
			server.handleOpsUnknownMaintenanceDispatchDispositionRead(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatal("god-mode malformed request reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnknownMaintenanceDispatchDispositionSummaryPreservesOriginal(t *testing.T) {
	at := time.Now().UTC()
	value := repository.CapacityDispatchUnknownMaintenanceDisposition{ID: uuid.New(), JobID: uuid.New(), RunID: uuid.New(), OriginalReturnedAt: at, OriginalRunSHA256: strings.Repeat("a", 64), HistoricalReturn: "unknown", State: "unknown_maintenance_disposed", EffectScan: repository.CapacityDispatchUnknownMaintenanceEffectScan{CurrentMemberCount: 1, CurrentMembers: json.RawMessage(`[{"private-sentinel":"never-export"}]`)}}
	out := unknownMaintenanceDispatchDispositionSummary(value)
	if out["original_return_recorded"] != true || out["original_finalization_ack_present"] != false || out["finalization_ack_at"] != nil || out["workflow_run_preserved"] != true || out["historical_return"] != "unknown" || out["provider_read_performed"] != false || out["provider_quiescence_proved"] != false || out["replayed"] != false || out["original_returned_at"] != at {
		t.Fatal("summary invented or rewrote history", out)
	}
	raw, err := json.Marshal(out)
	if err != nil || strings.Contains(string(raw), "never-export") {
		t.Fatal("summary exports original membership body", err)
	}
}
