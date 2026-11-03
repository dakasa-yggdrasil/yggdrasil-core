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
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestHTTPMaintenanceDispatchDispositionClosedCASRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(unknownMaintenanceDispatchCASFixture())
	old, err := decodeUnknownMaintenanceDispatchDisposition(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeHTTPMaintenanceDispatchDisposition(strings.NewReader(good))
	if err != nil || !reflect.DeepEqual(got.CapacityDispatchUnknownMaintenanceDispositionRequest, old) || got.Issuer != "" {
		t.Fatal("nine CAS operands changed or authority synthesized", got, err)
	}
	for key := range unknownMaintenanceDispatchCASFixture() {
		for _, absent := range []bool{false, true} {
			value := unknownMaintenanceDispatchCASFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, err := decodeHTTPMaintenanceDispatchDisposition(strings.NewReader(encode(value))); err == nil {
				t.Fatal("missing/null CAS accepted", key, absent)
			}
		}
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"reason", repository.CapacityDispatchHTTPMaintenanceReason},
		{"historical_return", "succeeded"}, {"finalization_ack_at", "2026-11-02T13:26:06Z"},
		{"effect_scan", map[string]any{"quiet": true}}, {"current_members", []any{}}, {"provider_absent", true},
		{"original_dispatch_updated_at", "2026-11-02T13:26:06Z"}, {"executor_barrier", "caller-owned"},
		{"job_id", strings.ToUpper(unknownMaintenanceDispatchCASFixture()["job_id"].(string))},
		{"expected_run_id", uuid.Nil.String()}, {"expected_lease_owner", "not-a-uuid"},
		{"expected_envelope_sha256", strings.Repeat("A", 64)}, {"expected_run_sha256", strings.Repeat("b", 63)},
		{"expected_members_sha256", strings.Repeat("C", 64)}, {"expected_fencing_token", 0},
		{"expected_fencing_token", -1}, {"expected_fencing_token", int64(9007199254740992)},
		{"expected_fencing_token", 1.5}, {"expected_fencing_token", "1"},
		{"expected_pending_wake_count", 0}, {"expected_pending_wake_count", 33}, {"expected_pending_wake_count", "32"},
		{"expected_returned_at", "invalid"}, {"expected_returned_at", "0001-01-01T00:00:00Z"},
	} {
		value := unknownMaintenanceDispatchCASFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeHTTPMaintenanceDispatchDisposition(strings.NewReader(encode(value))); err == nil {
			t.Fatal("caller authority or malformed CAS accepted", mutation.key)
		}
	}
	for _, raw := range []string{
		"", "{}", "null", "[]", good + good, strings.TrimSuffix(good, "}"),
		good + strings.Repeat(" ", unknownMaintenanceDispatchBodyLimit+1),
		strings.TrimSuffix(good, "}") + `,"job_id":"54136edb-daef-4aae-b29b-87bf84996e1f"}`,
		strings.TrimSuffix(good, "}") + `,"\u006aob_id":"54136edb-daef-4aae-b29b-87bf84996e1f"}`,
	} {
		if _, err := decodeHTTPMaintenanceDispatchDisposition(strings.NewReader(raw)); err == nil {
			t.Fatal("nonclosed body accepted")
		}
	}
}

func TestHTTPMaintenanceDispatchDispositionRequiresCurrentAdministrativeHuman(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	const base = "/api/v1/ops/capacity/http-maintenance-dispatch-dispositions"
	for _, route := range []struct {
		method string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{http.MethodPost, (*Server).handleOpsHTTPMaintenanceDispatchDisposition},
		{http.MethodGet, (*Server).handleOpsHTTPMaintenanceDispatchDispositionRead},
	} {
		w := httptest.NewRecorder()
		route.handle(&Server{}, w, httptest.NewRequest(route.method, base, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated caller reached repository", route.method, w.Code)
		}
		for _, permissions := range [][]string{{"yggdrasil:manage_workflows"}, {"yggdrasil:*"}} {
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, permissions)
			r := rbacTestRequestWithClaims(route.method, base, actor)
			r.Body = io.NopCloser(strings.NewReader(`{"provider_absent":true}`))
			r.SetPathValue("jobId", "not-a-uuid")
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			want := http.StatusForbidden
			if permissions[0] == "yggdrasil:*" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatal("administrative gate or closed input bypassed", route.method, permissions, w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		}
		// A bearer without a resolved human session cannot bypass the real
		// outer console gate into either new administrative route.
		r := httptest.NewRequest(route.method, base, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer declared-workflow-only-credential")
		s := &Server{}
		w = httptest.NewRecorder()
		s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route.handle(s, w, r)
		})).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("nonhuman credential crossed console gate", route.method, w.Code)
		}
	}
}

func TestHTTPMaintenanceDispatchDispositionSessionCSRF(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "declared-http-maintenance-csrf-test")
	const base = "/api/v1/ops/capacity/http-maintenance-dispatch-dispositions"
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		for _, token := range []string{"missing", "foreign", "valid"} {
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			mux := http.NewServeMux()
			mux.HandleFunc("POST "+base, s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsHTTPMaintenanceDispatchDisposition))
			mux.HandleFunc("GET "+base+"/{jobId}", s.requireOpsPermissionFunc(permManageWorkflows, s.handleOpsHTTPMaintenanceDispatchDispositionRead))
			path := base
			if method == http.MethodGet {
				path += "/not-a-uuid"
			}
			r := rbacTestRequestWithClaims(method, path, actor)
			r.Body = io.NopCloser(strings.NewReader(`{}`))
			switch token {
			case "foreign":
				r.Header.Set(csrfHeaderName, computeCSRFToken(uuid.New()))
			case "valid":
				claims, _ := claimsFromContext(r.Context())
				r.Header.Set(csrfHeaderName, computeCSRFToken(uuid.MustParse(claims["session_id"].(string))))
			}
			want := http.StatusForbidden
			if method == http.MethodGet || token == "valid" {
				// The real route permission check precedes the handler's GodMode check.
				programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
				programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
				want = http.StatusBadRequest
			}
			w := httptest.NewRecorder()
			s.csrfMiddleware(mux).ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("session CSRF contract changed", method, token, w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestHTTPMaintenanceDispatchDispositionSummaryPreservesOriginal(t *testing.T) {
	returned := time.Date(2026, 11, 2, 13, 26, 6, 898975000, time.UTC)
	updated := returned.Add(-time.Second)
	v := repository.CapacityDispatchHTTPMaintenanceDisposition{
		ID: uuid.New(), JobID: uuid.New(), RunID: uuid.New(), OriginalReturnedAt: returned,
		OriginalDispatchUpdatedAt: updated, HistoricalReturn: "unknown", State: "http_maintenance_disposed",
		Reason: repository.CapacityDispatchHTTPMaintenanceReason,
		EffectScan: repository.CapacityDispatchHTTPMaintenanceEffectScan{
			Schema: repository.CapacityDispatchHTTPMaintenanceScanSchema, CurrentMemberCount: 2,
			CurrentMembers: json.RawMessage(`[{"private-sentinel":"never-export"},{"private-sentinel":"never-export"}]`),
		},
	}
	out := httpMaintenanceDispatchDispositionSummary(v)
	wantKeys := []string{
		"schema", "id", "job_id", "run_id", "original_dispatch_sha256", "original_run_sha256", "original_dispatch_updated_at", "original_returned_at",
		"current_members_sha256", "current_member_count", "executor_barrier", "disposing_core_process_started_at", "disposing_core_hostname",
		"disposing_core_pid", "disposing_core_source_commit", "minimum_lease_age_seconds", "recorded_at", "issuer", "reason", "historical_return",
		"dispatch_state", "original_return_recorded", "original_finalization_ack_present", "finalization_ack_at", "workflow_run_preserved",
		"provider_mutation_evidence", "replayed", "provider_read_performed", "provider_quiescence_proved", "other_core_replicas_excluded", "new_current_admission_required",
	}
	gotKeys := make([]string, 0, len(out))
	for key := range out {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatal("public receipt allowlist changed", gotKeys)
	}
	if out["schema"] != "capacity_dispatch_http_maintenance_disposition_v1" || out["original_returned_at"] != returned || out["original_dispatch_updated_at"] != updated ||
		out["historical_return"] != "unknown" || out["dispatch_state"] != v.State || out["reason"] != v.Reason || out["current_member_count"] != 2 ||
		out["original_return_recorded"] != true || out["original_finalization_ack_present"] != false || out["finalization_ack_at"] != nil || out["workflow_run_preserved"] != true ||
		out["replayed"] != false || out["provider_read_performed"] != false || out["provider_quiescence_proved"] != false ||
		out["other_core_replicas_excluded"] != false || out["new_current_admission_required"] != true {
		t.Fatal("receipt invented ACK, health or authority, or rewrote history", out)
	}
	raw, err := json.Marshal(out)
	if err != nil || strings.Contains(string(raw), "never-export") || strings.Contains(string(raw), "private-sentinel") {
		t.Fatal("receipt exports retained membership body", err)
	}
}
