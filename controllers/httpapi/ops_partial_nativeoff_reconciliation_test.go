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

func TestPartialNativeOffOpsRequiresExplicitAdministrativeIdentity(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, handle := range []func(*Server, http.ResponseWriter, *http.Request){
		func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsPartialNativeOffReconciliation(w, r)
		},
		func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsPartialNativeOffReconciliationRead(w, r)
		},
		func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsPartialNativeOffReconciliationObserve(w, r)
		},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ops/capacity/failed-installed-guest-disposals/partial-native-off-reconciliations", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		handle(&Server{}, w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("anonymous or machine identity bypass", w.Code)
		}
		s, m := rbacTestSetup(t)
		id := uuid.New()
		programCollaboratorWithPermissions(m, id, []string{"yggdrasil:manage_workflows"})
		r = rbacTestRequestWithClaims(http.MethodPost, "/", id)
		w = httptest.NewRecorder()
		handle(s, w, r)
		if w.Code != http.StatusForbidden {
			t.Fatal("ordinary manager reached provider read", w.Code)
		}
		if e := m.ExpectationsWereMet(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPartialNativeOffOpsClosedIDsAndPublicProjection(t *testing.T) {
	pre, id, last := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, prior := range []string{"", last} {
		raw := `{"preregistration_id":"` + pre + `","reconciliation_id":"` + id + `","expected_previous_read_id":"` + prior + `"}`
		a, b, c, e := decodePartialNativeOffRead(strings.NewReader(raw))
		if e != nil || a != pre || b != id || c != prior {
			t.Fatal("exact public CAS IDs refused", e)
		}
	}
	good := `{"preregistration_id":"` + pre + `","reconciliation_id":"` + id + `","expected_previous_read_id":""}`
	for _, bad := range []string{`{}`, `null`, `[]`, good + good, strings.Replace(good, `}`, `,"force":true}`, 1), strings.Replace(good, `}`, `,"expected_previous_read_id":""}`, 1), strings.Replace(good, `"expected_previous_read_id":""`, `"expected_previous_read_id":null`, 1), strings.Replace(good, `"expected_previous_read_id":""`, `"expected_previous_read_id":"not-a-UUID"`, 1)} {
		if _, _, _, e := decodePartialNativeOffRead(strings.NewReader(bad)); e == nil {
			t.Fatal("caller supplied authority or duplicate key accepted")
		}
	}
	v := repository.FailedInstalledPartialNativeOff{FailedRun: `{"private":"DO_NOT_EXPORT"}`}
	v.OriginalClaimedIntent.LeaseOwner = "DO_NOT_EXPORT"
	raw, e := json.Marshal(partialNativeOffSummary(v))
	if e != nil || strings.Contains(string(raw), "DO_NOT_EXPORT") || !strings.Contains(string(raw), `"original_command_returned4_or_caller200_claimed":false`) {
		t.Fatal("private history leaked or command return invented", e)
	}
}
