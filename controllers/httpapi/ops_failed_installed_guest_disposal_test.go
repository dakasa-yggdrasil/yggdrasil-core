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

func TestFailedInstalledDisposalRequiresExplicitAdministrativeIdentity(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, route := range []struct {
		method, path string
		handle       func(*Server, http.ResponseWriter, *http.Request)
	}{
		{http.MethodGet, "/api/v1/ops/capacity/failed-installed-guest-disposals/id", func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsFailedInstalledGuestDisposalRead(w, r)
		}},
		{http.MethodPost, "/api/v1/ops/capacity/failed-installed-guest-disposals", func(s *Server, w http.ResponseWriter, r *http.Request) { s.handleOpsFailedInstalledGuestDisposal(w, r) }},
		{http.MethodPost, "/api/v1/ops/capacity/failed-installed-guest-disposals/advance", func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsFailedInstalledGuestDisposalAdvance(w, r)
		}},
		{http.MethodPost, "/api/v1/ops/capacity/failed-installed-guest-disposals/complete", func(s *Server, w http.ResponseWriter, r *http.Request) {
			s.handleOpsFailedInstalledGuestDisposalComplete(w, r)
		}},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			route.handle(&Server{}, w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("no-claims or warn-mode bypass", w.Code)
			}
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
			r = rbacTestRequestWithClaims(route.method, route.path, actor)
			w = httptest.NewRecorder()
			route.handle(s, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("ordinary workflow manager reached repository", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedInstalledDisposalAcceptsOnlyTwoOriginalIDsAndSafeSummary(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	good := `{"preregistration_id":"` + a + `","expected_failed_run_id":"` + b + `"}`
	if x, y, err := decodeFailedInstalledGuestDisposal(strings.NewReader(good)); err != nil || x != a || y != b {
		t.Fatal(err)
	}
	if x, y, err := decodeFailedInstalledGuestIDs(strings.NewReader(strings.ReplaceAll(good, "expected_failed_run_id", "admission_id")), "admission_id"); err != nil || x != a || y != b {
		t.Fatal("advance/complete IDs", err)
	}
	for _, raw := range []string{`{"preregistration_id":"` + a + `","expected_failed_run_id":"` + b + `","retirement_mode":"legacy_guest548_original_v1"}`, `{}`, `null`, `[]`, good + good, `{"preregistration_id":"` + a + `","expected_failed_run_id":"` + b + `","useful_capacity_before":0}`, `{"preregistration_id":"` + a + `","preregistration_id":"` + a + `","expected_failed_run_id":"` + b + `"}`, `{"preregistration_id":"` + a + `","expected_failed_run_id":null}`, `{"preregistration_id":"` + a + `","expected_failed_run_id":"00000000-0000-0000-0000-000000000000"}`} {
		if _, _, err := decodeFailedInstalledGuestDisposal(strings.NewReader(raw)); err == nil {
			t.Fatal("caller supplied disposal authority accepted")
		}
	}
	r := repository.FailedInstalledGuestDisposal{OriginalRun: string(`{"private":"DO_NOT_EXPORT"}`), LastFailedRun: string(`{"private":"DO_NOT_EXPORT"}`), BusinessEffectsPreserved: true}
	wire, err := json.Marshal(failedInstalledGuestDisposalSummary(r))
	if err != nil || strings.Contains(string(wire), "DO_NOT_EXPORT") || !strings.Contains(string(wire), `"business_effects_preserved":true`) || strings.Contains(string(wire), "no_effect") {
		t.Fatal("summary leaked or erased effects", err)
	}
}
