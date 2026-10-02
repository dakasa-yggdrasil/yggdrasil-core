package httpapi

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestValidatePausedReactorEventTypesExact(t *testing.T) {
	got, err := validatePausedReactorEventTypes([]string{"team.created", "github.repository.ensured"})
	if err != nil || !reflect.DeepEqual(got, []string{"github.repository.ensured", "team.created"}) {
		t.Fatalf("valid exact names=%v, err=%v", got, err)
	}
	for _, invalid := range [][]string{
		{"team.*"}, {" team.created"}, {"TEAM.CREATED"},
		{"team.created", "team.created"}, {"reactor.dead_lettered"},
	} {
		if _, err := validatePausedReactorEventTypes(invalid); err == nil {
			t.Fatalf("accepted invalid pause set %q", invalid)
		}
	}
}

func TestReactorDispatchPolicyPutRequiresManageIntegrations(t *testing.T) {
	// The shared console RBAC middleware permits missing grants in warn mode.
	// The dispatch policy is an operator control and must enforce regardless.
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &Server{db: db, logger: zap.NewNop()}
	collabID := uuid.New()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/ops/integration-instances/{namespace}/{name}/reactor-dispatch",
		srv.requireReactorPolicyPermissionFunc(permManageIntegrations, srv.handleReactorDispatchPolicyPut))
	mux.HandleFunc("GET /api/v1/ops/integration-instances/{namespace}/{name}/reactor-dispatch",
		srv.requireReactorPolicyPermissionFunc(permViewIntegrations, srv.handleReactorDispatchPolicyGet))
	programNoPermissions(mock, collabID)
	req := rbacTestRequestWithClaims(http.MethodPut,
		"/api/v1/ops/integration-instances/dakasa/slack/reactor-dispatch", collabID)
	req.Body = http.NoBody
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission.denied") {
		t.Fatalf("unauthorized policy PUT status=%d body=%s", w.Code, w.Body.String())
	}
	programNoPermissions(mock, collabID)
	get := rbacTestRequestWithClaims(http.MethodGet,
		"/api/v1/ops/integration-instances/dakasa/slack/reactor-dispatch", collabID)
	getResponse := httptest.NewRecorder()
	mux.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusForbidden || !strings.Contains(getResponse.Body.String(), "permission.denied") {
		t.Fatalf("unauthorized policy GET status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQL expectations: %v", err)
	}
}

func TestReactorDispatchPolicyPermissionsAllowAuthorizedSession(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &Server{db: db, logger: zap.NewNop()}
	collabID := uuid.New()
	for _, tc := range []struct {
		method string
		perm   string
	}{
		{http.MethodGet, permViewIntegrations},
		{http.MethodPut, permManageIntegrations},
	} {
		programCollaboratorWithPermissions(mock, collabID, []string{permViewIntegrations, permManageIntegrations})
		called := false
		wrapped := srv.requireReactorPolicyPermissionFunc(tc.perm, func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		response := httptest.NewRecorder()
		wrapped(response, rbacTestRequestWithClaims(tc.method,
			"/api/v1/ops/integration-instances/dakasa/slack/reactor-dispatch", collabID))
		if !called || response.Code != http.StatusOK {
			t.Fatalf("authorized %s not accepted: called=%v status=%d", tc.method, called, response.Code)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("SQL expectations: %v", err)
	}
}
