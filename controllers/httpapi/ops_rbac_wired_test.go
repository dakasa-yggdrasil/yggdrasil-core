package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 5 wired-route integration tests — audit 2026-05-27 §3.1.
//
// These tests verify that the per-route requireOpsPermissionFunc wiring
// in server.go actually intercepts unauthorized callers. Unit tests in
// ops_rbac_middleware_test.go cover the middleware in isolation; these
// cover the route → middleware → handler chain.
//
// We don't spin up the full New() (which requires a postgres + amqp),
// so we register a single route's wrapper directly on a private mux,
// mirroring what server.go does. Drift between this and server.go is
// caught by TestConsoleRoutesAreFullyMapped + TestConsoleRoutesUseCanonicalPermissions.

// wiredRouteCase is a stamp covering one (route group, permission) pair.
type wiredRouteCase struct {
	name        string
	method      string
	path        string
	requiredPerm string
	// handler is a no-op that returns 200 on pass-through. The point of
	// these tests is the middleware behaviour, not the handler.
	handler http.HandlerFunc
}

func newRBACPassThroughHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// programNoPermissions sets up the sqlmock so GetCollaborator succeeds
// (best-effort) and ResolveYggdrasilPermissions returns NO rows.
func programNoPermissions(mock sqlmock.Sqlmock, collabID uuid.UUID) {
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WithArgs(collabID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "display_name", "primary_email", "status", "role",
			"manager_id", "absence_started_at", "absence_ended_at",
			"personal_data", "employment_data", "preferences", "traits", "metadata",
			"created_at", "updated_at",
		}).AddRow(
			collabID.String(), "noperms", "No Perms", "noperms@example.com", "active", "engineer",
			nil, nil, nil,
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"),
			"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
		))
	// Empty team_grants result.
	mock.ExpectQuery(`(?i)FROM\s+public\.team_grants`).
		WithArgs(collabID).
		WillReturnRows(sqlmock.NewRows([]string{"action_name"}))
}

// TestWiredConsoleRoutes_WarnModeDoesNotBlock: in warn mode (default),
// every console route group emits an X-RBAC-Warn header but lets the
// handler complete. This is the rollout-safety guarantee.
func TestWiredConsoleRoutes_WarnModeDoesNotBlock(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")

	groups := []wiredRouteCase{
		{"collaborators_list", "GET", "/api/v1/console/collaborators", permViewPeople, nil},
		{"collaborators_create", "POST", "/api/v1/console/collaborators", permCreateCollaborator, nil},
		{"collaborators_offboard", "POST", "/api/v1/console/collaborators/abc/offboard", permOffboardCollaborator, nil},
		{"teams_list", "GET", "/api/v1/console/teams", permViewTeams, nil},
		{"teams_create", "POST", "/api/v1/console/teams", permCreateTeam, nil},
		{"team_grants_list", "GET", "/api/v1/console/teams/abc/grants", permManageTeamPermissions, nil},
		{"team_grants_create", "POST", "/api/v1/console/teams/abc/grants", permManageTeamPermissions, nil},
		{"integration_instances_list", "GET", "/api/v1/console/integration-instances", permViewIntegrations, nil},
		{"integration_instances_create", "POST", "/api/v1/console/integration-instances", permManageIntegrations, nil},
		{"secrets_list", "GET", "/api/v1/console/secrets", permManageIntegrations, nil},
		{"workflows_list", "GET", "/api/v1/console/workflows", permViewOps, nil},
		{"workflow_runs_create", "POST", "/api/v1/console/workflow-runs", permManageWorkflows, nil},
		{"auth_providers_list", "GET", "/api/v1/console/auth/providers", permManageAuthProviders, nil},
		{"provision_aws", "POST", "/api/v1/console/provision/aws", permManageOrganization, nil},
	}

	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			metrics.ResetForTest()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()
			srv := &Server{db: db, logger: zap.NewNop()}

			collabID := uuid.New()
			programNoPermissions(mock, collabID)

			wrapped := srv.requireOpsPermissionFunc(g.requiredPerm, newRBACPassThroughHandler())

			r := rbacTestRequestWithClaims(g.method, g.path, collabID)
			w := httptest.NewRecorder()
			wrapped(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("[%s] warn-mode should pass through, got status %d body=%s", g.name, w.Code, w.Body.String())
			}
			if warn := w.Header().Get(rbacWarnHeader); warn != g.requiredPerm {
				t.Errorf("[%s] expected X-RBAC-Warn=%s, got %q", g.name, g.requiredPerm, warn)
			}
			snap := metrics.RBACDeniedSnapshot()
			key := g.requiredPerm + "|warn"
			if snap[key] != 1 {
				t.Errorf("[%s] expected warn counter for %s to be 1, got %d (snap=%+v)", g.name, key, snap[key], snap)
			}
		})
	}
}

// TestWiredConsoleRoutes_EnforceModeRejects: in enforce mode every
// route group returns 403 + Problem+JSON when the caller lacks the
// gating permission. This is the "after observation flips enforce"
// posture.
func TestWiredConsoleRoutes_EnforceModeRejects(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	groups := []wiredRouteCase{
		{"collaborators_list", "GET", "/api/v1/console/collaborators", permViewPeople, nil},
		{"teams_create", "POST", "/api/v1/console/teams", permCreateTeam, nil},
		{"secrets_create", "POST", "/api/v1/console/secrets", permManageIntegrations, nil},
		{"workflow_runs_create", "POST", "/api/v1/console/workflow-runs", permManageWorkflows, nil},
		{"provision_aws", "POST", "/api/v1/console/provision/aws", permManageOrganization, nil},
		{"auth_providers_list", "GET", "/api/v1/console/auth/providers", permManageAuthProviders, nil},
	}

	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			metrics.ResetForTest()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()
			srv := &Server{db: db, logger: zap.NewNop()}

			collabID := uuid.New()
			programNoPermissions(mock, collabID)

			called := false
			wrapped := srv.requireOpsPermissionFunc(g.requiredPerm, func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			r := rbacTestRequestWithClaims(g.method, g.path, collabID)
			w := httptest.NewRecorder()
			wrapped(w, r)

			if called {
				t.Fatalf("[%s] enforce-mode must not invoke handler", g.name)
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("[%s] expected 403, got %d", g.name, w.Code)
			}
			if !strings.Contains(w.Body.String(), `"code":"permission.denied"`) {
				t.Errorf("[%s] body should contain permission.denied: %s", g.name, w.Body.String())
			}
			snap := metrics.RBACDeniedSnapshot()
			key := g.requiredPerm + "|enforce"
			if snap[key] != 1 {
				t.Errorf("[%s] expected enforce counter for %s to be 1, got %d", g.name, key, snap[key])
			}
		})
	}
}

// TestWiredConsoleRoutes_GodModeAdminPassesThroughEveryRoute: the
// "yggdrasil:*" wildcard grant must let an admin pass every gate. This
// is the smoke test for "did we accidentally hardcode a permission
// somewhere that god-mode doesn't satisfy".
func TestWiredConsoleRoutes_GodModeAdminPassesThroughEveryRoute(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	// One stamp per permission constant — coverage matrix.
	perms := []string{
		permViewPeople, permCreateCollaborator, permEditCollaborator,
		permOffboardCollaborator, permViewTeams, permCreateTeam, permEditTeam,
		permManageTeamPermissions, permViewIntegrations, permManageIntegrations,
		permManageAuthProviders, permViewOps, permManageWorkflows, permManageOrganization,
	}

	for _, perm := range perms {
		t.Run(perm, func(t *testing.T) {
			metrics.ResetForTest()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()
			srv := &Server{db: db, logger: zap.NewNop()}

			collabID := uuid.New()
			programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:*"})

			called := false
			wrapped := srv.requireOpsPermissionFunc(perm, func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/test", collabID)
			w := httptest.NewRecorder()
			wrapped(w, r)

			if !called {
				t.Fatalf("[%s] god-mode admin must pass through; status=%d", perm, w.Code)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("[%s] expected 200, got %d", perm, w.Code)
			}
			if warn := w.Header().Get(rbacWarnHeader); warn != "" {
				t.Errorf("[%s] god-mode admin should not have X-RBAC-Warn header, got %q", perm, warn)
			}
		})
	}
}
