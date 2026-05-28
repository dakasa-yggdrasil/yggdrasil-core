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

// Phase 5B wired-route integration tests for /api/v1/ops/* — extension
// of the Phase 5 wired tests in ops_rbac_wired_test.go.
//
// Same shape: per-route-group cases assert warn-mode pass-through,
// enforce-mode rejection, and god-mode bypass. The handler itself is a
// no-op pass-through — the point is the middleware behaviour, not the
// handler.

// opsRouteCases is the inventory of /api/v1/ops/* routes with their
// gating permission. Wiring drift is also caught by
// TestOpsRoutesAreFullyMapped (regex scan over server.go), but these
// cases additionally exercise the full middleware → handler chain so
// any contract change in requireOpsPermission surfaces here.
//
// Mirrors the mapping committed in server.go.
func opsRouteCases() []wiredRouteCase {
	return []wiredRouteCase{
		// surfaces (read = view_integrations; mutate = manage_integrations)
		{"ops_surfaces_list", "GET", "/api/v1/ops/surfaces", permViewIntegrations, nil},
		{"ops_surface_targets_list", "GET", "/api/v1/ops/surface-targets", permViewIntegrations, nil},
		{"ops_surface_target_upsert", "PUT", "/api/v1/ops/surface-targets/abc", permManageIntegrations, nil},
		{"ops_surface_target_delete", "DELETE", "/api/v1/ops/surface-targets/abc", permManageIntegrations, nil},
		{"ops_surface_target_refresh", "POST", "/api/v1/ops/surface-targets/abc/refresh", permManageIntegrations, nil},
		{"ops_surface_manifest", "GET", "/api/v1/ops/surfaces/abc/manifest", permViewIntegrations, nil},
		{"ops_surface_data", "GET", "/api/v1/ops/surfaces/abc/data/view1", permViewIntegrations, nil},
		{"ops_surface_action", "POST", "/api/v1/ops/surfaces/abc/action/act1", permManageIntegrations, nil},
		// workflows (view = view_ops; dispatch/retry/abort/replay = manage_workflows)
		{"ops_workflows_list", "GET", "/api/v1/ops/workflows", permViewOps, nil},
		{"ops_workflow_detail", "GET", "/api/v1/ops/workflows/abc", permViewOps, nil},
		{"ops_workflow_retry", "POST", "/api/v1/ops/workflows/abc/retry", permManageWorkflows, nil},
		{"ops_workflow_abort", "POST", "/api/v1/ops/workflows/abc/abort", permManageWorkflows, nil},
		{"ops_workflow_replay", "POST", "/api/v1/ops/workflows/abc/replay", permManageWorkflows, nil},
		// approvals (view = view_ops; decide = manage_workflows — same class as guardian)
		{"ops_approvals_list", "GET", "/api/v1/ops/approvals", permViewOps, nil},
		{"ops_approval_approve", "POST", "/api/v1/ops/approvals/abc/approve", permManageWorkflows, nil},
		{"ops_approval_reject", "POST", "/api/v1/ops/approvals/abc/reject", permManageWorkflows, nil},
		// drift (view = view_ops; reconcile = manage_workflows)
		{"ops_drift_list", "GET", "/api/v1/ops/drift", permViewOps, nil},
		{"ops_drift_reconcile", "POST", "/api/v1/ops/drift/abc/reconcile", permManageWorkflows, nil},
		// catalog/system (catalog = view_integrations; system_health = view_ops)
		{"ops_catalog", "GET", "/api/v1/ops/catalog", permViewIntegrations, nil},
		{"ops_system_health", "GET", "/api/v1/ops/system/health", permViewOps, nil},
		// audit (view_audit)
		{"ops_audit", "GET", "/api/v1/ops/audit", permViewAudit, nil},
		// people probes (missing-mfa = view_people)
		{"ops_collaborators_missing_mfa", "GET", "/api/v1/ops/collaborators/missing-mfa", permViewPeople, nil},
	}
}

// TestWiredOpsRoutes_WarnModeDoesNotBlock: every ops route group emits an
// X-RBAC-Warn header but lets the handler complete in warn mode.
func TestWiredOpsRoutes_WarnModeDoesNotBlock(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")

	for _, g := range opsRouteCases() {
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

// TestWiredOpsRoutes_EnforceModeRejects: in enforce mode every ops
// route group returns 403 + Problem+JSON when the caller lacks the
// gating permission.
func TestWiredOpsRoutes_EnforceModeRejects(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	// One stamp per distinct permission used by ops routes — coverage matrix.
	groups := []wiredRouteCase{
		{"ops_surfaces_list", "GET", "/api/v1/ops/surfaces", permViewIntegrations, nil},
		{"ops_surface_target_delete", "DELETE", "/api/v1/ops/surface-targets/abc", permManageIntegrations, nil},
		{"ops_workflows_list", "GET", "/api/v1/ops/workflows", permViewOps, nil},
		{"ops_workflow_abort", "POST", "/api/v1/ops/workflows/abc/abort", permManageWorkflows, nil},
		{"ops_audit", "GET", "/api/v1/ops/audit", permViewAudit, nil},
		{"ops_collaborators_missing_mfa", "GET", "/api/v1/ops/collaborators/missing-mfa", permViewPeople, nil},
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

// TestWiredOpsRoutes_GodModeAdminPassesThroughEveryRoute: god-mode
// (`yggdrasil:*`) lets an admin pass every ops-route gate.
func TestWiredOpsRoutes_GodModeAdminPassesThroughEveryRoute(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	// Distinct permissions used by ops routes.
	perms := []string{
		permViewIntegrations,
		permManageIntegrations,
		permViewOps,
		permManageWorkflows,
		permViewAudit,
		permViewPeople,
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

			r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/ops/test", collabID)
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

