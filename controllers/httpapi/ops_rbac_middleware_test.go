package httpapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TestRBACEnforceMode_DefaultsToWarn locks down the rollout default. A
// fresh deploy must be warn-mode so surface-console RBAC drift can be
// observed without 403-storming legit users mid-rollout. Mirror of the
// A7 CSRF default behaviour.
func TestRBACEnforceMode_DefaultsToWarn(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "")
	if got := rbacEnforceMode(); got != "warn" {
		t.Fatalf("default mode: expected warn, got %q", got)
	}
}

// TestRBACEnforceMode_RespectsExplicitEnforce: production flips this once
// the observation window converges.
func TestRBACEnforceMode_RespectsExplicitEnforce(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	if got := rbacEnforceMode(); got != "enforce" {
		t.Fatalf("explicit enforce: expected enforce, got %q", got)
	}
}

// TestRBACEnforceMode_GarbageDefaultsWarn: unknown values fall back to
// warn (fail-open during partial rollouts).
func TestRBACEnforceMode_GarbageDefaultsWarn(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "panic")
	if got := rbacEnforceMode(); got != "warn" {
		t.Fatalf("garbage mode should fall back to warn, got %q", got)
	}
}

// rbacTestSetup builds a Server with a sqlmock-backed DB and returns the
// mock so tests can program the permission query result.
func rbacTestSetup(t *testing.T) (*Server, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := &Server{db: db, logger: zap.NewNop()}
	return srv, mock
}

// rbacTestRequestWithClaims builds a request whose context carries
// collaborator_id claims (as if requireAuthenticatedConsoleAPIs already
// resolved the session). Tests can then drive the middleware in
// isolation.
func rbacTestRequestWithClaims(method, path string, collabID uuid.UUID) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	claims := map[string]any{
		"collaborator_id": collabID.String(),
		"sub":             collabID.String(),
		"session_id":      uuid.NewString(),
	}
	return r.WithContext(contextWithClaims(r.Context(), claims))
}

// programCollaboratorWithPermissions queues the two SQL roundtrips the
// middleware performs: GetCollaborator + ResolveYggdrasilPermissions.
//
// permissions is the action_catalog list returned by team_grants for the
// collaborator; pass []string{"yggdrasil:*"} for god-mode.
func programCollaboratorWithPermissions(mock sqlmock.Sqlmock, collabID uuid.UUID, permissions []string) {
	// 1) GetCollaborator(ctx, db, collabID.String()) — best-effort, errors
	// swallowed. We satisfy it with a row that has empty traits so god-mode
	// via traits.yggdrasil_admin doesn't accidentally apply.
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WithArgs(collabID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "display_name", "primary_email", "status", "role",
			"manager_id", "absence_started_at", "absence_ended_at",
			"personal_data", "employment_data", "preferences", "traits", "metadata",
			"created_at", "updated_at",
		}).AddRow(
			collabID.String(), "test-user", "Test User", "test@example.com", "active", "engineer",
			nil, nil, nil,
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"),
			"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
		))

	// 2) ResolveYggdrasilPermissions's team_grants query.
	rows := sqlmock.NewRows([]string{"action_name"})
	for _, p := range permissions {
		// god-mode is stored as "*" in team_grants; ResolveYggdrasilPermissions
		// collapses it to YggdrasilGodModeAction in the returned slice. We
		// emulate the row shape by passing "*" when the test asks for
		// "yggdrasil:*".
		if p == "yggdrasil:*" {
			rows = rows.AddRow("*")
		} else {
			rows = rows.AddRow(p)
		}
	}
	mock.ExpectQuery(`(?i)FROM\s+public\.team_grants`).
		WithArgs(collabID).
		WillReturnRows(rows)
}

// TestRequireOpsPermission_NoClaimsPassesThroughWorkflowToken: when the
// upstream auth middleware authorized the caller via the workflow-run
// token (no claims attached), the RBAC check must NOT 403 — automation
// callers have their own auth path and bypass user-perm enforcement.
func TestRequireOpsPermission_NoClaimsPassesThroughWorkflowToken(t *testing.T) {
	metrics.ResetForTest()
	srv, _ := rbacTestSetup(t)

	called := false
	mw := srv.requireOpsPermission("yggdrasil:view_people")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// No claims context — simulates the workflow-run-token branch in
	// requireAuthenticatedConsoleAPIs.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/collaborators", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Fatalf("expected workflow-run-token caller to pass through, got status %d", w.Code)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}
}

// TestRequireOpsPermission_AuthorizedUserPassesThrough: the canonical
// happy path. User has the exact permission; handler runs; no warn
// header, no metric bump.
func TestRequireOpsPermission_AuthorizedUserPassesThrough(t *testing.T) {
	metrics.ResetForTest()
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:view_people"})

	called := false
	mw := srv.requireOpsPermission("yggdrasil:view_people")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/collaborators", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Fatalf("authorized user should pass through; status=%d", w.Code)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}
	if warn := w.Header().Get(rbacWarnHeader); warn != "" {
		t.Errorf("authorized user should not have X-RBAC-Warn header, got %q", warn)
	}
	snap := metrics.RBACDeniedSnapshot()
	if len(snap) != 0 {
		t.Errorf("authorized user should not bump denied counter, got %+v", snap)
	}
}

// TestRequireOpsPermission_GodModePassesThrough: traits.yggdrasil_admin
// OR a wildcard team_grant translates to YggdrasilGodModeAction, which
// matches any yggdrasil:* permission without an explicit grant.
func TestRequireOpsPermission_GodModePassesThrough(t *testing.T) {
	metrics.ResetForTest()
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:*"})

	called := false
	mw := srv.requireOpsPermission("yggdrasil:manage_workflows") // any yggdrasil:* perm
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/console/workflow-runs", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Fatalf("god-mode user should pass through; status=%d", w.Code)
	}
	if warn := w.Header().Get(rbacWarnHeader); warn != "" {
		t.Errorf("god-mode user should not have X-RBAC-Warn header, got %q", warn)
	}
}

// TestRequireOpsPermission_WarnModeMissingPermissionPassesThrough: when
// the user lacks the permission AND the rollout is in warn mode, the
// middleware MUST allow the request through (preserving the FE-driven
// auth-or-anonymous boundary surface-console relies on today). It MUST:
//   - log a warning
//   - bump the counter with mode=warn
//   - set the X-RBAC-Warn header
//   - leave status untouched (200 from the wrapped handler)
func TestRequireOpsPermission_WarnModeMissingPermissionPassesThrough(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	// User has SOME permissions but NOT the one being checked.
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:view_teams"})

	called := false
	mw := srv.requireOpsPermission("yggdrasil:view_people")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/collaborators", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Fatalf("warn-mode missing permission should pass through; status=%d", w.Code)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}
	if warn := w.Header().Get(rbacWarnHeader); warn != "yggdrasil:view_people" {
		t.Errorf("warn-mode missing permission should set X-RBAC-Warn header, got %q", warn)
	}
	snap := metrics.RBACDeniedSnapshot()
	got := snap["yggdrasil:view_people|warn"]
	if got != 1 {
		t.Errorf("expected rbac_denied counter for warn mode to be 1, got %d (snap=%+v)", got, snap)
	}
}

// TestRequireOpsPermission_EnforceModeMissingPermissionRejects: in
// enforce mode the request is rejected with 403 + Problem+JSON. The
// handler MUST NOT be invoked. Counter bumps under mode=enforce.
func TestRequireOpsPermission_EnforceModeMissingPermissionRejects(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	// User has SOME permissions but NOT the one being checked.
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:view_teams"})

	called := false
	mw := srv.requireOpsPermission("yggdrasil:offboard_collaborator")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/console/collaborators/abc/offboard", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if called {
		t.Fatalf("enforce-mode missing permission should NOT invoke handler")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: expected 403, got %d", w.Code)
	}
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "problem+json") {
		t.Errorf("expected application/problem+json, got %q", contentType)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"code":"permission.denied"`) {
		t.Errorf("response body should contain permission.denied code, got %q", body)
	}
	snap := metrics.RBACDeniedSnapshot()
	got := snap["yggdrasil:offboard_collaborator|enforce"]
	if got != 1 {
		t.Errorf("expected rbac_denied counter for enforce mode to be 1, got %d (snap=%+v)", got, snap)
	}
}

// TestRequireOpsPermission_DBErrorAlwaysFails500: an infrastructure
// error (DB down, query plan bug, …) must fail-closed even in warn
// mode. Operators need to see infrastructure problems unambiguously;
// silent pass-through would hide a malfunction.
func TestRequireOpsPermission_DBErrorAlwaysFails500(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()

	// GetCollaborator is best-effort (swallowed), so program it to succeed
	// silently — but make ResolveYggdrasilPermissions fail with a DB error.
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WithArgs(collabID.String()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "display_name", "primary_email", "status", "role",
			"manager_id", "absence_started_at", "absence_ended_at",
			"personal_data", "employment_data", "preferences", "traits", "metadata",
			"created_at", "updated_at",
		}).AddRow(
			collabID.String(), "test-user", "Test User", "test@example.com", "active", "engineer",
			nil, nil, nil,
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"),
			"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
		))
	mock.ExpectQuery(`(?i)FROM\s+public\.team_grants`).
		WithArgs(collabID).
		WillReturnError(sql.ErrConnDone)

	called := false
	mw := srv.requireOpsPermission("yggdrasil:view_people")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/collaborators", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if called {
		t.Fatalf("DB error should NOT invoke handler")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: expected 500, got %d", w.Code)
	}
}

// TestRequireOpsPermission_AttachesPermissionToContext: downstream
// handlers (e.g. ops_audit_middleware) read ctxKeyOpsPermission to tag
// audit rows. Lock that contract.
func TestRequireOpsPermission_AttachesPermissionToContext(t *testing.T) {
	metrics.ResetForTest()
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:view_people"})

	var got string
	mw := srv.requireOpsPermission("yggdrasil:view_people")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(ctxKeyOpsPermission{}).(string); ok {
			got = v
		}
		w.WriteHeader(http.StatusOK)
	}))

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/collaborators", collabID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got != "yggdrasil:view_people" {
		t.Errorf("permission not attached to context: got %q, want yggdrasil:view_people", got)
	}
}

// TestRequireOpsPermissionFunc_HandlerFuncShape: the convenience wrapper
// preserves all the behaviour of the http.Handler-shaped variant; this
// is the form server.go actually uses.
func TestRequireOpsPermissionFunc_HandlerFuncShape(t *testing.T) {
	metrics.ResetForTest()
	srv, mock := rbacTestSetup(t)
	collabID := uuid.New()
	programCollaboratorWithPermissions(mock, collabID, []string{"yggdrasil:view_people"})

	called := false
	hf := srv.requireOpsPermissionFunc("yggdrasil:view_people", func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/console/collaborators", collabID)
	w := httptest.NewRecorder()
	hf(w, r)

	if !called {
		t.Fatalf("HandlerFunc wrapper should invoke next on authorized; status=%d", w.Code)
	}
}

// TestRBACDeniedMetric_LabelShape locks down the (permission, mode)
// label scheme: the Prometheus exposition must emit the permission and
// mode as separate labels, the value must be a uint64 counter, and
// unknown modes must be silently dropped to keep cardinality bounded.
func TestRBACDeniedMetric_LabelShape(t *testing.T) {
	metrics.ResetForTest()
	metrics.IncRBACDenied("yggdrasil:view_people", metrics.RBACModeWarn)
	metrics.IncRBACDenied("yggdrasil:view_people", metrics.RBACModeWarn)
	metrics.IncRBACDenied("yggdrasil:view_people", metrics.RBACModeEnforce)
	metrics.IncRBACDenied("yggdrasil:view_teams", metrics.RBACModeEnforce)
	// Unknown mode must drop silently.
	metrics.IncRBACDenied("yggdrasil:view_people", "bogus")
	// Empty permission must drop silently.
	metrics.IncRBACDenied("", metrics.RBACModeWarn)

	snap := metrics.RBACDeniedSnapshot()
	if got := snap["yggdrasil:view_people|warn"]; got != 2 {
		t.Errorf("expected view_people|warn=2, got %d", got)
	}
	if got := snap["yggdrasil:view_people|enforce"]; got != 1 {
		t.Errorf("expected view_people|enforce=1, got %d", got)
	}
	if got := snap["yggdrasil:view_teams|enforce"]; got != 1 {
		t.Errorf("expected view_teams|enforce=1, got %d", got)
	}
	if _, ok := snap["yggdrasil:view_people|bogus"]; ok {
		t.Errorf("unknown mode should not have entry, got %+v", snap)
	}
}

// helper — avoid an unused import warning when the package linker tightens.
var _ = context.Background
