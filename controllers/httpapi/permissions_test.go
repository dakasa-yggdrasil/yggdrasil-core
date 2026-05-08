package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func dbForPermissionsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping permissions HTTP integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func cleanPermissionsFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.role_permission_bindings WHERE permission_name LIKE 'pt:%'`); err != nil {
		t.Fatalf("delete bindings: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.permissions_catalog WHERE name LIKE 'pt:%'`); err != nil {
		t.Fatalf("delete permissions: %v", err)
	}
}

func newPermissionsTestServer(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	srv, err := New("test-yggdrasil-core", db, nil, logger)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return srv
}

func postJSONPerms(t *testing.T, srv http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

func TestPermissionRegister_Idempotent(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissionsFixtures(t, db)

	srv := newPermissionsTestServer(t, db)

	body := map[string]any{
		"name":          "pt:vacation:request-own",
		"description":   "request own vacation",
		"registered_by": "integration-employment-clt",
	}
	if rr := postJSONPerms(t, srv, "/api/v1/permissions/catalog", body); rr.Code != http.StatusOK {
		t.Fatalf("first register: %d body=%s", rr.Code, rr.Body.String())
	}
	body["description"] = "updated description"
	if rr := postJSONPerms(t, srv, "/api/v1/permissions/catalog", body); rr.Code != http.StatusOK {
		t.Fatalf("idempotent re-register: %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPermissionBindingsList_AfterCreate(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissionsFixtures(t, db)

	srv := newPermissionsTestServer(t, db)

	if rr := postJSONPerms(t, srv, "/api/v1/permissions/catalog", map[string]any{
		"name":          "pt:vacation:approve",
		"registered_by": "integration-employment-clt",
	}); rr.Code != http.StatusOK {
		t.Fatalf("register: %d", rr.Code)
	}
	if rr := postJSONPerms(t, srv, "/api/v1/permissions/bindings", map[string]any{
		"role":            "hr-manager",
		"permission_name": "pt:vacation:approve",
		"bound_by":        "test",
	}); rr.Code != http.StatusOK {
		t.Fatalf("bind: %d body=%s", rr.Code, rr.Body.String())
	}
	req := httptest.NewRequest("GET", "/api/v1/permissions/bindings?role=hr-manager", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list bindings: %d", rr.Code)
	}
	var resp struct {
		Bindings []model.RoleBinding `json:"bindings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Bindings) == 0 {
		t.Fatalf("expected at least one binding for hr-manager")
	}
}

func TestPermissionEvaluate_AllowedAndDenied(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()
	cleanPermissionsFixtures(t, db)

	srv := newPermissionsTestServer(t, db)

	if rr := postJSONPerms(t, srv, "/api/v1/permissions/catalog", map[string]any{
		"name":          "pt:paystub:view-own",
		"registered_by": "integration-employment-clt",
	}); rr.Code != http.StatusOK {
		t.Fatalf("register: %d", rr.Code)
	}
	if rr := postJSONPerms(t, srv, "/api/v1/permissions/bindings", map[string]any{
		"role":            "engineer",
		"permission_name": "pt:paystub:view-own",
	}); rr.Code != http.StatusOK {
		t.Fatalf("bind: %d", rr.Code)
	}
	rr := postJSONPerms(t, srv, "/api/v1/permissions/evaluate", map[string]any{
		"subject_role": "engineer",
		"permission":   "pt:paystub:view-own",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate allow: %d", rr.Code)
	}
	var allowResp model.EvaluatePermissionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &allowResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !allowResp.Allowed {
		t.Fatalf("expected allowed=true for engineer/pt:paystub:view-own, got %+v", allowResp)
	}

	rr2 := postJSONPerms(t, srv, "/api/v1/permissions/evaluate", map[string]any{
		"subject_role": "intern",
		"permission":   "pt:paystub:view-own",
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("evaluate deny: %d", rr2.Code)
	}
	var denyResp model.EvaluatePermissionResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &denyResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if denyResp.Allowed {
		t.Fatalf("expected allowed=false for intern, got %+v", denyResp)
	}
}

func TestPermissionRegister_Rejects400OnMissingName(t *testing.T) {
	db := dbForPermissionsTest(t)
	defer func() { _ = db.Close() }()

	srv := newPermissionsTestServer(t, db)
	rr := postJSONPerms(t, srv, "/api/v1/permissions/catalog", map[string]any{"registered_by": "x"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}
