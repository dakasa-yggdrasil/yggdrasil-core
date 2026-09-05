package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// dbForManifestDeleteTest opens the integration Postgres or skips. Same
// env-var contract as the other repository-touching tests in this package.
func dbForManifestDeleteTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping manifests delete integration test")
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

// newManifestDeleteServer wires the minimal mux + Server needed by the
// route tests. Mirrors newEventPublishServer in scope: no OIDC, no SPA.
func newManifestDeleteServer(db *sql.DB) http.Handler {
	server := &Server{
		serviceName: "yggdrasil-core-test",
		db:          db,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/v1/manifests/{id}", server.handleManifestDelete)
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)
	mux.HandleFunc("GET /api/v1/manifests", server.handleManifestListGeneric)
	return mux
}

// seedManifestForDelete creates one manifest version through the public
// HTTP path so the test reproduces the same row shape operators see
// in production. Returns the manifest id from the response envelope.
func seedManifestForDelete(t *testing.T, h http.Handler, name string) string {
	t.Helper()
	body := map[string]any{
		"name":      name,
		"namespace": "delete-test",
		"spec": map[string]any{
			"category":   "application",
			"class":      "platform",
			"lifecycle":  map[string]any{},
			"components": []any{},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=product", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("seed POST status: got %d, want %d (body=%s)", w.Code, http.StatusCreated, w.Body.String())
	}
	var resp struct {
		Manifest struct {
			ID string `json:"id"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode seed response: %v", err)
	}
	if resp.Manifest.ID == "" {
		t.Fatalf("seed response missing manifest.id: %s", w.Body.String())
	}
	return resp.Manifest.ID
}

func doDelete(t *testing.T, h http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestHandleManifestDelete_HardDelete validates the default mode removes
// the row from the manifests table and a subsequent GET no longer surfaces it.
func TestHandleManifestDelete_HardDelete(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForManifestDeleteTest(t)
	defer db.Close()
	// Clean the per-test namespace; row counts must be reproducible.
	if _, err := db.Exec(`DELETE FROM public.manifests WHERE namespace = $1`, "delete-test"); err != nil {
		t.Fatalf("clean manifests: %v", err)
	}

	h := newManifestDeleteServer(db)
	id := seedManifestForDelete(t, h, "hard-delete-target")

	w := doDelete(t, h, "/api/v1/manifests/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("hard delete status: got %d, want %d (body=%s)", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if resp["deleted"] != true {
		t.Fatalf("expected deleted=true, got %v", resp["deleted"])
	}
	if resp["mode"] != "hard" {
		t.Fatalf("expected mode=hard, got %v", resp["mode"])
	}

	// Row gone from the DB after a hard delete; not just inactive.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.manifests WHERE id = $1`, id).Scan(&count); err != nil {
		t.Fatalf("count after hard delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected row gone after hard delete, got %d", count)
	}
}

// TestHandleManifestDelete_SoftDelete validates ?soft=true keeps the
// row but flips active=FALSE so active_only=true lists no longer
// surface it.
func TestHandleManifestDelete_SoftDelete(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForManifestDeleteTest(t)
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM public.manifests WHERE namespace = $1`, "delete-test"); err != nil {
		t.Fatalf("clean manifests: %v", err)
	}

	h := newManifestDeleteServer(db)
	id := seedManifestForDelete(t, h, "soft-delete-target")

	w := doDelete(t, h, "/api/v1/manifests/"+id+"?soft=true", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("soft delete status: got %d, want %d (body=%s)", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode soft delete response: %v", err)
	}
	if resp["mode"] != "soft" {
		t.Fatalf("expected mode=soft, got %v", resp["mode"])
	}

	// Row still there, but active flipped.
	var active bool
	if err := db.QueryRow(`SELECT active FROM public.manifests WHERE id = $1`, id).Scan(&active); err != nil {
		t.Fatalf("read active after soft delete: %v", err)
	}
	if active {
		t.Fatalf("expected active=false after soft delete, got true")
	}
}

// TestHandleManifestDelete_IdempotentNotFound validates the
// already-absent path: a fresh UUID that never existed returns 200 with
// already_absent=true so the periodic purge retry loop doesn't choke.
func TestHandleManifestDelete_IdempotentNotFound(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	db := dbForManifestDeleteTest(t)
	defer db.Close()

	h := newManifestDeleteServer(db)

	// Random UUID that doesn't exist in the table.
	w := doDelete(t, h, "/api/v1/manifests/018f2b4a-1234-7abc-def0-deadbeefcafe", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("not-found status: got %d, want %d (body=%s)", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode not-found response: %v", err)
	}
	if resp["deleted"] != true {
		t.Fatalf("expected deleted=true, got %v", resp["deleted"])
	}
	if resp["already_absent"] != true {
		t.Fatalf("expected already_absent=true, got %v", resp["already_absent"])
	}
}

// TestHandleManifestDelete_InvalidID guards the 400 path: a non-UUID
// path param must fail validation before the repository is touched.
func TestHandleManifestDelete_InvalidID(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	// nil DB is fine: the handler returns 400 before touching s.db.
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/v1/manifests/{id}", server.handleManifestDelete)

	w := doDelete(t, mux, "/api/v1/manifests/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status: got %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

// TestHandleManifestDelete_AuthRequired guards the authenticated path: a
// configured workflow machine principal does not turn manifest deletion into
// a machine-token route, and anonymous/wrong-token requests receive 401.
func TestHandleManifestDelete_AuthRequired(t *testing.T) {
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "machine-token", "ci",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/v1/manifests/{id}", server.handleManifestDelete)

	// No header — expect 401.
	w := doDelete(t, mux, "/api/v1/manifests/018f2b4a-1234-7abc-def0-deadbeefcafe", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status: got %d, want %d (body=%s)", w.Code, http.StatusUnauthorized, w.Body.String())
	}

	// Wrong token — still 401.
	w = doDelete(t, mux, "/api/v1/manifests/018f2b4a-1234-7abc-def0-deadbeefcafe", map[string]string{
		"X-Yggdrasil-Workflow-Token": "wrong",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
