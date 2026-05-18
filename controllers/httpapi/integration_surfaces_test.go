package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	_ "github.com/lib/pq"
)

func openSurfacesTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping handler integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestHandleIntegrationSurfacesList(t *testing.T) {
	db := openSurfacesTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	ctx := context.Background()
	intType := "slack"
	m := integrationsurfaces.Manifest{
		Name:            "surface-handler-test",
		IntegrationType: &intType,
		Category:        integrationsurfaces.CategoryIntegration,
		Spec: integrationsurfaces.ManifestSpec{
			Category: integrationsurfaces.CategoryIntegration,
			Runtime:  integrationsurfaces.Runtime{Kind: "spa", BasePath: "/s/handler-test"},
			Display:  integrationsurfaces.Display{Title: "Handler Test", AppearsOn: []string{"ops-integrations"}},
		},
		Active: true,
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", m.Name) })
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}

	srv := &Server{integrationSurfacesRepo: repo}
	req := httptest.NewRequest("GET", "/api/v1/integration-surfaces?appears_on=ops-integrations", nil)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfacesList()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []integrationsurfaces.Manifest `json:"items"`
		Total int                            `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range body.Items {
		if it.Name == m.Name {
			found = true
		}
	}
	if !found {
		t.Errorf("test manifest not in list: %+v", body)
	}
}

func TestHandleIntegrationSurfacesGet_404(t *testing.T) {
	db := openSurfacesTestDB(t)
	srv := &Server{integrationSurfacesRepo: integrationsurfaces.NewRepository(db)}
	req := httptest.NewRequest("GET", "/api/v1/integration-surfaces/surface-does-not-exist", nil)
	req.SetPathValue("name", "surface-does-not-exist")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceGet()(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestHandleIntegrationSurfaceSync(t *testing.T) {
	db := openSurfacesTestDB(t)
	repo := integrationsurfaces.NewRepository(db)
	ctx := context.Background()
	m := integrationsurfaces.Manifest{
		Name:     "surface-touch-test",
		Category: integrationsurfaces.CategoryCore,
		Spec:     integrationsurfaces.ManifestSpec{Category: integrationsurfaces.CategoryCore, Display: integrationsurfaces.Display{Title: "T"}},
		Active:   true,
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", m.Name) })
	if err := repo.Upsert(ctx, &m); err != nil {
		t.Fatal(err)
	}

	srv := &Server{integrationSurfacesRepo: repo}
	req := httptest.NewRequest("POST", "/api/v1/integration-surfaces/"+m.Name+"/sync", strings.NewReader(""))
	req.SetPathValue("name", m.Name)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceSync()(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Code)
	}
}
