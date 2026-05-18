package httpapi

import (
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

// TestIntegrationSurfaceRoutes_MountedOnRealRouter boots the full httpapi.New
// router with a real DB (no rabbitmq) and verifies the 4 new routes are
// registered and reachable. Surface-query returns 503 because the dispatcher
// option is not provided (rabbitmq is nil in this test) — that's the
// expected fail-closed behaviour.
func TestIntegrationSurfaceRoutes_MountedOnRealRouter(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping routes smoke")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Seed a smoke row so the list returns ≥ 1 item.
	const seedName = "surface-routes-smoke"
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", seedName) })
	_, _ = db.Exec("DELETE FROM integration_surfaces WHERE name = $1", seedName)
	if _, err := db.Exec(`
		INSERT INTO integration_surfaces (name, category, spec, active)
		VALUES ($1, 'core', '{"category":"core","runtime":{"kind":"spa","base_path":"/s/x"},"display":{"title":"S","appears_on":["ops-integrations"]}}'::jsonb, true)
	`, seedName); err != nil {
		t.Fatalf("seed: %v", err)
	}

	repo := integrationsurfaces.NewRepository(db)
	handler, err := New("test", db, nil, nil,
		WithIntegrationSurfacesRepo(repo),
	)
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}

	t.Run("list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/integration-surfaces?appears_on=ops-integrations", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Items []integrationsurfaces.Manifest `json:"items"`
			Total int                            `json:"total"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, it := range resp.Items {
			if it.Name == seedName {
				found = true
			}
		}
		if !found {
			t.Errorf("seed row not returned: items=%+v", resp.Items)
		}
	})

	t.Run("get", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/integration-surfaces/"+seedName, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("sync_touch", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/integration-surfaces/"+seedName+"/sync", strings.NewReader(""))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Errorf("status=%d body=%s, want 202", w.Code, w.Body.String())
		}
	})

	t.Run("surface_query_dispatcher_absent_returns_503", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/integrations/any-id/surface-query",
			strings.NewReader(`{"query_name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		// Dispatcher not configured (no rabbitmq in this test) → handler returns 503.
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status=%d body=%s, want 503", w.Code, w.Body.String())
		}
	})
}
