package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/stretchr/testify/require"
)

func TestHandleOpsSurfacesList_EmptyByDefault(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces", nil)
	rec := httptest.NewRecorder()

	s.handleOpsSurfacesList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got model.SurfaceListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Empty(t, got.Surfaces)
}

func TestHandleOpsSurfaceManifest_NotFound(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces/heimdall/manifest", nil)
	req.SetPathValue("id", "heimdall")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceManifest(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleOpsSurfacesList_FromCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT surface_id, surface_version").
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "surface_version", "schema_version", "display_name",
			"icon", "description", "page_count", "widget_count", "permission_count",
			"health", "fetched_at",
		}).AddRow("github", "1.0.0", 1, "GitHub", "git-branch", "Repos", 2, 0, 2, "down", time.Now()))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces", nil)
	rec := httptest.NewRecorder()

	s.handleOpsSurfacesList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got model.SurfaceListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Len(t, got.Surfaces, 1)
	require.Equal(t, "github", got.Surfaces[0].Surface)
	require.Equal(t, "error", got.Surfaces[0].Health)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsSurfaceManifest_FromCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	raw := []byte(`{"surface":"github","surface_version":"1.0.0","schema_version":1,"display_name":"GitHub","icon":"git-branch","pages":[]}`)
	mock.ExpectQuery("SELECT surface_id, surface_version").
		WithArgs("github").
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "surface_version", "schema_version", "display_name",
			"icon", "description", "page_count", "widget_count", "permission_count",
			"raw", "health", "fetched_at",
		}).AddRow("github", "1.0.0", 1, "GitHub", "git-branch", "Repos", 0, 0, 0, raw, "ok", time.Now()))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces/github/manifest", nil)
	req.SetPathValue("id", "github")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceManifest(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, string(raw), rec.Body.String())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsSurfaceTargetsList(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	mock.ExpectQuery("SELECT surface_id, base_url").
		WithArgs(true).
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "base_url", "enabled", "description", "created_at", "updated_at",
		}).AddRow("github", "http://integration-github:8080", true, "GitHub Enterprise", now, now))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/surface-targets", nil)
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceTargetsList(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got opsSurfaceTargetsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Len(t, got.Targets, 1)
	require.Equal(t, "github", got.Targets[0].SurfaceID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsSurfaceTargetUpsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	mock.ExpectQuery("INSERT INTO public.surface_runtime_targets").
		WithArgs("github", "http://integration-github:8080", true, "GitHub Enterprise").
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "base_url", "enabled", "description", "created_at", "updated_at",
		}).AddRow("github", "http://integration-github:8080", true, "GitHub Enterprise", now, now))

	s := &Server{db: db}
	req := httptest.NewRequest("PUT", "/api/v1/ops/surface-targets/github", strings.NewReader(`{
		"base_url":"http://integration-github:8080/",
		"description":"GitHub Enterprise"
	}`))
	req.SetPathValue("id", "github")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceTargetUpsert(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got model.SurfaceRuntimeTarget
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	require.Equal(t, "github", got.SurfaceID)
	require.Equal(t, "http://integration-github:8080", got.BaseURL)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsSurfaceData_ProxiesToConfiguredRuntime(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/surface/data/pulses", r.URL.Path)
		require.Equal(t, "limit=10", r.URL.RawQuery)
		writeJSON(w, http.StatusOK, map[string]any{"rows": []any{}})
	}))
	defer upstream.Close()

	s := &Server{surfaceBaseURLs: map[string]string{"heimdall": upstream.URL}}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces/heimdall/data/pulses?limit=10", nil)
	req.SetPathValue("id", "heimdall")
	req.SetPathValue("viewId", "pulses")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceData(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"rows":[]}`, rec.Body.String())
}

func TestHandleOpsSurfaceData_ProxiesToDatabaseRuntimeTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/surface/data/pulses", r.URL.Path)
		writeJSON(w, http.StatusOK, map[string]any{"rows": []any{"db"}})
	}))
	defer upstream.Close()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	mock.ExpectQuery("SELECT surface_id, base_url").
		WithArgs("heimdall").
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "base_url", "enabled", "description", "created_at", "updated_at",
		}).AddRow("heimdall", upstream.URL, true, "", now, now))

	s := &Server{db: db}
	req := httptest.NewRequest("GET", "/api/v1/ops/surfaces/heimdall/data/pulses", nil)
	req.SetPathValue("id", "heimdall")
	req.SetPathValue("viewId", "pulses")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceData(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"rows":["db"]}`, rec.Body.String())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestHandleOpsSurfaceAction_ProxiesToConfiguredRuntime(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/surface/action/configure", r.URL.Path)
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
	}))
	defer upstream.Close()

	s := &Server{surfaceBaseURLs: map[string]string{"github": upstream.URL}}
	req := httptest.NewRequest("POST", "/api/v1/ops/surfaces/github/action/configure", nil)
	req.SetPathValue("id", "github")
	req.SetPathValue("actionId", "configure")
	rec := httptest.NewRecorder()

	s.handleOpsSurfaceAction(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"accepted":true}`, rec.Body.String())
}
