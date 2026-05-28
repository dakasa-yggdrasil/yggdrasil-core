package httpapi

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"go.uber.org/zap"
)

// Phase 6 — handleOpsSurfaceConfigureContext tests.
//
// Aggregate replaces 3 sequential queries from OpsIntegrationsPage detail
// panel. Heavy mocking required (the catalog walker reads two manifest
// listings); we exercise the matching strategy via the pure helper
// matchCatalogEntryForSurface, then assert the handler returns the
// expected envelope shape for the "happy path" and "404 on missing
// surface" cases.

// TestMatchCatalogEntryForSurface_ExactPluginName — pass 1 of the
// resolver: surface id matches plugin_name exactly.
func TestMatchCatalogEntryForSurface_ExactPluginName(t *testing.T) {
	domains := []model.IntegrationCatalogDomain{
		{
			Domain: "comms",
			Sections: []model.IntegrationCatalogSection{
				{Name: "messaging", Entries: []model.IntegrationCatalogEntry{
					{PluginName: "slack", Entry: "slack-bot"},
					{PluginName: "discord", Entry: "discord-webhook"},
				}},
			},
		},
	}
	e, ok := matchCatalogEntryForSurface(domains, "slack")
	if !ok || e.PluginName != "slack" {
		t.Fatalf("expected slack match, got ok=%v entry=%+v", ok, e)
	}
}

// TestMatchCatalogEntryForSurface_ExactEntrySlug — pass 2: surface
// matches the entry slug when no plugin matches.
func TestMatchCatalogEntryForSurface_ExactEntrySlug(t *testing.T) {
	domains := []model.IntegrationCatalogDomain{
		{
			Sections: []model.IntegrationCatalogSection{
				{Entries: []model.IntegrationCatalogEntry{
					{PluginName: "github-actions", Entry: "github"},
				}},
			},
		},
	}
	e, ok := matchCatalogEntryForSurface(domains, "github")
	if !ok || e.PluginName != "github-actions" {
		t.Fatalf("expected entry-slug match → github-actions, got ok=%v entry=%+v", ok, e)
	}
}

// TestMatchCatalogEntryForSurface_SubstringMatch — pass 3: surface
// contains plugin name as a substring. Mirrors the FE's `.includes`
// fallback for surfaces like "github-stats-ops" that share the same
// underlying provider as the plugin.
func TestMatchCatalogEntryForSurface_SubstringMatch(t *testing.T) {
	domains := []model.IntegrationCatalogDomain{
		{
			Sections: []model.IntegrationCatalogSection{
				{Entries: []model.IntegrationCatalogEntry{
					{PluginName: "github", Entry: "github-actions"},
				}},
			},
		},
	}
	e, ok := matchCatalogEntryForSurface(domains, "github-stats-ops")
	if !ok || e.PluginName != "github" {
		t.Fatalf("expected substring match → github, got ok=%v entry=%+v", ok, e)
	}
}

// TestMatchCatalogEntryForSurface_NoMatch — no domain entries match the
// surface id; resolver returns false.
func TestMatchCatalogEntryForSurface_NoMatch(t *testing.T) {
	domains := []model.IntegrationCatalogDomain{
		{
			Sections: []model.IntegrationCatalogSection{
				{Entries: []model.IntegrationCatalogEntry{
					{PluginName: "slack", Entry: "slack-bot"},
				}},
			},
		},
	}
	_, ok := matchCatalogEntryForSurface(domains, "stripe")
	if ok {
		t.Fatalf("expected no match for stripe, got ok=true")
	}
}

// TestHandleOpsSurfaceConfigureContext_MissingIDReturns400 verifies
// defensive 400 on empty path arg.
func TestHandleOpsSurfaceConfigureContext_MissingIDReturns400(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ops/surfaces//configure-context", nil)
	r.SetPathValue("id", "")
	w := httptest.NewRecorder()
	s.handleOpsSurfaceConfigureContext(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestHandleOpsSurfaceConfigureContext_MissingSurfaceReturns404 verifies
// that an unknown surface id returns 404 (not 500).
func TestHandleOpsSurfaceConfigureContext_MissingSurfaceReturns404(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// GetSurfaceManifest returns sql.ErrNoRows for missing surface — our
	// repository wraps it as ErrSurfaceManifestNotFound.
	mock.ExpectQuery(`(?i)FROM\s+public\.surface_manifests`).
		WithArgs("nope").
		WillReturnError(sql.ErrNoRows)

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ops/surfaces/nope/configure-context", nil)
	r.SetPathValue("id", "nope")
	w := httptest.NewRecorder()
	s.handleOpsSurfaceConfigureContext(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestHandleOpsSurfaceConfigureContext_FieldNames locks down the
// canonical envelope shape so the TS side won't drift silently when
// fields are renamed.
//
// We stub GetSurfaceManifest to return a row with non-empty Raw so the
// surface section serializes; the catalog walker hits two SELECT *
// FROM manifests queries that return empty (no catalog → matchedEntry
// stays nil), so catalog_entry / integration_type_manifest /
// current_instance all serialize as `null` (the JSON tag is
// `omitempty` but `nil` pointer + omitempty still works — the test
// here is that the surface field is present).
func TestHandleOpsSurfaceConfigureContext_FieldNames(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`(?i)FROM\s+public\.surface_manifests`).
		WithArgs("github").
		WillReturnRows(sqlmock.NewRows([]string{
			"surface_id", "surface_version", "schema_version", "display_name",
			"icon", "description", "page_count", "widget_count", "permission_count",
			"raw", "health", "fetched_at",
		}).AddRow(
			"github", "v1", 1, "GitHub", "ghicon", "Source control", 1, 1, 1,
			[]byte(`{"surface_id":"github"}`), "ok", time.Now(),
		))
	// integration_type manifests listing (catalog walker).
	mock.ExpectQuery(`(?i)FROM\s+public\.manifests`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "description",
			"labels", "active", "version", "spec", "checksum", "created_at", "updated_at",
		}))
	// integration_instance manifests listing — also empty for the
	// "surface alone" case.
	mock.ExpectQuery(`(?i)FROM\s+public\.manifests`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "api_version", "kind", "namespace", "name", "description",
			"labels", "active", "version", "spec", "checksum", "created_at", "updated_at",
		}))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ops/surfaces/github/configure-context", nil)
	r.SetPathValue("id", "github")
	w := httptest.NewRecorder()
	s.handleOpsSurfaceConfigureContext(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"surface"`) || !strings.Contains(body, `"surface_id"`) {
		t.Errorf("missing surface envelope: %s", body)
	}
	if !strings.Contains(body, `"display_name"`) {
		t.Errorf("missing display_name: %s", body)
	}
}
