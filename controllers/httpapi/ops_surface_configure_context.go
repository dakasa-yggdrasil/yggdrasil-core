package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Phase 6 aggregator — audit 2026-05-27 §2.4.
//
// OpsIntegrationsPage detail panel previously fired THREE sequential
// dependent queries to render ONE integration's configure form:
//
//   1. getManifest(surface)              — surface manifest (cached row)
//   2. listOpsIntegrationCatalog()       — full catalog tree (so the FE can
//                                          find the entry slug matching `surface`)
//   3. getOpsIntegrationCatalogEntry(...) — entry details + integration_type
//                                          manifest (the schema-bearing manifest)
//
// Query 3 DEPENDS on query 2's data; parallelization is impossible with
// the current API shape. The aggregate below performs the same matching
// server-side (one catalog walk) and returns the merged result in one
// response.
//
// Permission gate: yggdrasil:view_integrations.

type opsSurfaceConfigureContext struct {
	Surface                 *opsSurfaceConfigureSurface         `json:"surface,omitempty"`
	CatalogEntry            *model.IntegrationCatalogEntry      `json:"catalog_entry,omitempty"`
	IntegrationTypeManifest *model.Manifest                     `json:"integration_type_manifest,omitempty"`
	CurrentInstance         *model.Manifest                     `json:"current_instance,omitempty"`
}

// opsSurfaceConfigureSurface is the trimmed surface metadata the FE
// needs to render the modal heading + the data-driven SchemaForm
// (the full manifest blob is exposed via `Raw` for any view-kind
// switching the FE still does).
type opsSurfaceConfigureSurface struct {
	SurfaceID      string          `json:"surface_id"`
	SurfaceVersion string          `json:"surface_version"`
	DisplayName    string          `json:"display_name"`
	Icon           string          `json:"icon,omitempty"`
	Description    string          `json:"description,omitempty"`
	Health         string          `json:"health,omitempty"`
	Raw            json.RawMessage `json:"raw,omitempty"`
}

// handleOpsSurfaceConfigureContext serves the aggregate.
//
// Resolution order:
//   1. Surface manifest by id (cached in surface_manifests).
//   2. Walk integration catalog looking for an entry whose plugin name
//      or domain/entry matches the surface id.
//   3. If matched, load the integration_type manifest (schema bearer).
//   4. If an integration_instance exists for this type, load it.
//
// Missing surface → 404. Missing catalog match → returns the surface
// alone (the FE can still show the form using fallback fields). Missing
// instance → null `current_instance` (modal renders an empty form).
func (s *Server) handleOpsSurfaceConfigureContext(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}

	var resp opsSurfaceConfigureContext

	// 1. Surface manifest. 404 when not present.
	surfaceRow, err := repository.GetSurfaceManifest(ctx, s.db, id)
	if errors.Is(err, repository.ErrSurfaceManifestNotFound) {
		writeJSONError(w, http.StatusNotFound, "surface not found")
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if len(bytes.TrimSpace(surfaceRow.Raw)) == 0 {
		writeJSONError(w, http.StatusNotFound, "surface not found")
		return
	}
	resp.Surface = &opsSurfaceConfigureSurface{
		SurfaceID:      surfaceRow.SurfaceID,
		SurfaceVersion: surfaceRow.SurfaceVersion,
		DisplayName:    surfaceRow.DisplayName,
		Icon:           surfaceRow.Icon,
		Description:    surfaceRow.Description,
		Health:         surfaceHealthForConsole(surfaceRow.Health),
		Raw:            json.RawMessage(surfaceRow.Raw),
	}

	// 2. Catalog walk. Server-side replacement of the FE's
	// catalogEntryForSurface() — the surface id might be exactly the
	// entry/plugin name, or contain a substring match (e.g. "github" is
	// in the surface id but the catalog plugin is "github-actions").
	// Match strategy: prefer exact plugin_name == surfaceID, then exact
	// entry == surfaceID, then case-insensitive substring on plugin_name.
	domains, listErr := messagecontroller.ListIntegrationCatalog(ctx, s.db, model.ListIntegrationCatalogRequest{})
	if listErr == nil {
		entry, found := matchCatalogEntryForSurface(domains, id)
		if found {
			entryCopy := entry
			resp.CatalogEntry = &entryCopy

			// 3. Integration type manifest. The catalog entry already
			// carries a ManifestReference; resolve the full manifest body
			// (where the schema lives).
			typeManifest, err := repository.GetManifestByID(ctx, s.db, entry.IntegrationType.ID)
			if err == nil {
				typeCopy := typeManifest
				resp.IntegrationTypeManifest = &typeCopy
			}

			// 4. Current integration_instance for this type, if any.
			// The catalog entry's Instances list is the ground truth.
			if len(entry.Instances) > 0 {
				first := entry.Instances[0]
				if instance, err := repository.GetManifestByID(ctx, s.db, first.IntegrationInstance.ID); err == nil {
					instanceCopy := instance
					resp.CurrentInstance = &instanceCopy
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// matchCatalogEntryForSurface picks the catalog entry that best
// describes a given surface id. Strategy mirrors the FE's
// catalogEntryForSurface() so behaviour is preserved across the move.
func matchCatalogEntryForSurface(domains []model.IntegrationCatalogDomain, surfaceID string) (model.IntegrationCatalogEntry, bool) {
	target := strings.ToLower(strings.TrimSpace(surfaceID))
	if target == "" {
		return model.IntegrationCatalogEntry{}, false
	}

	// Pass 1: exact plugin_name.
	for _, d := range domains {
		for _, sec := range d.Sections {
			for _, e := range sec.Entries {
				if strings.EqualFold(e.PluginName, target) {
					return e, true
				}
			}
		}
	}
	// Pass 2: exact entry slug.
	for _, d := range domains {
		for _, sec := range d.Sections {
			for _, e := range sec.Entries {
				if strings.EqualFold(e.Entry, target) {
					return e, true
				}
			}
		}
	}
	// Pass 3: substring (left edge or middle) on the plugin name.
	for _, d := range domains {
		for _, sec := range d.Sections {
			for _, e := range sec.Entries {
				plugin := strings.ToLower(e.PluginName)
				if plugin != "" && strings.Contains(target, plugin) {
					return e, true
				}
			}
		}
	}
	return model.IntegrationCatalogEntry{}, false
}
