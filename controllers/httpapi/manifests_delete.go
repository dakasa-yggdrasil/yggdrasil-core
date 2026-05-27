package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleManifestDelete removes a manifest by id.
//
// URL: DELETE /api/v1/manifests/{id}
// Query: ?soft=true flips active=FALSE on every version sharing the
// (kind, namespace, name) of the given id, preserving history. Default
// (soft absent/false) hard-deletes every such row from the manifests
// table.
//
// Auth: deferred to authorizeWorkflowRunRequest, same env-token guard
// that protects POST /api/v1/workflow-runs and POST /api/v1/events. When
// YGGDRASIL_WORKFLOW_RUN_TOKEN is unset (dev / tests) the endpoint is
// open — same convention as those neighbours so adopters don't need to
// learn a new auth flow for a destructive op.
//
// Idempotency: a request that targets an already-absent id returns 200
// with {"deleted": true, "already_absent": true}. This matches the
// recent not_found normalisation work and lets the periodic purge job
// safely re-issue a delete after a crash without partial-failure noise.
//
// Audit: every outcome (success, already_absent, error) emits an
// audit row keyed on action=manifest.delete so operators can replay
// what was removed and by whom from the audit_log table.
func (s *Server) handleManifestDelete(w http.ResponseWriter, r *http.Request) {
	// Auth gate: accept either YGGDRASIL_WORKFLOW_RUN_TOKEN (workflow caller)
	// or a valid console session — matches the POST /api/v1/manifests
	// auth posture (security audit 2026-05-27 A1).
	if !s.manifestWriteAuthorized(r) {
		writeMappedError(w, errWorkflowRunUnauthorized)
		return
	}

	rawID := strings.TrimSpace(r.PathValue("id"))
	if rawID == "" {
		writeJSONError(w, http.StatusBadRequest, "manifest id is required")
		return
	}

	manifestID, err := uuid.Parse(rawID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid manifest id %q: %v", rawID, err))
		return
	}

	soft := queryBool(r, "soft")
	mode := "hard"
	if soft {
		mode = "soft"
	}

	var rowsAffected int64
	if soft {
		rowsAffected, err = repository.MarkManifestInactiveByID(r.Context(), s.db, manifestID)
	} else {
		rowsAffected, err = repository.HardDeleteManifestByID(r.Context(), s.db, manifestID)
	}

	if err != nil {
		// Idempotent: not found means the caller's intent (manifest is
		// gone) already holds. Return 200 with already_absent=true so
		// retry loops in the purge job don't trip on transient races.
		if errors.Is(err, repository.ErrManifestNotFound) {
			s.recordAudit(r, "manifest.delete", "manifest", manifestID.String(),
				"success", map[string]any{"mode": mode, "already_absent": true})
			writeJSON(w, http.StatusOK, map[string]any{
				"deleted":        true,
				"already_absent": true,
				"mode":           mode,
			})
			return
		}
		s.recordAudit(r, "manifest.delete", "manifest", manifestID.String(),
			"error", map[string]any{"mode": mode, "error": err.Error()})
		writeMappedError(w, err)
		return
	}

	s.recordAudit(r, "manifest.delete", "manifest", manifestID.String(),
		"success", map[string]any{"mode": mode, "rows_affected": rowsAffected})

	IncManifestDeleted(mode)

	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":       true,
		"mode":          mode,
		"rows_affected": rowsAffected,
	})
}
