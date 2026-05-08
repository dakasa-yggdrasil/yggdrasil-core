package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// handlePermissionRegister registers (or upserts) one permission in the
// global catalog. Integrations call this on install.
func (s *Server) handlePermissionRegister(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeMappedError(w, fmt.Errorf("name is required"))
		return
	}
	if strings.TrimSpace(req.RegisteredBy) == "" {
		writeMappedError(w, fmt.Errorf("registered_by is required"))
		return
	}
	perm, err := repository.RegisterPermission(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permission": perm})
}

// handlePermissionList lists registered permissions with optional filters.
func (s *Server) handlePermissionList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	perms, err := repository.ListPermissions(r.Context(), s.db, model.ListPermissionsRequest{
		RegisteredBy: strings.TrimSpace(q.Get("registered_by")),
		NamePrefix:   strings.TrimSpace(q.Get("name_prefix")),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

// handlePermissionBindingCreate maps role → permission idempotently.
func (s *Server) handlePermissionBindingCreate(w http.ResponseWriter, r *http.Request) {
	var req model.BindRoleToPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.Role) == "" {
		writeMappedError(w, fmt.Errorf("role is required"))
		return
	}
	if strings.TrimSpace(req.PermissionName) == "" {
		writeMappedError(w, fmt.Errorf("permission_name is required"))
		return
	}
	binding, err := repository.BindRoleToPermission(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"binding": binding})
}

// handlePermissionBindingList lists role bindings with optional filters.
func (s *Server) handlePermissionBindingList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bindings, err := repository.ListBindings(r.Context(), s.db, model.ListBindingsRequest{
		Role:           strings.TrimSpace(q.Get("role")),
		PermissionName: strings.TrimSpace(q.Get("permission_name")),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": bindings})
}

// handlePermissionEvaluate decides whether a (role, teams) subject has a
// permission. Used by middlewares + surfaces to gate actions.
func (s *Server) handlePermissionEvaluate(w http.ResponseWriter, r *http.Request) {
	var req model.EvaluatePermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.Permission) == "" {
		writeMappedError(w, fmt.Errorf("permission is required"))
		return
	}
	resp, err := repository.EvaluatePermission(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
