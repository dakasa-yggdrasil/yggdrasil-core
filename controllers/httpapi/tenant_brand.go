package httpapi

import (
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func (s *Server) handleTenantBrandGet(w http.ResponseWriter, r *http.Request) {
	brand, err := repository.GetTenantBrand(r.Context(), s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"brand": brand})
}

func (s *Server) handleTenantBrandPatch(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		writeMappedError(w, err)
		return
	}

	if !canManageTenantBrand(collaborator) {
		writeJSONError(w, http.StatusForbidden, "organization settings require admin access")
		return
	}

	var req model.UpdateTenantBrandRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	brand, err := repository.UpdateTenantBrand(r.Context(), s.db, req, collaborator.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"brand": brand})
}

func canManageTenantBrand(collaborator model.Collaborator) bool {
	for _, role := range collectOrganizationRoles(collaborator) {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "owner", "director", "tenant-admin", "org-admin", "organization-admin":
			return true
		}
	}
	return false
}

func collectOrganizationRoles(collaborator model.Collaborator) []string {
	roles := make([]string, 0, 8)
	roles = appendRoleValue(roles, collaborator.Traits["tartaro_roles"])
	roles = appendRoleValue(roles, collaborator.Traits["roles"])
	roles = appendRoleValue(roles, collaborator.Traits["role"])
	roles = appendRoleValue(roles, collaborator.EmploymentData["role"])
	roles = appendRoleValue(roles, collaborator.Metadata["roles"])
	roles = appendRoleValue(roles, collaborator.Metadata["role"])
	return roles
}

func appendRoleValue(out []string, value any) []string {
	switch v := value.(type) {
	case string:
		return append(out, splitRoleString(v)...)
	case []string:
		return append(out, v...)
	case []any:
		for _, item := range v {
			out = appendRoleValue(out, item)
		}
	}
	return out
}

func splitRoleString(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
