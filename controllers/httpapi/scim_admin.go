package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type scimClientCreateRequest struct {
	Slug        string            `json:"slug"`
	Permissions map[string]string `json:"permissions"`
	TTLHours    int               `json:"ttl_hours,omitempty"`
}

type scimClientCreateResponse struct {
	Slug        string     `json:"slug"`
	BearerToken string     `json:"bearer_token"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// handleSCIMClientCreate provisions a new SCIM bearer token for a downstream SP
// (GH Enterprise, AWS Identity Center, Slack). The plaintext token is returned
// once; only its SHA-256 is persisted. Defaults: read-only on Users + Groups.
func (s *Server) handleSCIMClientCreate(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var req scimClientCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if req.Slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug required"})
		return
	}
	if req.Permissions == nil {
		req.Permissions = map[string]string{"users": "read", "groups": "read"}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeMappedError(w, err)
		return
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var expiresAt *time.Time
	if req.TTLHours > 0 {
		t := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
		expiresAt = &t
	}

	client, err := repository.CreateSCIMClient(r.Context(), s.db, req.Slug, hash, req.Permissions, expiresAt)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, scimClientCreateResponse{
		Slug:        client.Slug,
		BearerToken: token,
		ExpiresAt:   client.ExpiresAt,
	})
}

// handleSCIMClientList returns the list of registered SCIM clients (without
// any bearer hashes). `?include_revoked=true` shows revoked entries.
func (s *Server) handleSCIMClientList(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	include := r.URL.Query().Get("include_revoked") == "true"
	clients, err := repository.ListSCIMClients(r.Context(), s.db, include)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if clients == nil {
		writeJSON(w, http.StatusOK, map[string]any{"scim_clients": []any{}})
		return
	}
	// Defense-in-depth: never echo bearer hashes outwards.
	out := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		out = append(out, map[string]any{
			"slug":         c.Slug,
			"permissions":  c.Permissions,
			"created_at":   c.CreatedAt,
			"last_used_at": c.LastUsedAt,
			"expires_at":   c.ExpiresAt,
			"revoked_at":   c.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"scim_clients": out})
}

// requireSCIMSlug centralizes the not-empty check so callers don't drift.
func requireSCIMSlug(slug string) error {
	if slug == "" {
		return errors.New("slug required")
	}
	return nil
}
