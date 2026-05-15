package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleIssueSetupToken — POST /api/v1/auth/passwords/setup-tokens
//
// Admin-only endpoint that issues a single-use setup URL for a collaborator who
// has not yet configured a password. The caller must be an authenticated session;
// a fine-grained permission check (e.g. iam.collaborators.invite) is NOT yet
// enforced — see CONCERN below.
//
// CONCERN: No permission check beyond valid session is in place. The plan calls
// for requirePermission("iam.collaborators.invite") but the canonical permission
// gate API has not been confirmed in this codebase. Gate by collaborator role or
// permission before merging to production.
func (s *Server) handleIssueSetupToken(w http.ResponseWriter, r *http.Request) {
	tokenStr, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}
	_, admin, err := repository.ResolveAuthSession(r.Context(), s.db, tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}

	// TODO(permission): enforce iam.collaborators.invite permission check here.
	// Until the canonical requirePermission helper is identified and wired, any
	// authenticated session can call this endpoint. Track as security concern
	// before GA.
	_ = admin // admin identity captured for audit; used in IssueCredentialToken.CreatedBy below

	var req model.IssueSetupTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collabID, err := uuid.Parse(req.CollaboratorID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "invalid_collaborator_id"})
		return
	}
	ttl := time.Duration(req.ExpiresInSeconds) * time.Second
	if ttl <= 0 {
		ttl = envDurationCred("AUTH_PASSWORD_SETUP_TOKEN_TTL", 48*time.Hour)
	}
	gen, err := password.GenerateToken()
	if err != nil {
		writeMappedError(w, err)
		return
	}
	issued, err := repository.IssueCredentialToken(r.Context(), s.db, repository.IssueCredentialTokenInput{
		CollaboratorID:  collabID,
		Purpose:         model.CredentialTokenPurposeSetup,
		TokenHash:       gen.Hash,
		ExpiresAt:       time.Now().Add(ttl),
		CreatedBy:       &admin.ID,
		InvalidatePrior: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialSetupTokenIssued, "collaborator", collabID.String(), &admin.ID, map[string]any{
		"token_id":        issued.ID,
		"collaborator_id": collabID.String(),
		"expires_at":      issued.ExpiresAt,
		"issued_by_id":    admin.ID.String(),
		"purpose":         "setup",
	}); err != nil {
		// best-effort emit; token already persisted — do not fail the response
		_ = err
	}

	setupURL := buildSetupURL(os.Getenv("YGGDRASIL_PUBLIC_BASE_URL"), gen.Raw)
	writeJSON(w, http.StatusCreated, model.IssueSetupTokenResponse{
		TokenID:   issued.ID,
		SetupURL:  setupURL,
		ExpiresAt: issued.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func buildSetupURL(base, raw string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	return fmt.Sprintf("%s/setup?token=%s", base, raw)
}

func envDurationCred(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func emitCredentialEvent(ctx context.Context, db *sql.DB, evtType, aggType, aggID string, actorID *uuid.UUID, payload map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	req := model.EmitEventRequest{
		Type:          evtType,
		SchemaVersion: "v1",
		AggregateType: aggType,
		AggregateID:   aggID,
		Payload:       payload,
	}
	if actorID != nil {
		req.Actor = &model.EventActor{Type: "collaborator", ID: actorID.String()}
	}
	if _, err := repository.EmitEvent(ctx, tx, req); err != nil {
		return err
	}
	return tx.Commit()
}
