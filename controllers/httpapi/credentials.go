package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
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

// handleSetupCommit — POST /api/v1/auth/passwords/setup
//
// Atomically redeems a single-use setup token, sets the collaborator's password,
// optionally updates profile fields, emits an audit event, commits the transaction,
// then opens a new auth session outside the transaction and returns it to the caller.
//
// Session creation is intentionally deferred until after the Tx commits: this
// avoids holding a session-side write lock inside the same serializable Tx and
// mirrors the pattern used by handleAuthLogin. The only risk is a partial failure
// (token consumed, session not created) on a fatal DB error after Commit, which is
// acceptable because the collaborator can contact support.
//
// MFA enrollment: the handler does NOT require MFA to already be enrolled (this is
// the bootstrap path). The response carries mfa_enrollment_required=true when the
// collaborator has never enrolled, so the client can redirect to /api/v1/auth/mfa/enroll.
func (s *Server) handleSetupCommit(w http.ResponseWriter, r *http.Request) {
	// Read body once; we need to decode twice.
	bodyBytes, err := readAndCloseBody(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Primary decode into typed struct.
	var req model.PasswordSetupRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Whitelist-validate profile keys via secondary decode into map.
	if extras := unknownSetupProfileFields(bodyBytes); len(extras) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"code":     "setup_unknown_fields",
			"rejected": extras,
		})
		return
	}

	if strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "token_required"})
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "password_required"})
		return
	}

	// Quick length pre-check before touching the DB.
	minLen := envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12)
	if len(req.NewPassword) < minLen {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"code":   "password_too_weak",
			"reason": "too_short",
		})
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Step 1: Consume the token atomically.
	tokenHash := password.HashToken(req.Token)
	row := tx.QueryRowContext(r.Context(), `
		UPDATE auth_credential_tokens
		SET consumed_at = NOW()
		WHERE token_hash = $1
		  AND purpose = 'setup'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()
		RETURNING id, collaborator_id, expires_at
	`, tokenHash)
	var tokenID, collabID uuid.UUID
	var expiresAt time.Time
	if err := row.Scan(&tokenID, &collabID, &expiresAt); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "setup_token_invalid"})
		return
	}

	// Step 2: Load collaborator to build user-token list for password policy.
	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 3: Full policy check with user tokens.
	commonPasswords, _ := commonPasswordsCached()
	userTokens := []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}
	if err := password.ValidateStrength(req.NewPassword, minLen, commonPasswords, userTokens); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"code":   "password_too_weak",
			"reason": err.Error(),
		})
		return
	}

	// Step 4: Hash the password.
	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 5 + 6: Update auth_identities with hash + expiry.
	rotation := envDurationCred("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)
	if _, err := tx.ExecContext(r.Context(), `
		UPDATE auth_identities
		SET password_hash        = $2,
		    password_scheme      = $3,
		    password_updated_at  = NOW(),
		    password_expires_at  = NOW() + $4::interval,
		    password_must_change = false
		WHERE collaborator_id = $1
	`, collabID, hash, string(scheme), rotation.String()); err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 7: Optionally update collaborator profile.
	if req.Profile != nil {
		var setParts []string
		args := []any{collabID}
		if req.Profile.DisplayName != nil {
			args = append(args, *req.Profile.DisplayName)
			setParts = append(setParts, fmt.Sprintf("display_name = $%d", len(args)))
		}
		if req.Profile.Timezone != nil {
			args = append(args, *req.Profile.Timezone)
			setParts = append(setParts, fmt.Sprintf("timezone = $%d", len(args)))
		}
		if req.Profile.PersonalData != nil {
			pd, _ := json.Marshal(req.Profile.PersonalData)
			args = append(args, string(pd))
			setParts = append(setParts, fmt.Sprintf("personal_data = personal_data || $%d::jsonb", len(args)))
		}
		if len(setParts) > 0 {
			q := "UPDATE collaborators SET " + strings.Join(setParts, ", ") + " WHERE id = $1"
			if _, err := tx.ExecContext(r.Context(), q, args...); err != nil {
				writeMappedError(w, err)
				return
			}
		}
	}

	// Step 9: Emit audit event inside the transaction.
	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCredentialPasswordSetupCompleted,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collabID.String(),
		Actor: &model.EventActor{
			Type: "collaborator",
			ID:   collabID.String(),
		},
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"token_id":        tokenID.String(),
			"source":          "setup",
			"ip":              r.RemoteAddr,
			"user_agent":      r.UserAgent(),
		},
	})

	// Step 10: Commit.
	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	// Step 8/11: Open session OUTSIDE the committed transaction, then re-fetch collaborator
	// to pick up any profile changes made inside the Tx.
	sessionMeta := mergeAuthMetadata(nil, r)
	session, sessionToken, err := repository.CreateAuthSession(r.Context(), s.db, collabID, sessionMeta, authSessionTTL())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	collab, _ = repository.GetCollaborator(r.Context(), s.db, collabID.String())
	identity, _ := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collabID)

	needsMFA := identity.MFAEnrolledAt == nil

	resp := map[string]any{
		"session":                 session,
		"token":                   sessionToken,
		"collaborator":            collab,
		"mfa_enrollment_required": needsMFA,
	}
	if needsMFA {
		resp["mfa_enroll_url"] = "/api/v1/auth/mfa/enroll"
	}

	writeAuthCookie(w, sessionToken, session.ExpiresAt)
	writeJSON(w, http.StatusOK, resp)
}

// readAndCloseBody reads the entire request body and closes it.
func readAndCloseBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// unknownSetupProfileFields decodes only the "profile" key from raw JSON into a
// map and returns any keys that are NOT in the allowed whitelist.
func unknownSetupProfileFields(body []byte) []string {
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil
	}
	raw, ok := outer["profile"]
	if !ok {
		return nil
	}
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(raw, &profile); err != nil {
		return nil
	}
	allowed := map[string]struct{}{
		"display_name":  {},
		"timezone":      {},
		"personal_data": {},
	}
	var extras []string
	for k := range profile {
		if _, ok := allowed[k]; !ok {
			extras = append(extras, k)
		}
	}
	return extras
}

// commonPasswordsCached loads the common-password list from disk (lazy, best-effort).
// Returns an empty map when the file is absent so callers can proceed without blacklist.
func commonPasswordsCached() (map[string]struct{}, error) {
	path := os.Getenv("AUTH_PASSWORD_COMMON_LIST_PATH")
	if path == "" {
		path = "internal/auth/password/common_top1000.txt"
	}
	return password.LoadCommonPasswords(path)
}

// envIntCred reads an integer environment variable, returning def when absent or invalid.
func envIntCred(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
