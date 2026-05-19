package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleIssueSetupToken — POST /api/v1/auth/passwords/setup-tokens
//
// Admin-only endpoint that issues a single-use setup URL for a collaborator who
// has not yet configured a password. The caller must supply the static admin
// token via X-Yggdrasil-Auth-Admin-Token header or as a Bearer token matching
// YGGDRASIL_AUTH_ADMIN_TOKEN — the same gate used by all other admin endpoints.
func (s *Server) handleIssueSetupToken(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

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
		CreatedBy:       nil,
		InvalidatePrior: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialSetupTokenIssued, "collaborator", collabID.String(), nil, map[string]any{
		"token_id":        issued.ID,
		"collaborator_id": collabID.String(),
		"expires_at":      issued.ExpiresAt,
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

// handlePasswordChange — POST /api/v1/auth/passwords/change
//
// Authenticated endpoint that allows a collaborator to change their own password
// while proving liveness via MFA inline. Steps:
//  1. Resolve bearer session → collaborator.
//  2. Verify current_password.
//  3. Enforce MFA enrolled; verify supplied factor (totp_code, recovery_code, or
//     webauthn_assertion). WebAuthn inline assertion is not yet implemented
//     (Phase 2); supplying webauthn_assertion returns 501.
//  4. Validate new password strength.
//  5. Reject new == current.
//  6. In a transaction: update hash, revoke other sessions, emit event.
//  7. Return {password_updated_at, password_expires_at}.
//
// Header X-Yggdrasil-Rotation-Triggered: true sets event source = "rotation"
// (default "voluntary").
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	tokenStr, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}
	session, collab, err := repository.ResolveAuthSession(r.Context(), s.db, tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		return
	}

	var req model.PasswordChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 2: verify current password.
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_current_password"})
		return
	}

	// Step 3: MFA gate.
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collab.ID); err != nil {
		if errors.Is(err, mfa.ErrMFANotEnrolled) {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{"code": "mfa_not_enrolled"})
			return
		}
		writeMappedError(w, err)
		return
	}
	if err := s.verifyInlineMFAFactor(r, collab.ID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		if errors.Is(err, errMFANotSupplied) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_mfa"})
			return
		}
		if errors.Is(err, errWebAuthnNotImplemented) {
			writeJSON(w, http.StatusNotImplemented, map[string]any{"code": "webauthn_not_implemented"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_mfa"})
		return
	}

	// Step 4: validate new password strength.
	minLen := envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12)
	commonPasswords, _ := commonPasswordsCached()
	if err := password.ValidateStrength(req.NewPassword, minLen, commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": "password_too_weak", "reason": err.Error()})
		return
	}

	// Step 5: reject if new == current.
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.NewPassword); err == nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": "password_unchanged"})
		return
	}

	// Step 6: hash new password.
	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	rotation := envDurationCred("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)

	// Step 6 (continued): transactional update.
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

	if _, err := tx.ExecContext(r.Context(), `
		UPDATE auth_identities
		SET password_hash        = $2,
		    password_scheme      = $3,
		    password_updated_at  = NOW(),
		    password_expires_at  = NOW() + $4::interval,
		    password_must_change = false
		WHERE collaborator_id = $1
	`, collab.ID, hash, string(scheme), rotation.String()); err != nil {
		writeMappedError(w, err)
		return
	}

	// Revoke all other active sessions; keep the current one intact.
	if _, err := tx.ExecContext(r.Context(), `
		UPDATE auth_sessions
		SET status     = 'revoked',
		    revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND id             <> $2
		  AND revoked_at IS NULL
	`, collab.ID, session.ID); err != nil {
		writeMappedError(w, err)
		return
	}

	source := "voluntary"
	if strings.EqualFold(r.Header.Get("X-Yggdrasil-Rotation-Triggered"), "true") {
		source = "rotation"
	}
	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCredentialPasswordChanged,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Actor:         &model.EventActor{Type: "collaborator", ID: collab.ID.String()},
		Payload: map[string]any{
			"collaborator_id": collab.ID.String(),
			"source":          source,
			"ip":              r.RemoteAddr,
		},
	})

	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	// Step 7: respond with updated credential state.
	state, _ := repository.GetPasswordCredentialState(r.Context(), s.db, collab.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"password_updated_at": state.PasswordUpdatedAt,
		"password_expires_at": state.PasswordExpiresAt,
	})
}

// handlePasswordForgot — POST /api/v1/auth/passwords/forgot
//
// Public, anti-enumeration endpoint for initiating a password reset. ALWAYS
// responds 202 with the same body regardless of whether the identifier exists,
// a rate-limit was hit, the body was malformed, or any internal error occurred.
// This prevents account enumeration.
//
// Flow:
//  1. Decode body → identifier (email or slug).
//  2. LookupCollaboratorByIdentifier — returns (nil, nil) on no match.
//  3. If matched and rate-limit free: GenerateToken + IssueCredentialToken
//     (purpose=reset, TTL=24h, InvalidatePrior=true) + emit best-effort event.
//  4. Return 202 unconditionally.
func (s *Server) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	const acceptedBody = `{"status":"if_account_exists_token_was_generated"}`
	respondAccepted := func() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(acceptedBody))
	}

	var req model.PasswordForgotRequest
	if err := decodeJSON(r, &req); err != nil {
		respondAccepted()
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		respondAccepted()
		return
	}

	collab, err := repository.LookupCollaboratorByIdentifier(r.Context(), s.db, identifier)
	if err != nil || collab == nil {
		respondAccepted()
		return
	}

	rlKey := "forgot:" + strings.ToLower(identifier)
	maxPerHour := envIntCred("AUTH_PASSWORD_FORGOT_RATE_LIMIT_PER_HOUR", 3)
	if err := enforceForgotRateLimit(r.Context(), s.db, rlKey, maxPerHour, time.Hour); err != nil {
		respondAccepted()
		return
	}

	gen, err := password.GenerateToken()
	if err != nil {
		respondAccepted()
		return
	}
	ttl := envDurationCred("AUTH_PASSWORD_RESET_TOKEN_TTL", 24*time.Hour)
	issued, err := repository.IssueCredentialToken(r.Context(), s.db, repository.IssueCredentialTokenInput{
		CollaboratorID:  collab.ID,
		Purpose:         model.CredentialTokenPurposeReset,
		TokenHash:       gen.Hash,
		ExpiresAt:       time.Now().Add(ttl),
		InvalidatePrior: true,
		CreatedBy:       nil,
		Metadata:        map[string]any{"rl_key": rlKey},
	})
	if err == nil {
		_ = emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialResetTokenIssued, "collaborator", collab.ID.String(), nil, map[string]any{
			"token_id":        issued.ID,
			"collaborator_id": collab.ID.String(),
			"expires_at":      issued.ExpiresAt,
			"source":          "self_service",
			"purpose":         "reset",
		})
	}

	respondAccepted()
}

// handlePasswordReset — POST /api/v1/auth/passwords/reset
//
// Public endpoint that completes a password-reset flow initiated by handlePasswordForgot.
// Steps:
//  1. Decode body → token, new_password, MFA factor.
//  2. Consume the reset token (atomic, single-use).
//  3. Enforce MFA enrolled; verify supplied factor (totp_code or recovery_code).
//  4. Load collaborator profile for password-policy user tokens.
//  5. Validate new password strength.
//  6. In a transaction: update password hash, revoke ALL active sessions (total
//     revoke — no current session to preserve), emit audit event.
//  7. Outside Tx: open a brand-new auth session.
//  8. Return {session, token, collaborator}.
func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req model.PasswordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 2: consume the reset token atomically.
	tokenHash := password.HashToken(req.Token)
	out, err := repository.ConsumeCredentialToken(r.Context(), s.db, repository.ConsumeCredentialTokenInput{
		TokenHash: tokenHash, Purpose: model.CredentialTokenPurposeReset,
	})
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "reset_token_invalid"})
		return
	}
	collabID, _ := uuid.Parse(out.CollaboratorID)

	// Step 3: MFA gate.
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collabID); err != nil {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"code": "mfa_not_enrolled"})
		return
	}
	if err := s.verifyInlineMFAFactor(r, collabID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		if errors.Is(err, errWebAuthnNotImplemented) {
			writeJSON(w, http.StatusNotImplemented, map[string]any{"code": "webauthn_not_implemented"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_mfa"})
		return
	}

	// Step 4: load collaborator for password-policy user tokens.
	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 5: validate new password strength.
	commonPasswords, _ := commonPasswordsCached()
	if err := password.ValidateStrength(req.NewPassword, envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12), commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": "password_too_weak", "reason": err.Error()})
		return
	}

	// Step 6: hash new password.
	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	rotation := envDurationCred("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)

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

	// Revoke ALL active sessions — total revoke (user has no current session during recovery).
	if _, err := tx.ExecContext(r.Context(), `
		UPDATE auth_sessions
		SET status     = 'revoked',
		    revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND revoked_at IS NULL
	`, collabID); err != nil {
		writeMappedError(w, err)
		return
	}

	_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCredentialPasswordChanged,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collabID.String(),
		Actor:         &model.EventActor{Type: "collaborator", ID: collabID.String()},
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"source":          "reset",
			"ip":              r.RemoteAddr,
		},
	})

	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	// Step 7: open new session OUTSIDE the committed Tx (same pattern as handleSetupCommit).
	sessionMeta := mergeAuthMetadata(nil, r)
	session, sessionToken, err := repository.CreateAuthSession(r.Context(), s.db, collabID, sessionMeta, authSessionTTL())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeAuthCookie(w, sessionToken, session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"session":      session,
		"token":        sessionToken,
		"collaborator": collab,
	})
}

// sentinel errors used by verifyInlineMFAFactor.
var (
	errMFANotSupplied         = errors.New("no mfa factor supplied")
	errWebAuthnNotImplemented = errors.New("webauthn inline assertion not yet implemented (Phase 2)")
)

// verifyInlineMFAFactor verifies the first non-empty MFA factor supplied in the
// request against the stored credentials for collabID. It is a method on
// *Server so it can access s.db and s.envelope.
//
// Priority: totp_code > recovery_code > webauthn_assertion.
// If none are supplied, errMFANotSupplied is returned.
// WebAuthn inline assertion is a Phase 2 feature; supplying webauthn_assertion
// returns errWebAuthnNotImplemented.
func (s *Server) verifyInlineMFAFactor(
	r *http.Request,
	collabID uuid.UUID,
	totpCode, recoveryCode string,
	webauthnAssertion map[string]any,
) error {
	totpCode = strings.TrimSpace(totpCode)
	recoveryCode = strings.TrimSpace(recoveryCode)

	if totpCode != "" {
		if s.envelope == nil {
			return fmt.Errorf("TOTP verification unavailable: KEK not configured")
		}
		secret, err := repository.GetTOTPSecret(r.Context(), s.db, s.envelope, collabID)
		if err != nil {
			return fmt.Errorf("get totp secret: %w", err)
		}
		return mfa.ValidateTOTP(string(secret), totpCode)
	}

	if recoveryCode != "" {
		return repository.VerifyAndInvalidateRecoveryCode(r.Context(), s.db, collabID, recoveryCode)
	}

	// webauthn_assertion path: blocked until Phase 2 (inline assertion verify).
	// Return a distinct sentinel so the caller can surface 501 instead of 401.
	if webauthnAssertion != nil {
		return errWebAuthnNotImplemented
	}

	// No factor supplied at all.
	return errMFANotSupplied
}

