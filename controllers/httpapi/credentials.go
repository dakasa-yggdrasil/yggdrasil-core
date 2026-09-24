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
	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// handleIssueSetupToken — POST /api/v1/auth/passwords/setup-tokens
//
// Admin-only endpoint that issues a single-use setup URL for a collaborator who
// has not yet configured a password. The caller must supply the static admin
// token via X-Yggdrasil-Auth-Admin-Token header or as a Bearer token matching
// YGGDRASIL_AUTH_ADMIN_TOKEN — the same gate used by all other admin endpoints.
func (s *Server) handleIssueSetupToken(w http.ResponseWriter, r *http.Request) {
	principal, err := resolveAuthAdminPrincipal(r, s.db)
	if err != nil {
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
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeInvalidInput,
			"Invalid input",
			"collaborator_id is not a valid UUID",
			httperr.WithInstance(r.URL.Path))
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
	var createdBy *uuid.UUID
	if principal.CollaboratorID != uuid.Nil {
		adminID := principal.CollaboratorID
		createdBy = &adminID
	}
	tokenInput := repository.IssueCredentialTokenInput{
		CollaboratorID:  collabID,
		Purpose:         model.CredentialTokenPurposeSetup,
		TokenHash:       gen.Hash,
		ExpiresAt:       time.Now().Add(ttl),
		CreatedBy:       createdBy,
		InvalidatePrior: true,
	}
	if req.ResetMFA {
		// Read back by the setup preflight so the page greets a returning
		// person, not a first access.
		tokenInput.Metadata = map[string]any{"mfa_reset": true}
	}

	var issued model.CredentialToken
	if req.ResetMFA {
		// Full recovery (lost second factor, with or without the password):
		// the factor and password wipe, the session fan-out, the audit event
		// and the new link commit together, so the account is never left
		// without factors and without a link, or with the old password
		// still opening an enrollment.
		issued, err = s.resetMFAAndIssueSetupLink(r, collabID, tokenInput, principal)
	} else {
		issued, err = repository.IssueCredentialToken(r.Context(), s.db, tokenInput)
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}

	issuedPayload := map[string]any{
		"token_id":        issued.ID,
		"collaborator_id": collabID.String(),
		"expires_at":      issued.ExpiresAt.UTC().Format(time.RFC3339),
		"purpose":         "setup",
	}
	if createdBy != nil {
		issuedPayload["issued_by_id"] = createdBy.String()
	}
	if req.ResetMFA {
		issuedPayload["mfa_reset"] = true
	}
	if err := emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialSetupTokenIssued, "collaborator", collabID.String(), createdBy, issuedPayload); err != nil {
		// Best effort: the token is already persisted and the response must
		// not fail, but a lost audit event has to be visible.
		s.logWarn("credential.setup_token_issued emit failed",
			zap.String("collaborator_id", collabID.String()), zap.Error(err))
	}

	if req.ResetMFA {
		s.dispatchBackchannelLogoutForCollaborator(r.Context(), collabID)
		metadata := map[string]any{
			"source_ip":  clientIP(r),
			"user_agent": r.UserAgent(),
			"source":     "admin_setup_link",
		}
		actor := principal.auditActor()
		safego.SafeGo("audit_auth_mfa_reset", func() {
			_ = s.recordAuthAuditSync(r, actor, AuditAuthMFAReset, collabID.String(), AuditOutcomeSuccess, metadata)
		})
	}

	setupURL := buildSetupURL(os.Getenv("YGGDRASIL_PUBLIC_BASE_URL"), gen.Raw)
	writeJSON(w, http.StatusCreated, model.IssueSetupTokenResponse{
		TokenID:   issued.ID,
		SetupURL:  setupURL,
		ExpiresAt: issued.ExpiresAt.UTC().Format(time.RFC3339),
		MFAReset:  req.ResetMFA,
	})
}

// resetMFAAndIssueSetupLink wipes the collaborator's second factors and
// password, revokes everything opened with them (§13 fan-out), records the
// attributed credential.mfa_reset event and issues the setup link, all in
// one transaction: a factor wipe that is not audited, or that leaves the
// account without a link, must not happen.
func (s *Server) resetMFAAndIssueSetupLink(r *http.Request, collabID uuid.UUID, in repository.IssueCredentialTokenInput, principal authAdminPrincipal) (model.CredentialToken, error) {
	ctx := r.Context()
	collab, err := repository.GetCollaborator(ctx, s.db, collabID.String())
	if err != nil {
		return model.CredentialToken{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.CredentialToken{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// Lock order: the per-collaborator issuance lock, then the setup token
	// rows, then the auth_identities row. handleSetupCommit takes token row
	// then auth_identities and never the issuance lock, so no cycle forms,
	// and two concurrent recoveries run one after the other.
	issued, err := repository.IssueCredentialTokenTx(ctx, tx, in)
	if err != nil {
		return model.CredentialToken{}, err
	}
	// Record whether this wipe actually replaced a credential. The wipe also
	// clears password_updated_at, so afterwards nothing on the account tells
	// a returning person from a new hire; only the issuance can. A full
	// recovery clicked on an account that was never set up stays a first
	// access. Read after the token rows are locked, before auth_identities,
	// to keep handleSetupCommit's lock order.
	prior, err := repository.GetCredentialAccountState(ctx, tx, collabID)
	if err != nil {
		return model.CredentialToken{}, err
	}
	// Same definition of "a credential existed" as handleSetupCommit: a
	// password or an enrolled factor. A TOTP secret from an abandoned
	// enrollment, leftover codes or a passkey without mfa_enrolled_at never
	// opened a session, so wiping them does not make someone a returning user.
	if prior.HasPassword || prior.MFAEnrolled {
		if _, err := tx.ExecContext(ctx,
			`UPDATE auth_credential_tokens SET metadata = metadata || '{"replaced_credential": true}'::jsonb WHERE id = $1`,
			issued.ID); err != nil {
			return model.CredentialToken{}, err
		}
	}
	if err := repository.ResetMFAFactors(ctx, tx, collabID); err != nil {
		return model.CredentialToken{}, err
	}
	if err := s.revokeForCredentialReplacement(ctx, tx, collab, repository.SessionRevocationReasonMFAReset, map[string]any{
		"source": "admin_setup_link",
		"by":     principal.auditActor(),
	}); err != nil {
		return model.CredentialToken{}, err
	}
	payload := map[string]any{
		"collaborator_id": collabID.String(),
		"source":          "admin_setup_link",
	}
	if principal.CollaboratorID != uuid.Nil {
		payload["issued_by_id"] = principal.CollaboratorID.String()
	}
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCredentialMFAReset,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collabID.String(),
		Actor:         principal.eventActor(r),
		Payload:       payload,
	}); err != nil {
		return model.CredentialToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.CredentialToken{}, err
	}
	return issued, nil
}

// revokeForCredentialReplacement is the §13 INTEGRATION_CONTRACT fan-out for
// every path that replaces a credential through a link (setup re-access,
// self-service reset, admin MFA reset): console sessions and OIDC refresh
// tokens are revoked, a global session_revocation row tells introspection
// and adapters, and collaborator.session_terminated is emitted. The caller
// fires the back-channel logout after its commit.
func (s *Server) revokeForCredentialReplacement(ctx context.Context, tx *sql.Tx, collab model.Collaborator, reason string, metadata map[string]any) error {
	if _, err := repository.RevokeAllAuthSessions(ctx, tx, collab.ID); err != nil {
		return err
	}
	rev, err := repository.InsertSessionRevocation(ctx, s.db, tx, repository.InsertSessionRevocationRequest{
		CollaboratorID: collab.ID,
		SessionJTI:     nil,
		Reason:         reason,
		Metadata:       metadata,
	})
	if err != nil {
		return err
	}
	sessionPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
		"reason":          reason,
		"revocation_id":   rev.ID.String(),
		"emitted_at":      time.Now().UTC().Format(time.RFC3339),
	}
	if collab.PrimaryEmail != "" {
		sessionPayload["primary_email"] = collab.PrimaryEmail
	}
	_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:           repository.EventTypeCollaboratorSessionTerminated,
		SchemaVersion:  "v1",
		AggregateType:  "collaborator",
		AggregateID:    collab.ID.String(),
		Payload:        sessionPayload,
		IdempotencyKey: "session.terminated." + rev.ID.String(),
	})
	return err
}

func buildSetupURL(base, raw string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	return fmt.Sprintf("%s/setup?token=%s", base, raw)
}

// setupTokenRejection describes why a setup token is unusable; nil means usable.
// It maps 1:1 onto httperr.WriteProblem so both `preflight` and `commit` produce
// identical wire responses for the same underlying state.
type setupTokenRejection struct {
	status int
	code   string
	title  string
	detail string
	extras map[string]any
}

// rowQuerier is implemented by both *sql.DB and *sql.Tx — lets the lookup run
// inside a transaction (commit path, with FOR UPDATE) or stand-alone (preflight).
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// lookupSetupToken inspects a setup token without consuming it. Pass forUpdate=true
// when the caller is inside a Tx that will mutate the row next; preflight uses
// forUpdate=false to keep the call lock-free.
func lookupSetupToken(ctx context.Context, q rowQuerier, rawToken string, forUpdate bool) (tokenID, collabID uuid.UUID, expiresAt time.Time, rej *setupTokenRejection) {
	tokenHash := password.HashToken(rawToken)
	lockClause := ""
	if forUpdate {
		lockClause = " FOR UPDATE"
	}
	var consumedAt sql.NullTime
	err := q.QueryRowContext(ctx, `
		SELECT id, collaborator_id, expires_at, consumed_at
		FROM auth_credential_tokens
		WHERE token_hash = $1 AND purpose = 'setup'`+lockClause,
		tokenHash).Scan(&tokenID, &collabID, &expiresAt, &consumedAt)
	return classifySetupToken(tokenID, collabID, expiresAt, consumedAt, err)
}

// classifySetupToken maps the lookup outcome of a setup token onto its
// problem response (nil when usable). Split from the query so the mapping is
// testable without a database.
func classifySetupToken(tokenID, collabID uuid.UUID, expiresAt time.Time, consumedAt sql.NullTime, err error) (uuid.UUID, uuid.UUID, time.Time, *setupTokenRejection) {
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, uuid.Nil, time.Time{}, &setupTokenRejection{
			status: http.StatusUnauthorized,
			code:   httperr.CodeAuthSetupTokenInvalid,
			title:  "Invalid setup link",
			detail: "this setup link is not recognised — please request a new one from your administrator",
		}
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, &setupTokenRejection{
			status: http.StatusInternalServerError,
			code:   httperr.CodeInternal,
			title:  "Internal error",
			detail: "failed to load setup token state",
		}
	}
	if consumedAt.Valid {
		return uuid.Nil, uuid.Nil, time.Time{}, &setupTokenRejection{
			status: http.StatusConflict,
			code:   httperr.CodeAuthSetupTokenAlreadyUsed,
			title:  "Setup link already used",
			detail: "this link has already been used and your password is set — sign in with your email and password, or request a password reset if you forgot it",
			extras: map[string]any{"consumed_at": consumedAt.Time.UTC().Format(time.RFC3339)},
		}
	}
	if time.Now().After(expiresAt) {
		return uuid.Nil, uuid.Nil, time.Time{}, &setupTokenRejection{
			status: http.StatusUnauthorized,
			code:   httperr.CodeAuthSetupTokenExpired,
			title:  "Setup link expired",
			detail: "this setup link has expired — please request a new one from your administrator",
			extras: map[string]any{"expired_at": expiresAt.UTC().Format(time.RFC3339)},
		}
	}
	return tokenID, collabID, expiresAt, nil
}

// writeSetupTokenRejection translates a rejection into a problem+json response.
func writeSetupTokenRejection(w http.ResponseWriter, instance string, rej *setupTokenRejection) {
	opts := []httperr.Option{httperr.WithInstance(instance)}
	for k, v := range rej.extras {
		opts = append(opts, httperr.WithExtra(k, v))
	}
	httperr.WriteProblem(w, rej.status, rej.code, rej.title, rej.detail, opts...)
}

// lookupResetToken inspects a self-service reset token without consuming it.
// Every unusable state answers 401 auth.reset_token_invalid (the code the
// console already handles); `reason` tells the page which copy to show.
func lookupResetToken(ctx context.Context, q rowQuerier, rawToken string) (tokenID, collabID uuid.UUID, expiresAt time.Time, rej *setupTokenRejection) {
	var consumedAt sql.NullTime
	err := q.QueryRowContext(ctx, `
		SELECT id, collaborator_id, expires_at, consumed_at
		FROM auth_credential_tokens
		WHERE token_hash = $1 AND purpose = 'reset'`,
		password.HashToken(rawToken)).Scan(&tokenID, &collabID, &expiresAt, &consumedAt)
	return classifyResetToken(tokenID, collabID, expiresAt, consumedAt, err, time.Now())
}

func classifyResetToken(tokenID, collabID uuid.UUID, expiresAt time.Time, consumedAt sql.NullTime, err error, now time.Time) (uuid.UUID, uuid.UUID, time.Time, *setupTokenRejection) {
	invalid := func(reason, detail string) *setupTokenRejection {
		return &setupTokenRejection{
			status: http.StatusUnauthorized,
			code:   httperr.CodeAuthResetTokenInvalid,
			title:  "Invalid reset token",
			detail: detail,
			extras: map[string]any{"reason": reason},
		}
	}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return uuid.Nil, uuid.Nil, time.Time{}, invalid("not_found", "this reset link is not recognised; request a new one")
	case err != nil:
		return uuid.Nil, uuid.Nil, time.Time{}, &setupTokenRejection{
			status: http.StatusInternalServerError,
			code:   httperr.CodeInternal,
			title:  "Internal error",
			detail: "failed to load reset token state",
		}
	case consumedAt.Valid:
		return uuid.Nil, uuid.Nil, time.Time{}, invalid("already_used", "this reset link was already used or replaced by a newer one; request a new one")
	case now.After(expiresAt):
		return uuid.Nil, uuid.Nil, time.Time{}, invalid("expired", "this reset link has expired; request a new one")
	}
	return tokenID, collabID, expiresAt, nil
}

// passwordPolicyView is the part of the password policy a form can check
// live. The identity and common-password rules still run server-side; the
// console mirrors the identity rule from the collaborator fields it gets.
func passwordPolicyView() map[string]any {
	return map[string]any{
		"min_length":          envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12),
		"rejects_identity":    true,
		"rejects_common_list": true,
	}
}

// passwordPolicyReason maps a ValidateStrength error onto the stable
// `reason` the forms translate (too_short / contains_identity / too_common).
func passwordPolicyReason(err error) string {
	switch {
	case errors.Is(err, password.ErrPasswordTooShort):
		return "too_short"
	case errors.Is(err, password.ErrPasswordContainsIdentity):
		return "contains_identity"
	case errors.Is(err, password.ErrPasswordTooCommon):
		return "too_common"
	default:
		return "policy"
	}
}

func writePasswordPolicyProblem(w http.ResponseWriter, instance string, err error) {
	httperr.WriteProblem(w, http.StatusUnprocessableEntity,
		httperr.CodeAuthPasswordTooWeak,
		"Password too weak",
		err.Error(),
		httperr.WithInstance(instance),
		httperr.WithExtra("reason", passwordPolicyReason(err)))
}

// collaboratorIdentityView is what a recovery page shows and what the
// console needs to mirror the "no personal identifiers" rule live.
func collaboratorIdentityView(collab model.Collaborator) map[string]any {
	return map[string]any{
		"id":            collab.ID,
		"display_name":  collab.DisplayName,
		"primary_email": collab.PrimaryEmail,
		"slug":          collab.Slug,
	}
}

// handleSetupPreflight — GET /api/v1/auth/passwords/setup/preflight?token=…
//
// Cheap, read-only check the frontend calls *before* rendering the setup form.
// Lets the UI show "this link was already used, sign in instead" without ever
// asking the user to type a password that will be rejected anyway.
//
// It also reports the account posture so one page can serve both journeys a
// setup link carries: a first access (no password yet) and an admin-issued
// re-access for an existing account (has_password), plus whether the person
// will be asked to enroll a second factor or to sign in with it afterwards.
//
// Does not consume the token. Same authentication model as the POST commit:
// the token is the credential.
func (s *Server) handleSetupPreflight(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("token"))
	if raw == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"token query parameter is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("token", "required", "token is required"))
		return
	}
	_, collabID, expiresAt, rej := lookupSetupToken(r.Context(), s.db, raw, false)
	if rej != nil {
		writeSetupTokenRejection(w, r.URL.Path, rej)
		return
	}
	// Best-effort: fetch the collaborator and credential posture so the UI can
	// greet by name and pick the right journey. If a load fails the preflight
	// still succeeds; the commit will error loudly.
	resp := map[string]any{
		"status":          "ready",
		"expires_at":      expiresAt.UTC().Format(time.RFC3339),
		"password_policy": passwordPolicyView(),
	}
	if collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String()); err == nil {
		resp["collaborator"] = collaboratorIdentityView(collab)
	}
	if st, err := repository.GetCredentialAccountState(r.Context(), s.db, collabID); err == nil {
		// A full-recovery link arrives with no password and no factor, like a
		// brand-new account; `recovery` lets the page greet a returning person
		// as such instead of as a first access.
		//
		// The flag follows the account, not only the presented token: a plain
		// access link issued after a full recovery replaces the recovery link
		// but the person is still returning. It keys on replaced_credential,
		// which a full recovery stamps only when it wiped an existing password
		// or factor, so a recovery clicked on a never-configured account keeps
		// the first-access journey. The person may re-enroll a factor before
		// the password (enroll link, third-party login), so only a password
		// ends the recovery; the console words the rest from mfa_enrolled.
		var recovery bool
		if !st.HasPassword {
			_ = s.db.QueryRowContext(r.Context(), `
				SELECT EXISTS (
					SELECT 1 FROM auth_credential_tokens
					WHERE collaborator_id = $1
					  AND purpose = 'setup'
					  AND metadata @> '{"replaced_credential": true}'::jsonb
				)`, collabID).Scan(&recovery)
		}
		resp["account"] = map[string]any{
			"has_password": st.HasPassword,
			"mfa_enrolled": st.MFAEnrolled,
			"recovery":     recovery,
		}
	}
	writeJSON(w, http.StatusOK, resp)
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
// optionally updates profile fields, revokes older sessions, emits an audit
// event and commits. It never opens a session itself:
//
//   - no second factor enrolled: 428 auth.mfa_not_enrolled with enroll_url
//     (the bootstrap path; the session is issued by the MFA enrollment);
//   - second factor enrolled: 200 {status: password_set, next: login}; the
//     person signs in with the new password and the factor they already have.
//
// A rejected password (422) or an inactive account (403) rolls the
// transaction back, so the link stays usable.
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
		httperr.WriteProblem(w, http.StatusUnprocessableEntity,
			httperr.CodeUnknownFields,
			"Unknown fields",
			"profile contains fields outside the allowed whitelist",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("rejected", extras))
		return
	}

	if strings.TrimSpace(req.Token) == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"token is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("token", "required", "token is required"))
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"new_password is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("new_password", "required", "new_password is required"))
		return
	}

	// Quick length pre-check before touching the DB.
	minLen := envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12)
	if len(req.NewPassword) < minLen {
		httperr.WriteProblem(w, http.StatusUnprocessableEntity,
			httperr.CodeAuthPasswordTooWeak,
			"Password too weak",
			"password does not meet the minimum length requirement",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("reason", "too_short"))
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

	// Step 1: Inspect + consume the token. lookupSetupToken returns identical
	// problem responses to /setup/preflight, so a frontend that already passed
	// preflight will hit this only when there's a true race.
	tokenID, collabID, _, rej := lookupSetupToken(r.Context(), tx, req.Token, true)
	if rej != nil {
		writeSetupTokenRejection(w, r.URL.Path, rej)
		return
	}
	// Mark consumed now — still inside the tx, so any later failure rolls back.
	if _, err := tx.ExecContext(r.Context(),
		`UPDATE auth_credential_tokens SET consumed_at = NOW() WHERE id = $1`,
		tokenID); err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 2: Load collaborator to build user-token list for password policy.
	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 2b: A non-active collaborator (suspended / offboarded) must not
	// complete password setup and receive a session. Reject before writing
	// the credential — the deferred Rollback un-consumes the token, so a
	// re-activated account can still use the same link.
	if !collaboratorEligibleForSetup(collab.Status) {
		httperr.WriteProblem(w, http.StatusForbidden,
			httperr.CodeAuthAccountInactive,
			"Account not active",
			"this account is not active and cannot complete password setup; contact your administrator",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("status", collab.Status))
		return
	}

	// Step 3: Full policy check with user tokens.
	commonPasswords, _ := commonPasswordsCached()
	userTokens := []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}
	if err := password.ValidateStrength(req.NewPassword, minLen, commonPasswords, userTokens); err != nil {
		// Deferred Rollback un-consumes the token: a rejected password never
		// costs the person their link.
		writePasswordPolicyProblem(w, r.URL.Path, err)
		return
	}

	// Step 4: Hash the password.
	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 4b: remember whether this link replaces an existing credential.
	// A re-access (lost password) owes the §13 revocation fan-out; a first
	// access has nothing to revoke and must not emit a spurious
	// session.terminated.
	prior, err := repository.GetCredentialAccountState(r.Context(), tx, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	replacesCredential := prior.HasPassword || prior.MFAEnrolled

	// Step 5 + 6: Update auth_identities with hash + expiry. The lockout is
	// cleared too: the link holder was vouched for by an admin, and an
	// enrolled account is sent straight to the login, where a lockout left
	// over from guessing the forgotten password would refuse them.
	rotation := envDurationCred("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)
	res, err := tx.ExecContext(r.Context(), `
		UPDATE auth_identities
		SET password_hash        = $2,
		    password_scheme      = $3,
		    password_updated_at  = NOW(),
		    password_expires_at  = NOW() + $4::interval,
		    password_must_change = false,
		    failed_attempts      = 0,
		    locked_until         = NULL
		WHERE collaborator_id = $1
	`, collabID, hash, string(scheme), rotation.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Without this check, a missing auth_identity row (provisioning gap) would
	// silently commit with no password written — token consumed, user locked
	// out, no obvious failure. Surface it instead.
	if n, _ := res.RowsAffected(); n == 0 {
		httperr.WriteProblem(w, http.StatusInternalServerError,
			httperr.CodeAuthSetupIdentityMissing,
			"Auth identity missing",
			"no auth identity exists for this collaborator yet — provisioning is incomplete; contact an administrator",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("collaborator_id", collabID.String()))
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

	// Step 8: Sessions and tokens opened with the previous password must not
	// outlive it. On an admin-issued re-access (lost password) this signs
	// every old device and relying party out; a first access has none.
	if replacesCredential {
		if err := s.revokeForCredentialReplacement(r.Context(), tx, collab, repository.SessionRevocationReasonPasswordRotated, map[string]any{
			"source": "setup_link",
			"ip":     r.RemoteAddr,
		}); err != nil {
			writeMappedError(w, err)
			return
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
	if replacesCredential {
		s.dispatchBackchannelLogoutForCollaborator(r.Context(), collabID)
	}

	// Step 11: the setup link never mints a session on its own. A link is
	// possession of a URL, and a URL travels through chat and email; it must
	// not stand in for the second factor.
	//
	//   - No second factor yet (first access, or an admin MFA reset): 428 +
	//     enroll link and NO cookie, mirroring handleAuthLogin. The session
	//     only exists once MFA is enrolled.
	//   - Second factor enrolled (admin-issued re-access for someone who lost
	//     the password): 200 with next=login and NO cookie. The person signs
	//     in with the new password and proves the factor they already have.
	//     Minting a session here let the link holder skip MFA entirely.
	//
	// Re-fetch collaborator to pick up any profile changes made inside the Tx.
	collab, _ = repository.GetCollaborator(r.Context(), s.db, collabID.String())
	identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collabID)
	if err != nil {
		// Fail closed: without a confirmed MFA state we do not go further.
		writeMappedError(w, err)
		return
	}
	if identity.MFAEnrolledAt == nil {
		s.writeMFAEnrollRequired(w, r, collab)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                  "password_set",
		"next":                    "login",
		"mfa_enrollment_required": false,
		"collaborator":            collaboratorIdentityView(collab),
	})
}

// collaboratorEligibleForSetup reports whether a collaborator in the given
// status may complete first-time password setup. Allowlist (fail closed):
// only "active" and the onboarding state "pending_start" (plus the empty
// default, which normalizes to active) qualify. Suspended / offboarded /
// on_leave accounts are rejected.
func collaboratorEligibleForSetup(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active", "pending_start":
		return true
	default:
		return false
	}
}

// collaboratorCanSignIn is the status rule of the password login
// (repository.VerifyPasswordCredential): only "active" signs in. Self-service
// reset mints a session, so it follows this rule and not the wider setup
// allowlist; otherwise a pending_start account (a re-hire before the start
// date still holding old factors) would get a session the login refuses.
func collaboratorCanSignIn(status string) bool {
	return strings.ToLower(strings.TrimSpace(status)) == "active"
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
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthUnauthenticated,
			"Unauthenticated",
			"a valid session token is required",
			httperr.WithInstance(r.URL.Path))
		return
	}
	session, collab, err := repository.ResolveAuthSession(r.Context(), s.db, tokenStr)
	if err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthUnauthenticated,
			"Unauthenticated",
			"the provided session token is invalid or expired",
			httperr.WithInstance(r.URL.Path))
		return
	}

	var req model.PasswordChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Step 2: verify current password.
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.CurrentPassword); err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthInvalidCurrentPassword,
			"Invalid current password",
			"current_password does not match the stored credential",
			httperr.WithInstance(r.URL.Path))
		return
	}

	// Step 3: MFA gate.
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collab.ID); err != nil {
		if errors.Is(err, mfa.ErrMFANotEnrolled) {
			httperr.WriteProblem(w, http.StatusPreconditionRequired,
				httperr.CodeAuthMFANotEnrolled,
				"MFA not enrolled",
				"a second factor must be enrolled before changing the password",
				httperr.WithInstance(r.URL.Path))
			return
		}
		writeMappedError(w, err)
		return
	}
	if err := s.verifyInlineMFAFactor(r, collab.ID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		if errors.Is(err, errMFANotSupplied) {
			httperr.WriteProblem(w, http.StatusUnauthorized,
				httperr.CodeAuthMFAInvalid,
				"Invalid MFA",
				"no MFA factor was supplied",
				httperr.WithInstance(r.URL.Path))
			return
		}
		if errors.Is(err, errWebAuthnNotImplemented) {
			httperr.WriteProblem(w, http.StatusNotImplemented,
				httperr.CodeAuthWebAuthnNotImplemented,
				"WebAuthn not implemented",
				"inline WebAuthn assertion verification is not yet implemented (Phase 2)",
				httperr.WithInstance(r.URL.Path))
			return
		}
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthMFAInvalid,
			"Invalid MFA",
			"the supplied MFA factor could not be verified",
			httperr.WithInstance(r.URL.Path))
		return
	}

	// Step 4: validate new password strength.
	minLen := envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12)
	commonPasswords, _ := commonPasswordsCached()
	if err := password.ValidateStrength(req.NewPassword, minLen, commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		httperr.WriteProblem(w, http.StatusUnprocessableEntity,
			httperr.CodeAuthPasswordTooWeak,
			"Password too weak",
			err.Error(),
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("reason", err.Error()))
		return
	}

	// Step 5: reject if new == current.
	if err := repository.VerifyPassword(r.Context(), s.db, collab.ID, req.NewPassword); err == nil {
		httperr.WriteProblem(w, http.StatusUnprocessableEntity,
			httperr.CodeAuthPasswordUnchanged,
			"Password unchanged",
			"the new password is identical to the current one",
			httperr.WithInstance(r.URL.Path))
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

	// §13 INTEGRATION_CONTRACT: record the global session revocation so
	// every OIDC client + adapter reactor sees that the password rotation
	// invalidated outstanding tokens for this collaborator. session_jti=NULL
	// = "everything except this current session" matches the UPDATE above.
	rev, revErr := repository.InsertSessionRevocation(r.Context(), s.db, tx, repository.InsertSessionRevocationRequest{
		CollaboratorID: collab.ID,
		SessionJTI:     nil,
		Reason:         repository.SessionRevocationReasonPasswordRotated,
		Metadata: map[string]any{
			"source":          source,
			"ip":              r.RemoteAddr,
			"keep_session_id": session.ID.String(),
		},
	})
	if revErr == nil {
		sessionPayload := map[string]any{
			"collaborator_id": collab.ID.String(),
			"reason":          repository.SessionRevocationReasonPasswordRotated,
			"revocation_id":   rev.ID.String(),
			"emitted_at":      time.Now().UTC().Format(time.RFC3339),
		}
		if collab.PrimaryEmail != "" {
			sessionPayload["primary_email"] = collab.PrimaryEmail
		}
		_, _ = repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
			Type:           repository.EventTypeCollaboratorSessionTerminated,
			SchemaVersion:  "v1",
			AggregateType:  "collaborator",
			AggregateID:    collab.ID.String(),
			Payload:        sessionPayload,
			IdempotencyKey: "session.terminated." + rev.ID.String(),
		})
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, err)
		return
	}
	committed = true

	// §13 INTEGRATION_CONTRACT: fire RFC 8417 back-channel logout to every
	// OIDC client linked to this collaborator. Goroutine — the password
	// change response shouldn't wait on slow clients.
	s.dispatchBackchannelLogoutForCollaborator(r.Context(), collab.ID)

	// §A5/G1: emit canonical password.changed audit row. Distinct from
	// the session.revoked rows the §13 path emits — surfaces want to
	// pivot on "password changed for X" without scanning session logs.
	s.recordAuthAuditCollaborator(r, AuditAuthPasswordChanged, collab.ID, AuditOutcomeSuccess, nil)

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
	if err != nil || collab == nil || !collaboratorCanSignIn(collab.Status) {
		// Accounts that cannot sign in get no link either; same 202.
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
		if emitErr := emitCredentialEvent(r.Context(), s.db, repository.EventTypeCredentialResetTokenIssued, "collaborator", collab.ID.String(), nil, map[string]any{
			"token_id":        issued.ID,
			"collaborator_id": collab.ID.String(),
			"expires_at":      issued.ExpiresAt.UTC().Format(time.RFC3339),
			"source":          "self_service",
			"purpose":         "reset",
		}); emitErr != nil {
			s.logWarn("credential.reset_token_issued emit failed",
				zap.String("collaborator_id", collab.ID.String()), zap.Error(emitErr))
		}
		// Delivery is what makes this flow real: without it the token was
		// created and never reached anyone. The send runs in the background
		// so the 202 timing does not reveal whether the account exists.
		if cfg, ok := loadPasswordResetEmailConfig(); ok {
			s.dispatchPasswordResetEmail(cfg, *collab, gen.Raw, ttl)
		}
	}

	respondAccepted()
}

// handleForgotOptions: GET /api/v1/auth/passwords/forgot/options
//
// Tells the login page whether self-service reset can actually deliver a
// link. When it cannot, the page sends the person to an administrator
// instead of a form that silently goes nowhere. Carries no account data.
func (s *Server) handleForgotOptions(w http.ResponseWriter, r *http.Request) {
	_, ok := loadPasswordResetEmailConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"email_delivery":  ok,
		"reset_token_ttl": envDurationCred("AUTH_PASSWORD_RESET_TOKEN_TTL", 24*time.Hour).String(),
	})
}

// handleResetPreflight: GET /api/v1/auth/passwords/reset/preflight?token=…
//
// Read-only check the reset page runs before rendering the form: is the link
// usable, and which second factor can the person prove inline? Passkeys are
// not accepted inline yet, so an account whose only factor is a passkey gets
// factors=[] and the page routes them to an administrator. The token is the
// credential, as on the setup preflight.
func (s *Server) handleResetPreflight(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("token"))
	if raw == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"token query parameter is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("token", "required", "token is required"))
		return
	}
	_, collabID, expiresAt, rej := lookupResetToken(r.Context(), s.db, raw)
	if rej != nil {
		writeSetupTokenRejection(w, r.URL.Path, rej)
		return
	}
	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if !collaboratorCanSignIn(collab.Status) {
		httperr.WriteProblem(w, http.StatusForbidden,
			httperr.CodeAuthAccountInactive,
			"Account not active",
			"this account is not active and cannot reset its password; contact your administrator",
			httperr.WithInstance(r.URL.Path))
		return
	}
	st, err := repository.GetCredentialAccountState(r.Context(), s.db, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	resp := map[string]any{
		"status":          "ready",
		"expires_at":      expiresAt.UTC().Format(time.RFC3339),
		"password_policy": passwordPolicyView(),
		"collaborator":    collaboratorIdentityView(collab),
		"mfa_enrolled":    st.MFAEnrolled,
		"factors":         inlineResetFactors(st),
		// A passkey cannot be proven on this form yet, but it still works at
		// the login: such an account needs a plain access link, not a factor
		// wipe. The page words its advice from this.
		"has_passkey": st.PasskeyCount > 0,
	}
	writeJSON(w, http.StatusOK, resp)
}

// inlineResetFactors lists the second factors the reset form can collect.
func inlineResetFactors(st repository.CredentialAccountState) []string {
	factors := []string{}
	if !st.MFAEnrolled {
		return factors
	}
	if st.HasTOTP {
		factors = append(factors, "totp")
	}
	if st.HasRecoveryCodes {
		factors = append(factors, "recovery_code")
	}
	return factors
}

// handlePasswordReset — POST /api/v1/auth/passwords/reset
//
// Public endpoint that completes a password-reset flow initiated by
// handlePasswordForgot. The link survives the person's mistakes: the token
// is consumed only once every check has passed.
//
//  1. Decode body → token, new_password, MFA factor.
//  2. Look the token up WITHOUT consuming it (401 reset_token_invalid + reason).
//  3. Enforce MFA enrolled (428 otherwise: recovery goes through an admin).
//  4. Refuse inactive accounts (403) and validate the new password
//     (422 + reason); the token stays intact.
//  5. Reserve one of resetMFAMaxAttempts atomically, then verify the factor.
//     A wrong code answers 401 + attempts_remaining and the last failure
//     burns the link, which keeps a 6-digit code from being guessed through
//     an intercepted link (the reservation is what makes the cap hold under
//     concurrent requests).
//  6. Consume the token atomically (a concurrent use loses here).
//  7. In a transaction: update the password hash, revoke ALL sessions, emit
//     the audit event.
//  8. Outside the Tx: open a new session with its CSRF cookie.
func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req model.PasswordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"token is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("token", "required", "token is required"))
		return
	}

	// Step 2: inspect the token; nothing is consumed yet.
	tokenID, collabID, _, rej := lookupResetToken(r.Context(), s.db, req.Token)
	if rej != nil {
		writeSetupTokenRejection(w, r.URL.Path, rej)
		return
	}

	// Step 3: MFA gate.
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collabID); err != nil {
		httperr.WriteProblem(w, http.StatusPreconditionRequired,
			httperr.CodeAuthMFANotEnrolled,
			"MFA not enrolled",
			"a second factor must be enrolled before resetting the password",
			httperr.WithInstance(r.URL.Path))
		return
	}

	// Step 4: account status and password policy, before touching the
	// factor or the token. Offboarding and suspension do not invalidate an
	// outstanding reset link, so a live link must not reopen an account the
	// login and the setup commit already refuse.
	collab, err := repository.GetCollaborator(r.Context(), s.db, collabID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if !collaboratorCanSignIn(collab.Status) {
		httperr.WriteProblem(w, http.StatusForbidden,
			httperr.CodeAuthAccountInactive,
			"Account not active",
			"this account is not active and cannot reset its password; contact your administrator",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("status", collab.Status))
		return
	}
	commonPasswords, _ := commonPasswordsCached()
	if err := password.ValidateStrength(req.NewPassword, envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12), commonPasswords, []string{collab.PrimaryEmail, collab.Slug, collab.DisplayName}); err != nil {
		writePasswordPolicyProblem(w, r.URL.Path, err)
		return
	}

	// Step 5: second factor. Only a TOTP or recovery code can be proven
	// here, so anything else is answered before an attempt is spent.
	if strings.TrimSpace(req.TOTPCode) == "" && strings.TrimSpace(req.RecoveryCode) == "" {
		if req.WebAuthnAssertion != nil {
			httperr.WriteProblem(w, http.StatusNotImplemented,
				httperr.CodeAuthWebAuthnNotImplemented,
				"WebAuthn not implemented",
				"inline WebAuthn assertion verification is not yet implemented (Phase 2)",
				httperr.WithInstance(r.URL.Path))
			return
		}
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"totp_code or recovery_code is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("totp_code", "required", "totp_code or recovery_code is required"))
		return
	}
	// The attempt is reserved atomically BEFORE the check, so concurrent
	// requests cannot all slip under the cap.
	attempts, err := repository.ReserveResetTokenMFAAttempt(r.Context(), s.db, tokenID, resetMFAMaxAttempts)
	if errors.Is(err, repository.ErrResetAttemptsExhausted) {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthResetTokenInvalid,
			"Invalid reset token",
			"this reset link has no attempts left; request a new one",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("reason", "already_used"),
			httperr.WithExtra("attempts_remaining", 0))
		return
	}
	if err != nil {
		// Fail closed: an attempt that cannot be counted is not verified.
		writeMappedError(w, err)
		return
	}
	if err := s.verifyInlineMFAFactor(r, collabID, req.TOTPCode, req.RecoveryCode, req.WebAuthnAssertion); err != nil {
		if errors.Is(err, errWebAuthnNotImplemented) {
			httperr.WriteProblem(w, http.StatusNotImplemented,
				httperr.CodeAuthWebAuthnNotImplemented,
				"WebAuthn not implemented",
				"inline WebAuthn assertion verification is not yet implemented (Phase 2)",
				httperr.WithInstance(r.URL.Path))
			return
		}
		remaining := resetMFAMaxAttempts - attempts
		if remaining <= 0 {
			remaining = 0
			// The last reserved attempt failed: close the link. The reserve
			// step already refuses further attempts even if this write fails.
			if burnErr := repository.BurnCredentialToken(r.Context(), s.db, tokenID); burnErr != nil {
				s.logWarn("reset link burn failed", zap.String("token_id", tokenID.String()), zap.Error(burnErr))
			}
		}
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthMFAInvalid,
			"Invalid MFA",
			"the supplied MFA factor could not be verified",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("attempts_remaining", remaining))
		return
	}

	// Step 6: consume the token atomically.
	if _, err := repository.ConsumeCredentialToken(r.Context(), s.db, repository.ConsumeCredentialTokenInput{
		TokenHash: password.HashToken(req.Token), Purpose: model.CredentialTokenPurposeReset,
	}); err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthResetTokenInvalid,
			"Invalid reset token",
			"the reset token is invalid, expired, or already consumed",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("reason", "already_used"))
		return
	}

	scheme, hash, err := password.Hash(req.NewPassword)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	rotation := envDurationCred("AUTH_PASSWORD_ROTATION_PERIOD", 90*24*time.Hour)

	// Step 7.
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
		    password_must_change = false,
		    failed_attempts      = 0,
		    locked_until         = NULL
		WHERE collaborator_id = $1
	`, collabID, hash, string(scheme), rotation.String()); err != nil {
		writeMappedError(w, err)
		return
	}

	// Revoke everything opened with the old password: console sessions, OIDC
	// refresh tokens, plus the §13 revocation row and session.terminated.
	if err := s.revokeForCredentialReplacement(r.Context(), tx, collab, repository.SessionRevocationReasonPasswordRotated, map[string]any{
		"source": "self_service_reset",
		"ip":     r.RemoteAddr,
	}); err != nil {
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
	s.dispatchBackchannelLogoutForCollaborator(r.Context(), collabID)

	// Step 8: open a new session OUTSIDE the committed Tx, with the same
	// cookie pair a password login sets (the console needs the CSRF cookie
	// for its first mutation).
	sessionMeta := mergeAuthMetadata(nil, r)
	session, sessionToken, err := repository.CreateAuthSession(r.Context(), s.db, collabID, sessionMeta, authSessionTTL())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeAuthCookie(w, sessionToken, session.ExpiresAt)
	writeCSRFCookie(w, computeCSRFToken(session.ID), session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"session":      session,
		"token":        sessionToken,
		"collaborator": collab,
	})
}

// resetMFAMaxAttempts is how many second-factor proofs one reset link
// accepts; the link is burned when the last one fails.
const resetMFAMaxAttempts = 5

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
