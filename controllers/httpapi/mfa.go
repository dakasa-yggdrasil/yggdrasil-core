package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// mfaEnrollRequestBody is the body of POST /api/v1/auth/mfa/enroll/request.
type mfaEnrollRequestBody struct {
	CollaboratorEmail string `json:"collaborator_email"`
}

// mfaEnrollResponse is the body returned with the magic-link URL.
type mfaEnrollResponse struct {
	EnrollURL string    `json:"enroll_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Note: mfaEnrollRequiredResponse (a typed envelope) was removed in the
// §14-close migration (2026-05-28). The MFA enroll-required response is
// now emitted as a canonical RFC 7807 Problem+JSON via
// httperr.WriteProblem in writeMFAEnrollRequired — enroll_url,
// expires_at, and collaborator are carried as extension fields. Read
// docs/error_codes.md for the wire shape.

// hashEnrollToken returns the SHA-256 of the raw token (lower-cased hex).
// Repository persists only the hash; the raw token lives in the URL.
func hashEnrollToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// resolveCollaboratorFromEnrollToken validates the token (not consumed, not
// expired) and returns the linked collaborator. Returns an error suitable for
// writeMappedError when the token is invalid.
func (s *Server) resolveCollaboratorFromEnrollToken(ctx context.Context, raw string) (model.Collaborator, error) {
	if raw == "" {
		return model.Collaborator{}, errors.New("token required")
	}
	hash := hashEnrollToken(raw)
	tok, err := repository.GetMFAEnrollTokenByHash(ctx, s.db, hash)
	if err != nil {
		return model.Collaborator{}, err
	}
	if tok.ConsumedAt != nil {
		return model.Collaborator{}, repository.ErrMFAEnrollTokenAlreadyConsumed
	}
	if !tok.ExpiresAt.IsZero() && tok.ExpiresAt.Before(time.Now()) {
		return model.Collaborator{}, repository.ErrMFAEnrollTokenExpired
	}
	return repository.GetCollaborator(ctx, s.db, tok.CollaboratorID.String())
}

func (s *Server) issueMFAEnrollLink(ctx context.Context, r *http.Request, collab model.Collaborator) (mfaEnrollResponse, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return mfaEnrollResponse{}, err
	}
	token := hex.EncodeToString(raw)
	hash := hashEnrollToken(token)

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if _, err := repository.IssueMFAEnrollToken(ctx, s.db, collab.ID, hash, expiresAt); err != nil {
		return mfaEnrollResponse{}, err
	}

	return mfaEnrollResponse{
		EnrollURL: fmt.Sprintf("%s/mfa/enroll?token=%s", consoleBaseURL(r), token),
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Server) writeMFAEnrollRequired(w http.ResponseWriter, r *http.Request, collab model.Collaborator) {
	enroll, err := s.issueMFAEnrollLink(r.Context(), r, collab)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	httperr.WriteProblem(w, http.StatusPreconditionRequired,
		httperr.CodeAuthMFANotEnrolled,
		"MFA not enrolled",
		"MFA enrollment is required before a session can be issued.",
		httperr.WithInstance(r.URL.Path),
		httperr.WithExtra("enroll_url", enroll.EnrollURL),
		httperr.WithExtra("expires_at", enroll.ExpiresAt),
		httperr.WithExtra("collaborator", collab))
}

func consoleBaseURL(r *http.Request) string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv("YGGDRASIL_CONSOLE_URL")), "/"); base != "" {
		return base
	}
	if r != nil {
		scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
		if scheme == "" {
			scheme = "https"
			if r.TLS == nil && (strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1")) {
				scheme = "http"
			}
		}
		host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = strings.TrimSpace(r.Host)
		}
		if host != "" {
			return scheme + "://" + host
		}
	}
	return "https://yggdrasil.dakasa.me"
}

// handleMFAEnrollRequest issues a magic-link enroll token (POST). The CLI or
// onboarding workflow calls this after creating the collaborator + before
// fanning out provisioning downstream.
func (s *Server) handleMFAEnrollRequest(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	var req mfaEnrollRequestBody
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if req.CollaboratorEmail == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"collaborator_email is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("collaborator_email", "required", "collaborator_email is required"))
		return
	}
	collab, err := repository.GetCollaboratorByPrimaryEmail(r.Context(), s.db, req.CollaboratorEmail)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	enroll, err := s.issueMFAEnrollLink(r.Context(), r, collab)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, enroll)
}

func (s *Server) handleMFAEnrollValidate(w http.ResponseWriter, r *http.Request) {
	collab, err := s.resolveCollaboratorFromEnrollToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

// totpBeginRequest is the body of POST /api/v1/auth/mfa/factors/totp/begin
// and finish — both share the magic-link token.
type totpBeginRequest struct {
	Token string `json:"token"`
}

type totpBeginResponse struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauth_uri"`
}

type totpFinishRequest struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

func (s *Server) requireEnvelope(w http.ResponseWriter) bool {
	if s.envelope == nil {
		httperr.WriteProblem(w, http.StatusServiceUnavailable,
			httperr.CodeAuthKEKNotConfigured,
			"KEK not configured",
			"YGGDRASIL_AUTH_KEK_BASE64 is not configured; MFA secrets-at-rest unavailable")
		return false
	}
	return true
}

func (s *Server) handleMFATOTPBegin(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnvelope(w) {
		return
	}
	var req totpBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, err := s.resolveEnrollCollaborator(r, req.Token)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Make sure the collaborator has an auth_identity row.
	if err := repository.UpsertAuthIdentity(r.Context(), s.db, collab.ID, collab.PrimaryEmail); err != nil {
		writeMappedError(w, err)
		return
	}
	secret, err := mfa.GenerateTOTPSecret(collab.PrimaryEmail)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := repository.SetTOTPSecret(r.Context(), s.db, s.envelope, collab.ID, []byte(secret.Base32)); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, totpBeginResponse{
		Secret:     secret.Base32,
		OtpauthURI: secret.OTPAuthURL,
	})
}

func (s *Server) handleMFATOTPFinish(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnvelope(w) {
		return
	}
	var req totpFinishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, err := s.resolveEnrollCollaborator(r, req.Token)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	secret, err := repository.GetTOTPSecret(r.Context(), s.db, s.envelope, collab.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := mfa.ValidateTOTP(string(secret), req.Code); err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthMFAInvalid,
			"Invalid MFA",
			"invalid TOTP code",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("factor", "totp"))
		return
	}
	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := repository.SetRecoveryCodesHashes(r.Context(), s.db, collab.ID, hashes); err != nil {
		writeMappedError(w, err)
		return
	}
	// Session-mode enrollment (no magic-link token) has nothing to consume;
	// only the token flow burns the single-use enroll token.
	if strings.TrimSpace(req.Token) != "" {
		if err := repository.ConsumeMFAEnrollToken(r.Context(), s.db, hashEnrollToken(req.Token)); err != nil {
			writeMappedError(w, err)
			return
		}
	}
	if err := repository.MarkMFAEnrolled(r.Context(), s.db, collab.ID, time.Now()); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mfa_enrolled":   true,
		"codes":          codes,
		"displayed_once": true,
	})
}

// webauthnUserView is the surface-safe projection of a stored
// WebAuthnCredential. We pick fields the FE renders + intentionally
// drop attestation bytes + public key material — those are server-side
// only material.
type webauthnUserView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	DeviceKind     string     `json:"device_kind,omitempty"`
	Transports     []string   `json:"transports,omitempty"`
	BackupEligible bool       `json:"backup_eligible,omitempty"`
	BackupState    bool       `json:"backup_state,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

func webauthnCredentialsToViews(creds []model.WebAuthnCredential) []webauthnUserView {
	out := make([]webauthnUserView, 0, len(creds))
	for _, c := range creds {
		out = append(out, webauthnUserView{
			ID:             c.ID,
			Name:           c.Name,
			DeviceKind:     c.DeviceKind,
			Transports:     c.Transports,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
			CreatedAt:      c.CreatedAt,
			LastUsedAt:     c.LastUsedAt,
		})
	}
	return out
}

// webauthnCredentialsToLibCredentials lifts our persisted records into
// the lib's typed Credential view so go-webauthn's BeginLogin / Verify
// path can use them. We preserve every field the lib needs for verify
// (PublicKey, ID, SignCount, attestation raw bytes, transports).
func webauthnCredentialsToLibCredentials(creds []model.WebAuthnCredential) []wa.Credential {
	out := make([]wa.Credential, 0, len(creds))
	for _, c := range creds {
		raw := c.RawID
		if len(raw) == 0 {
			// Backward-compat: decode the ID if the row predates
			// RawID being stored.  Silent skip on malformed (the
			// credential won't be usable; user must re-enroll).
			if decoded, err := base64.RawURLEncoding.DecodeString(c.ID); err == nil {
				raw = decoded
			}
		}
		var aaguid []byte
		if c.AAGUID != "" {
			if dec, err := base64.RawURLEncoding.DecodeString(c.AAGUID); err == nil {
				aaguid = dec
			}
		}
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, wa.Credential{
			ID:                raw,
			PublicKey:         c.PublicKey,
			AttestationType:   c.AttestationType,
			AttestationFormat: c.AttestationFormat,
			Transport:         transports,
			Authenticator: wa.Authenticator{
				AAGUID:    aaguid,
				SignCount: c.SignCount,
			},
			Attestation: wa.CredentialAttestation{
				ClientDataJSON:     c.ClientDataJSON,
				AuthenticatorData:  c.AuthenticatorData,
				PublicKeyAlgorithm: c.PublicKeyAlgorithm,
				Object:             c.AttestationObject,
			},
		})
	}
	return out
}

// libCredentialToModel converts a freshly-issued lib Credential into
// our persisted shape. The caller fills Name + DeviceKind + UserAgent
// from the request context before persisting.
func libCredentialToModel(lc *wa.Credential) model.WebAuthnCredential {
	credID := base64.RawURLEncoding.EncodeToString(lc.ID)
	aaguid := ""
	if len(lc.Authenticator.AAGUID) > 0 {
		aaguid = base64.RawURLEncoding.EncodeToString(lc.Authenticator.AAGUID)
	}
	transports := make([]string, 0, len(lc.Transport))
	for _, t := range lc.Transport {
		if s := strings.TrimSpace(string(t)); s != "" {
			transports = append(transports, s)
		}
	}
	return model.WebAuthnCredential{
		ID:                 credID,
		RawID:              lc.ID,
		PublicKey:          lc.PublicKey,
		AttestationType:    lc.AttestationType,
		AttestationFormat:  lc.AttestationFormat,
		AttestationObject:  lc.Attestation.Object,
		AuthenticatorData:  lc.Attestation.AuthenticatorData,
		ClientDataJSON:     lc.Attestation.ClientDataJSON,
		PublicKeyAlgorithm: lc.Attestation.PublicKeyAlgorithm,
		AAGUID:             aaguid,
		SignCount:          lc.Authenticator.SignCount,
		Transports:         transports,
		BackupEligible:     lc.Flags.BackupEligible,
		BackupState:        lc.Flags.BackupState,
		CreatedAt:          time.Now().UTC(),
	}
}

func (s *Server) requireWebAuthn(w http.ResponseWriter, r *http.Request) bool {
	if s.webauthnEngine == nil || s.webauthnSessions == nil {
		httperr.WriteProblem(w, http.StatusServiceUnavailable,
			httperr.CodeAuthWebAuthnNotImplemented,
			"WebAuthn not configured",
			"WebAuthn engine is not configured; set YGGDRASIL_WEBAUTHN_RP_ID and YGGDRASIL_WEBAUTHN_ORIGINS",
			httperr.WithInstance(r.URL.Path))
		return false
	}
	return true
}

// mfaWebAuthnEnrollBeginRequest carries the magic-link enroll token (for
// the initial enroll flow) OR is empty (when the caller is already
// authenticated and adding a new device via /me/mfa). The handler picks
// the right code path based on which one is set.
type mfaWebAuthnEnrollBeginRequest struct {
	Token string `json:"token,omitempty"`
}

// mfaWebAuthnEnrollFinishRequest carries the magic-link enroll token,
// the friendly device name (defaults if blank), AND the raw
// AttestationResponse from navigator.credentials.create. We keep the
// AttestationResponse as a raw json.RawMessage so we can hand the same
// bytes back to protocol.ParseCredentialCreationResponseBody.
type mfaWebAuthnEnrollFinishRequest struct {
	Token              string          `json:"token,omitempty"`
	Name               string          `json:"name,omitempty"`
	AttestationResponse json.RawMessage `json:"attestation_response"`
}

// handleMFAWebAuthnBegin issues a CredentialCreationOptions for the FE
// to hand to navigator.credentials.create. Supports two entry points:
//   - Magic-link enroll flow: caller passes `token` (from email/invite).
//     Used by /enroll. Collaborator is resolved from the token.
//   - /me self-service flow: caller is already authenticated. Token
//     omitted; collaborator resolved from session.
func (s *Server) handleMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebAuthn(w, r) {
		return
	}
	var req mfaWebAuthnEnrollBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	collab, err := s.resolveEnrollCollaborator(r, req.Token)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Ensure auth_identity row exists — first-time enroll won't have one.
	if err := repository.UpsertAuthIdentity(r.Context(), s.db, collab.ID, collab.PrimaryEmail); err != nil {
		writeMappedError(w, err)
		return
	}

	// Load existing credentials so the lib can populate `excludeCredentials`
	// and prevent the same authenticator being enrolled twice.
	existing, err := repository.ListWebAuthnCredentials(r.Context(), s.db, collab.ID)
	if err != nil && !errors.Is(err, repository.ErrAuthIdentityNotFound) {
		writeMappedError(w, err)
		return
	}
	user := &mfa.User{
		IDBytes:     collab.ID[:],
		Username:    collab.PrimaryEmail,
		DisplayName: collab.DisplayName,
		Credentials: webauthnCredentialsToLibCredentials(existing),
	}

	creation, session, err := s.webauthnEngine.BeginRegistration(user,
		// Exclude already-registered credentials so the same device
		// can't be enrolled twice (the browser will reject silently).
		wa.WithExclusions(libCredentialsToDescriptors(user.Credentials)),
	)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.webauthnSessions.Put(mfa.RegistrationKey(collab.ID.String()), *session)
	writeJSON(w, http.StatusOK, creation)
}

// handleMFAWebAuthnFinish takes the AttestationResponse from
// navigator.credentials.create, runs go-webauthn FinishRegistration
// against the cached session, persists the new credential, and (on
// first-time enroll) consumes the magic-link token + marks MFA enrolled.
//
// Returns 200 with `{credential, recovery_codes?}`. recovery_codes are
// included on first-time enroll (the user has no codes yet); subsequent
// "add another device" calls return an empty list.
func (s *Server) handleMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebAuthn(w, r) {
		return
	}
	if !s.requireEnvelope(w) {
		return
	}

	// Peek the body so we can both pull the magic-link token + replay
	// the bytes into protocol.ParseCredentialCreationResponseBody.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	_ = r.Body.Close()

	var req mfaWebAuthnEnrollFinishRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMalformedBody,
			"Malformed body",
			err.Error(),
			httperr.WithInstance(r.URL.Path))
		return
	}
	if len(req.AttestationResponse) == 0 {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"attestation_response is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("attestation_response", "required", "attestation_response is required"))
		return
	}

	collab, err := s.resolveEnrollCollaborator(r, req.Token)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	session, err := s.webauthnSessions.Take(mfa.RegistrationKey(collab.ID.String()))
	if err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthWebAuthnCeremonyExpired,
			"Ceremony expired",
			"The WebAuthn registration ceremony timed out; please restart the flow.",
			httperr.WithInstance(r.URL.Path))
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.AttestationResponse)
	if err != nil {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeAuthWebAuthnInvalid,
			"Invalid WebAuthn response",
			err.Error(),
			httperr.WithInstance(r.URL.Path))
		return
	}

	// Reload credentials so the User struct passed to CreateCredential
	// matches what BeginRegistration saw.
	existing, err := repository.ListWebAuthnCredentials(r.Context(), s.db, collab.ID)
	if err != nil && !errors.Is(err, repository.ErrAuthIdentityNotFound) {
		writeMappedError(w, err)
		return
	}
	user := &mfa.User{
		IDBytes:     collab.ID[:],
		Username:    collab.PrimaryEmail,
		DisplayName: collab.DisplayName,
		Credentials: webauthnCredentialsToLibCredentials(existing),
	}
	credential, err := s.webauthnEngine.CreateCredential(user, session, parsed)
	if err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthWebAuthnInvalid,
			"WebAuthn registration failed",
			err.Error(),
			httperr.WithInstance(r.URL.Path))
		return
	}

	// Build the persisted record.
	record := libCredentialToModel(credential)
	record.UserAgent = r.UserAgent()
	record.DeviceKind = mfa.DeviceKindFromAttachment(parsed.AuthenticatorAttachment)

	// Auto-name when the FE didn't supply one.
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = autoNameForNewPasskey(existing)
	}
	if len(name) > 128 {
		name = name[:128]
	}
	record.Name = name

	if err := repository.AppendWebAuthnCredential(r.Context(), s.db, collab.ID, record); err != nil {
		writeMappedError(w, err)
		return
	}

	// First-time enroll: generate recovery codes + mark mfa_enrolled_at +
	// consume the magic-link token. Adding-another-device path: skip all
	// three (user already has codes + a non-nil mfa_enrolled_at).
	identity, identityErr := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collab.ID)
	if identityErr != nil && !errors.Is(identityErr, repository.ErrAuthIdentityNotFound) {
		writeMappedError(w, identityErr)
		return
	}

	var recoveryCodes []string
	firstEnroll := identity.MFAEnrolledAt == nil
	if firstEnroll {
		codes, hashes, err := mfa.GenerateRecoveryCodes()
		if err != nil {
			writeMappedError(w, err)
			return
		}
		if err := repository.SetRecoveryCodesHashes(r.Context(), s.db, collab.ID, hashes); err != nil {
			writeMappedError(w, err)
			return
		}
		recoveryCodes = codes
		if req.Token != "" {
			if err := repository.ConsumeMFAEnrollToken(r.Context(), s.db, hashEnrollToken(req.Token)); err != nil {
				writeMappedError(w, err)
				return
			}
		}
		if err := repository.MarkMFAEnrolled(r.Context(), s.db, collab.ID, time.Now()); err != nil {
			writeMappedError(w, err)
			return
		}
	}

	// Audit + metric.
	s.recordAuthAuditCollaborator(r, AuditAuthMFAEnrolled, collab.ID, AuditOutcomeSuccess, map[string]any{
		"factor":      "webauthn",
		"device_name": record.Name,
		"device_kind": record.DeviceKind,
		"credential_id_hint": shortCredID(record.ID),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"credential": webauthnUserView{
			ID:             record.ID,
			Name:           record.Name,
			DeviceKind:     record.DeviceKind,
			Transports:     record.Transports,
			BackupEligible: record.BackupEligible,
			BackupState:    record.BackupState,
			CreatedAt:      record.CreatedAt,
			LastUsedAt:     record.LastUsedAt,
		},
		"mfa_enrolled":      true,
		"codes":             recoveryCodes,
		"displayed_once":    len(recoveryCodes) > 0,
	})
}

// resolveEnrollCollaborator pivots on the magic-link token: when
// non-empty we resolve from the token; otherwise from the session
// cookie. This lets the same enroll handlers serve both the magic-link
// flow (/enroll, first-time, no session yet) and the session flow
// (post-setup redirect + the console guard that bounces every no-MFA
// session to /mfa/enroll, plus /me/mfa "add another device"). Shared by
// the WebAuthn and TOTP enroll endpoints so neither strands a logged-in
// collaborator who arrived without a token.
func (s *Server) resolveEnrollCollaborator(r *http.Request, token string) (model.Collaborator, error) {
	if strings.TrimSpace(token) != "" {
		return s.resolveCollaboratorFromEnrollToken(r.Context(), token)
	}
	collabID, err := s.requireSessionCollaborator(r)
	if err != nil {
		return model.Collaborator{}, err
	}
	return repository.GetCollaborator(r.Context(), s.db, collabID.String())
}

// mfaWebAuthnLoginBeginRequest is the body of POST /api/v1/auth/mfa/webauthn/login/begin.
// `identifier` is the same email-or-username the FE collected in the
// password step — we use it to resolve the user + their credentials.
type mfaWebAuthnLoginBeginRequest struct {
	Identifier string `json:"identifier"`
}

// handleMFAWebAuthnLoginBegin issues a CredentialRequestOptions for the
// browser to hand to navigator.credentials.get. The collaborator MUST
// already have passed the password step — this endpoint does NOT verify
// the password; it assumes the surface's flow already validated it.
// (We intentionally don't re-check the password here because the
// PasskeyScreen runs AFTER the 202 mfa_required response.)
func (s *Server) handleMFAWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebAuthn(w, r) {
		return
	}
	var req mfaWebAuthnLoginBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.Identifier) == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"identifier is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("identifier", "required", "identifier is required"))
		return
	}
	collab, err := repository.GetCollaboratorByPrimaryEmail(r.Context(), s.db, strings.TrimSpace(req.Identifier))
	if err != nil {
		// Don't leak whether the identifier maps to a real user — return
		// a generic "no passkey available" envelope. The caller's UI
		// surfaces "use another method".
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthMFAFactorUnavailable,
			"MFA factor unavailable",
			"no passkey registered for this identifier",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("factor", "webauthn"))
		return
	}
	creds, err := repository.ListWebAuthnCredentials(r.Context(), s.db, collab.ID)
	if err != nil && !errors.Is(err, repository.ErrAuthIdentityNotFound) {
		writeMappedError(w, err)
		return
	}
	if len(creds) == 0 {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthMFAFactorUnavailable,
			"MFA factor unavailable",
			"no passkey registered for this identifier",
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("factor", "webauthn"))
		return
	}
	user := &mfa.User{
		IDBytes:     collab.ID[:],
		Username:    collab.PrimaryEmail,
		DisplayName: collab.DisplayName,
		Credentials: webauthnCredentialsToLibCredentials(creds),
	}
	assertion, session, err := s.webauthnEngine.BeginLogin(user)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	s.webauthnSessions.Put(mfa.LoginKey(collab.ID.String()), *session)
	writeJSON(w, http.StatusOK, assertion)
}

// mfaWebAuthnLoginFinishRequest carries the identifier (we re-resolve
// the same user we issued the challenge to) + the raw AssertionResponse
// from navigator.credentials.get. The password+identifier WERE NOT
// validated again — the surface's flow validates them via /api/v1/auth/login
// after we return the WebAuthn-issued partial result; this endpoint only
// proves possession of the passkey.
type mfaWebAuthnLoginFinishRequest struct {
	Identifier        string          `json:"identifier"`
	Password          string          `json:"password,omitempty"`
	AssertionResponse json.RawMessage `json:"assertion_response"`
}

// handleMFAWebAuthnLoginFinish is the "complete the login" endpoint.
// It takes the password + identifier + the AssertionResponse, verifies
// the password, verifies the WebAuthn assertion, and (on success) issues
// the same session+cookie+CSRF envelope the password+TOTP flow does.
//
// Sign-count replay: every successful verify bumps the sign_count + last_used_at
// on the matched credential. The lib's validateLogin already rejects when
// the response counter <= stored — surfaced as auth.webauthn_replay.
func (s *Server) handleMFAWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebAuthn(w, r) {
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	_ = r.Body.Close()
	var req mfaWebAuthnLoginFinishRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMalformedBody,
			"Malformed body",
			err.Error(),
			httperr.WithInstance(r.URL.Path))
		return
	}
	if len(req.AssertionResponse) == 0 || strings.TrimSpace(req.Identifier) == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"identifier and assertion_response are required",
			httperr.WithInstance(r.URL.Path))
		return
	}
	// Verify the password — we MUST NOT skip this step. The /webauthn/login
	// flow is "second factor after password", not "passwordless".
	loginReq := model.LoginWithPasswordRequest{
		Identifier: req.Identifier,
		Password:   req.Password,
		Metadata:   mergeAuthMetadata(nil, r),
	}
	collab, err := repository.VerifyPasswordCredential(r.Context(), s.db, loginReq)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	session, err := s.webauthnSessions.Take(mfa.LoginKey(collab.ID.String()))
	if err != nil {
		httperr.WriteProblem(w, http.StatusUnauthorized,
			httperr.CodeAuthWebAuthnCeremonyExpired,
			"Ceremony expired",
			"The WebAuthn login ceremony timed out; please restart the flow.",
			httperr.WithInstance(r.URL.Path))
		return
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.AssertionResponse)
	if err != nil {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeAuthWebAuthnInvalid,
			"Invalid WebAuthn response",
			err.Error(),
			httperr.WithInstance(r.URL.Path))
		return
	}

	creds, err := repository.ListWebAuthnCredentials(r.Context(), s.db, collab.ID)
	if err != nil && !errors.Is(err, repository.ErrAuthIdentityNotFound) {
		writeMappedError(w, err)
		return
	}
	user := &mfa.User{
		IDBytes:     collab.ID[:],
		Username:    collab.PrimaryEmail,
		DisplayName: collab.DisplayName,
		Credentials: webauthnCredentialsToLibCredentials(creds),
	}
	matched, err := s.webauthnEngine.ValidateLogin(user, session, parsed)
	if err != nil {
		// Sign-count regressions show up as "Sign counter for credential" in
		// lib errors; we tag those distinctly so audit can spot them.
		code := httperr.CodeAuthWebAuthnInvalid
		reason := err.Error()
		if strings.Contains(strings.ToLower(reason), "counter") {
			code = httperr.CodeAuthWebAuthnReplay
		}
		metrics.IncAuthMFAVerify(metrics.AuthMFAVerifyFailed, metrics.AuthMFAFactorWebAuthn)
		s.recordAuthAuditCollaborator(r, AuditAuthMFAVerifyFailed, collab.ID, AuditOutcomeFailure, map[string]any{
			"factor": "webauthn",
			"reason": reason,
		})
		httperr.WriteProblem(w, http.StatusUnauthorized,
			code,
			"WebAuthn login failed",
			reason,
			httperr.WithInstance(r.URL.Path),
			httperr.WithExtra("factor", "webauthn"))
		return
	}

	// Persist updated sign_count + last_used_at on the matched credential.
	credID := base64.RawURLEncoding.EncodeToString(matched.ID)
	if err := repository.UpdateWebAuthnSignCount(r.Context(), s.db, collab.ID, credID, matched.Authenticator.SignCount, time.Now().UTC()); err != nil {
		// Non-fatal: the verify succeeded, the user has authenticated.
		// We log + audit but don't fail the login.
		if s.logger != nil {
			s.logger.Warn("webauthn sign_count update failed",
				zap.String("collaborator_id", collab.ID.String()),
				zap.Error(err))
		}
	}

	metrics.IncAuthMFAVerify(metrics.AuthMFAVerifySucceeded, metrics.AuthMFAFactorWebAuthn)
	s.recordAuthAuditCollaborator(r, AuditAuthMFAVerifySucceeded, collab.ID, AuditOutcomeSuccess, map[string]any{
		"factor": "webauthn",
		"credential_id_hint": shortCredID(credID),
	})

	// Issue the session — same envelope as password+TOTP login.
	auth, token, err := repository.CreateAuthSession(r.Context(), s.db, collab.ID, loginReq.Metadata, authSessionTTL())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	metrics.IncAuthLogin(metrics.AuthLoginSucceeded)
	metrics.IncAuthSessionCreated()
	s.recordAuthAuditCollaborator(r, AuditAuthSessionCreated, collab.ID, AuditOutcomeSuccess, map[string]any{
		"session_id": auth.ID.String(),
		"expires_at": auth.ExpiresAt.Format(time.RFC3339),
		"mfa_method": "webauthn",
	})
	s.recordAuthAuditCollaborator(r, AuditAuthLoginSucceeded, collab.ID, AuditOutcomeSuccess, map[string]any{
		"session_id": auth.ID.String(),
		"mfa_method": "webauthn",
	})
	writeAuthCookie(w, token, auth.ExpiresAt)
	writeCSRFCookie(w, computeCSRFToken(auth.ID), auth.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator":             collab,
		"session":                  auth,
		"token":                    token,
		"password_change_required": false,
		"mfa_enrollment_required":  false,
	})
}

// handleMFAFactorsList returns the calling user's active MFA factors
// (TOTP yes/no, list of passkeys, recovery codes remaining). NEVER
// includes public-key bytes / private material — the FE only renders
// names + device kinds + timestamps.
//
// GET /api/v1/auth/mfa/factors
func (s *Server) handleMFAFactorsList(w http.ResponseWriter, r *http.Request) {
	collabID, err := s.requireSessionCollaborator(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collabID)
	if err != nil {
		// Treat missing auth_identity as "nothing enrolled".
		if errors.Is(err, repository.ErrAuthIdentityNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"totp": map[string]any{"enrolled": false},
				"webauthn_credentials":     []webauthnUserView{},
				"recovery_codes_remaining": 0,
			})
			return
		}
		writeMappedError(w, err)
		return
	}
	recovery, err := repository.CountRecoveryCodesRemaining(r.Context(), s.db, collabID)
	if err != nil {
		recovery = 0
	}
	totp := map[string]any{"enrolled": identity.HasTOTP}
	if identity.HasTOTP && identity.MFAEnrolledAt != nil {
		totp["enrolled_at"] = identity.MFAEnrolledAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totp":                     totp,
		"webauthn_credentials":     webauthnCredentialsToViews(identity.WebAuthnCredentials),
		"recovery_codes_remaining": recovery,
	})
}

type mfaWebAuthnRenameRequest struct {
	Name string `json:"name"`
}

// handleMFAWebAuthnRename renames one credential. The caller MUST be
// the owner — we resolve the collaborator from session and only mutate
// rows for that user.
//
// PATCH /api/v1/auth/mfa/factors/webauthn/{credential_id}
func (s *Server) handleMFAWebAuthnRename(w http.ResponseWriter, r *http.Request) {
	collabID, err := s.requireSessionCollaborator(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	credID := r.PathValue("credential_id")
	if credID == "" {
		writeJSONError(w, http.StatusBadRequest, "credential_id is required")
		return
	}
	var req mfaWebAuthnRenameRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		httperr.WriteProblem(w, http.StatusBadRequest,
			httperr.CodeMissingField,
			"Missing field",
			"name is required",
			httperr.WithInstance(r.URL.Path),
			httperr.WithFieldError("name", "required", "name is required"))
		return
	}
	if err := repository.UpdateWebAuthnCredentialName(r.Context(), s.db, collabID, credID, name); err != nil {
		if errors.Is(err, repository.ErrWebAuthnCredentialNotFound) {
			httperr.WriteProblem(w, http.StatusNotFound,
				httperr.CodeAuthWebAuthnNotFound,
				"Credential not found",
				"no passkey matches this credential id",
				httperr.WithInstance(r.URL.Path))
			return
		}
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_id": credID,
		"name":          name,
	})
}

// handleMFAWebAuthnDelete removes one passkey. Refuses if removing the
// credential would strand the user with zero MFA factors (no TOTP + no
// other passkey). The recovery-codes-only state is considered "stranded"
// for this check — recovery codes are an escape hatch, not a primary
// factor.
//
// DELETE /api/v1/auth/mfa/factors/webauthn/{credential_id}
func (s *Server) handleMFAWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	collabID, err := s.requireSessionCollaborator(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	credID := r.PathValue("credential_id")
	if credID == "" {
		writeJSONError(w, http.StatusBadRequest, "credential_id is required")
		return
	}
	identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Last-factor protection.
	if !identity.HasTOTP && len(identity.WebAuthnCredentials) <= 1 {
		httperr.WriteProblem(w, http.StatusConflict,
			httperr.CodeAuthWebAuthnLastFactor,
			"Last factor",
			"this is your only MFA factor; add another (TOTP or a new passkey) before removing this one",
			httperr.WithInstance(r.URL.Path))
		return
	}
	if err := repository.RemoveWebAuthnCredential(r.Context(), s.db, collabID, credID); err != nil {
		if errors.Is(err, repository.ErrWebAuthnCredentialNotFound) {
			httperr.WriteProblem(w, http.StatusNotFound,
				httperr.CodeAuthWebAuthnNotFound,
				"Credential not found",
				"no passkey matches this credential id",
				httperr.WithInstance(r.URL.Path))
			return
		}
		writeMappedError(w, err)
		return
	}
	s.recordAuthAuditCollaborator(r, AuditAuthMFAUnenrolled, collabID, AuditOutcomeSuccess, map[string]any{
		"factor":             "webauthn",
		"credential_id_hint": shortCredID(credID),
	})
	w.WriteHeader(http.StatusNoContent)
}

// libCredentialsToDescriptors flattens the lib's stored credentials
// into the protocol.CredentialDescriptor slice that BeginRegistration
// uses for the excludeCredentials list.
func libCredentialsToDescriptors(creds []wa.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Descriptor())
	}
	return out
}

// autoNameForNewPasskey picks "Passkey N" where N is the next index
// after the existing credentials. Used when the FE doesn't send a name.
func autoNameForNewPasskey(existing []model.WebAuthnCredential) string {
	return fmt.Sprintf("Passkey %d", len(existing)+1)
}

// shortCredID returns the first 8 chars of a credential ID — enough to
// pivot in audit/logs without leaking the full credential ID into the
// audit_events row (defence-in-depth: an audit row leak shouldn't be a
// credential leak).
func shortCredID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func webauthnRelyingPartyID() string {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_WEBAUTHN_RP_ID")); v != "" {
		return v
	}
	return "yggdrasil.dakasa.me"
}

func webauthnRPDisplayName() string {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_WEBAUTHN_RP_NAME")); v != "" {
		return v
	}
	return "Yggdrasil"
}

// webauthnAllowedOrigins returns the comma-separated env list of allowed
// origins, plus the hardcoded production + local-dev defaults. Empty env
// gets only the defaults; non-empty env REPLACES them (so an operator
// can lock down to a single origin in production if desired).
func webauthnAllowedOrigins() []string {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_WEBAUTHN_ORIGINS")); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{
		"https://yggdrasil.dakasa.me",
		"http://localhost:5173",
		"http://localhost:9080",
	}
}

// handleMFAGenerateRecoveryCodes generates 10 single-use codes and persists
// only their hashes. The plaintext codes appear once in the response; the
// caller must store/print them (or accept that they cannot be re-derived).
func (s *Server) handleMFAGenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	collabID, err := s.requireSessionCollaborator(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := repository.SetRecoveryCodesHashes(r.Context(), s.db, collabID, hashes); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"codes":          codes,
		"displayed_once": true,
	})
}

// requireSessionCollaborator extracts the bearer/cookie session and returns
// the linked collaborator UUID. Used by /me-style endpoints that require an
// authenticated session.
func (s *Server) requireSessionCollaborator(r *http.Request) (uuid.UUID, error) {
	token, ok := extractAuthToken(r)
	if !ok {
		return uuid.Nil, errors.New("session required")
	}
	_, collab, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		return uuid.Nil, err
	}
	return collab.ID, nil
}
