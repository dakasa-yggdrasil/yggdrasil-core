package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
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

type mfaEnrollRequiredResponse struct {
	Error        string              `json:"error"`
	Code         string              `json:"code"`
	Message      string              `json:"message"`
	EnrollURL    string              `json:"enroll_url"`
	ExpiresAt    time.Time           `json:"expires_at"`
	Collaborator *model.Collaborator `json:"collaborator,omitempty"`
}

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
	writeJSON(w, http.StatusPreconditionRequired, mfaEnrollRequiredResponse{
		Error:        "mfa_not_enrolled",
		Code:         "mfa_not_enrolled",
		Message:      "MFA enrollment is required before a session can be issued.",
		EnrollURL:    enroll.EnrollURL,
		ExpiresAt:    enroll.ExpiresAt,
		Collaborator: &collab,
	})
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
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var req mfaEnrollRequestBody
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if req.CollaboratorEmail == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "collaborator_email required"})
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
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "YGGDRASIL_AUTH_KEK_BASE64 not configured"})
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
	collab, err := s.resolveCollaboratorFromEnrollToken(r.Context(), req.Token)
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
	collab, err := s.resolveCollaboratorFromEnrollToken(r.Context(), req.Token)
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid totp code"})
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
	if err := repository.ConsumeMFAEnrollToken(r.Context(), s.db, hashEnrollToken(req.Token)); err != nil {
		writeMappedError(w, err)
		return
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

// WebAuthn: Phase 1 ships begin (challenge issuance) — finish requires the
// caller to round-trip a CredentialCreationResponse parsed via go-webauthn.
// For Phase 1 we expose begin so the FE can demonstrate the flow; finish is
// stubbed and returns 501 until the persistence layer for credentials lands.
func (s *Server) handleMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	var req totpBeginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, err := s.resolveCollaboratorFromEnrollToken(r.Context(), req.Token)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Issue a challenge. We use a 32-byte random nonce and store keyed by
	// collaborator ID; the FE round-trips the challenge through navigator
	// .credentials.create. Phase 2 will move this into a Redis-backed
	// session cache and wire mfa.WebAuthnConfig from internal/auth/mfa.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		writeMappedError(w, err)
		return
	}
	s.webauthnSessions.Store(collab.ID.String(), challenge)
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge": hex.EncodeToString(challenge),
			"rp":        map[string]any{"name": "Yggdrasil", "id": webauthnRelyingPartyID()},
			"user":      map[string]any{"id": collab.ID.String(), "name": collab.PrimaryEmail, "displayName": collab.DisplayName},
			"pubKeyCredParams": []map[string]any{
				{"type": "public-key", "alg": -7},
				{"type": "public-key", "alg": -257},
			},
			"timeout":     60000,
			"attestation": "none",
		},
	})
}

func (s *Server) handleMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	// Phase 1 stub: implement end-to-end with go-webauthn FinishRegistration
	// once the credential storage shape is finalised. Returning 501 keeps
	// the wire contract alive without persisting half-validated credentials.
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn finish not yet implemented (Phase 2)"})
}

func webauthnRelyingPartyID() string {
	if v := os.Getenv("YGGDRASIL_WEBAUTHN_RP_ID"); v != "" {
		return v
	}
	return "yggdrasil-console.dakasa.me"
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

// jsonRawMessageOrEmpty is a guard so handler bodies don't panic on nil bodies
// when echoing nested JSON.
func jsonRawMessageOrEmpty(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage([]byte("{}"))
	}
	return json.RawMessage(b)
}
