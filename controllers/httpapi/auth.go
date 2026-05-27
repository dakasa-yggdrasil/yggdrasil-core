package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type authLoginResponse struct {
	Collaborator           model.Collaborator `json:"collaborator"`
	Session                model.AuthSession  `json:"session"`
	Token                  string             `json:"token"`
	PasswordChangeRequired bool               `json:"password_change_required"`
	PasswordChangeURL      string             `json:"password_change_url,omitempty"`
	MFAEnrollmentRequired  bool               `json:"mfa_enrollment_required"`
	MFAEnrollURL           string             `json:"mfa_enroll_url,omitempty"`
}

type authMFARequiredResponse struct {
	Error        string              `json:"error"`
	Code         string              `json:"code"`
	Message      string              `json:"message"`
	Factors      []string            `json:"factors"`
	Collaborator *model.Collaborator `json:"collaborator,omitempty"`
}

type authThirdPartyLoginResponse struct {
	Collaborator model.Collaborator       `json:"collaborator"`
	Identity     model.ThirdPartyIdentity `json:"identity"`
	Session      model.AuthSession        `json:"session"`
	Token        string                   `json:"token"`
}

type thirdPartyIdentitiesResponse struct {
	Identities []model.ThirdPartyIdentity `json:"identities"`
}

type thirdPartyAuthProvidersResponse struct {
	Providers []model.ThirdPartyAuthProvider `json:"providers"`
}

func (s *Server) handleAuthPasswordUpsert(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	var req model.UpsertPasswordCredentialRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	minLen := envIntCred("AUTH_PASSWORD_MIN_LENGTH", 12)
	commonPasswords, _ := commonPasswordsCached()
	if err := password.ValidateStrength(req.Password, minLen, commonPasswords, nil); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"code":   "password_too_weak",
			"reason": err.Error(),
		})
		return
	}

	scheme, hash, err := password.Hash(req.Password)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	credential, collaborator, err := repository.UpsertPasswordCredential(r.Context(), s.db, req, string(scheme), hash)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"credential":   credential,
		"collaborator": collaborator,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginWithPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	req.Metadata = mergeAuthMetadata(req.Metadata, r)
	collaborator, err := repository.VerifyPasswordCredential(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collaborator.ID); err != nil {
		if errors.Is(err, mfa.ErrMFANotEnrolled) {
			s.writeMFAEnrollRequired(w, r, collaborator)
			return
		}
		writeMappedError(w, err)
		return
	}

	identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collaborator.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	factors := authLoginFactors(identity)
	if len(factors) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "mfa enrollment has no factor available for login",
			"code":  "mfa_factor_unavailable",
		})
		return
	}

	req.TOTPCode = strings.TrimSpace(req.TOTPCode)
	req.RecoveryCode = strings.TrimSpace(req.RecoveryCode)
	if req.TOTPCode == "" && req.RecoveryCode == "" {
		writeJSON(w, http.StatusAccepted, authMFARequiredResponse{
			Error:        "mfa_required",
			Code:         "mfa_required",
			Message:      "MFA verification is required before a session can be issued.",
			Factors:      factors,
			Collaborator: &collaborator,
		})
		return
	}

	if req.TOTPCode != "" {
		if !identity.HasTOTP {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "mfa enrollment has no TOTP factor available for login",
				"code":  "mfa_totp_unavailable",
			})
			return
		}
		if !s.requireEnvelope(w) {
			return
		}
		secret, err := repository.GetTOTPSecret(r.Context(), s.db, s.envelope, collaborator.ID)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		if err := mfa.ValidateTOTP(string(secret), req.TOTPCode); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid totp code",
				"code":  "invalid_totp",
			})
			return
		}
	} else {
		if !identity.HasRecoveryCodes {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid recovery code",
				"code":  "invalid_recovery_code",
			})
			return
		}
		if err := repository.VerifyAndInvalidateRecoveryCode(r.Context(), s.db, collaborator.ID, req.RecoveryCode); err != nil {
			if errors.Is(err, mfa.ErrInvalidRecoveryCode) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "invalid recovery code",
					"code":  "invalid_recovery_code",
				})
				return
			}
			writeMappedError(w, err)
			return
		}
	}

	session, token, err := repository.CreateAuthSession(r.Context(), s.db, collaborator.ID, req.Metadata, authSessionTTL())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	passState, passErr := repository.GetPasswordCredentialState(r.Context(), s.db, collaborator.ID)
	needsPwdChange := false
	if passErr == nil {
		needsPwdChange = passState.PasswordMustChange ||
			(passState.PasswordExpiresAt != nil && passState.PasswordExpiresAt.Before(time.Now()))
	}
	// If ErrPasswordCredentialNotFound (SSO-only collaborator), treat as no
	// password change required. Any other error is non-fatal — we still issue
	// the session; the flags default to false.

	needsMFA := identity.MFAEnrolledAt == nil

	resp := authLoginResponse{
		Collaborator:           collaborator,
		Session:                session,
		Token:                  token,
		PasswordChangeRequired: needsPwdChange,
		MFAEnrollmentRequired:  needsMFA,
	}
	if needsPwdChange {
		resp.PasswordChangeURL = "/api/v1/auth/passwords/change"
	}
	if needsMFA {
		resp.MFAEnrollURL = "/api/v1/auth/mfa/enroll"
	}

	writeAuthCookie(w, token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, resp)
}

func authLoginFactors(identity model.AuthIdentity) []string {
	factors := make([]string, 0, 2)
	if identity.HasTOTP {
		factors = append(factors, "totp")
	}
	if identity.HasRecoveryCodes {
		factors = append(factors, "recovery_code")
	}
	return factors
}

func (s *Server) handleAuthThirdPartyLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginWithThirdPartyIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	req.SessionMetadata = mergeAuthMetadata(req.SessionMetadata, r)
	collaborator, identity, session, token, err := repository.AuthenticateWithThirdPartyIdentity(
		r.Context(),
		s.db,
		req,
		authSessionTTL(),
	)
	if err != nil {
		if errors.Is(err, mfa.ErrMFANotEnrolled) {
			s.writeMFAEnrollRequired(w, r, collaborator)
			return
		}
		writeMappedError(w, err)
		return
	}

	writeAuthCookie(w, token, session.ExpiresAt)
	writeJSON(w, http.StatusOK, authThirdPartyLoginResponse{
		Collaborator: collaborator,
		Identity:     identity,
		Session:      session,
		Token:        token,
	})
}

func (s *Server) handleAuthThirdPartyStart(w http.ResponseWriter, r *http.Request) {
	provider, err := s.resolveAuthProvider(r.Context(), r.PathValue("provider"))
	if err != nil {
		writeMappedError(w, err)
		return
	}

	redirectTo := queryString(r, "redirect_to")
	// When the OIDC OP signals "login required" it calls our LoginURL with
	// auth_request_id=<uuid>. Preserve it on the state cookie so the
	// callback can mark the auth_request as Done() and resume the OP flow
	// by redirecting to <issuer>/authorize/callback?id=<uuid>. Empty when
	// the third-party login was initiated outside an OIDC flow.
	authRequestID := queryString(r, "auth_request_id")
	state, err := coreauth.NewThirdPartyState(provider.Name, normalizePostAuthRedirect(redirectTo), authRequestID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	stateToken, err := coreauth.SignThirdPartyState(authThirdPartyStateSecret(), state)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	redirectURI := authThirdPartyCallbackURL(r, provider.Name)
	authURL, err := buildThirdPartyAuthorizeURL(provider, redirectURI, state.Nonce)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeThirdPartyStateCookie(w, stateToken)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAuthThirdPartyCallback(w http.ResponseWriter, r *http.Request) {
	provider, err := s.resolveAuthProvider(r.Context(), r.PathValue("provider"))
	if err != nil {
		writeMappedError(w, err)
		return
	}

	stateCookie, err := r.Cookie(authThirdPartyStateCookieName())
	if err != nil {
		writeMappedError(w, fmt.Errorf("third-party auth state cookie is required"))
		return
	}
	state, err := coreauth.VerifyThirdPartyState(authThirdPartyStateSecret(), stateCookie.Value)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if state.Provider != provider.Name {
		writeMappedError(w, fmt.Errorf("third-party auth state provider mismatch"))
		return
	}
	if strings.TrimSpace(r.URL.Query().Get("state")) != state.Nonce {
		writeMappedError(w, fmt.Errorf("third-party auth state mismatch"))
		return
	}
	if providerError := strings.TrimSpace(r.URL.Query().Get("error")); providerError != "" {
		writeMappedError(w, fmt.Errorf("third-party provider returned error %q", providerError))
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		writeMappedError(w, fmt.Errorf("third-party authorization code is required"))
		return
	}

	redirectURI := authThirdPartyCallbackURL(r, provider.Name)
	accessToken, _, err := coreauth.ExchangeAuthorizationCode(r.Context(), http.DefaultClient, provider, code, redirectURI)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	profile, err := coreauth.FetchOAuthProfile(r.Context(), http.DefaultClient, provider, accessToken)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Domain-default + auto-provision: ensure a collaborator exists for the
	// claim email before AuthenticateWithThirdPartyIdentity runs the
	// AutoLinkByEmail path. Google OAuth surfaces verification status as the
	// boolean "email_verified" claim; defensive type assertion (`_, ok`) so a
	// missing or non-bool claim is treated as "not verified" rather than
	// panicking.
	emailVerified, _ := profile.Claims["email_verified"].(bool)
	if _, err := provisionCollaboratorFromClaim(r.Context(), s.db, profile.Email, profile.DisplayName, emailVerified); err != nil {
		writeMappedError(w, err)
		return
	}

	collaborator, identity, session, token, err := repository.AuthenticateWithThirdPartyIdentity(
		r.Context(),
		s.db,
		model.LoginWithThirdPartyIdentityRequest{
			Provider:        provider.Name,
			Subject:         profile.Subject,
			Login:           profile.Login,
			Email:           profile.Email,
			DisplayName:     profile.DisplayName,
			ProfileURL:      profile.ProfileURL,
			AvatarURL:       profile.AvatarURL,
			Claims:          profile.Claims,
			AutoLinkByEmail: provider.AutoLinkByEmail,
			SessionMetadata: mergeAuthMetadata(map[string]any{
				"auth_flow": "browser_callback",
				"provider":  provider.Name,
			}, r),
		},
		authSessionTTL(),
	)
	if err != nil {
		if errors.Is(err, mfa.ErrMFANotEnrolled) {
			enroll, issueErr := s.issueMFAEnrollLink(r.Context(), r, collaborator)
			if issueErr != nil {
				writeMappedError(w, issueErr)
				return
			}
			clearThirdPartyStateCookie(w)
			http.Redirect(w, r, enroll.EnrollURL, http.StatusFound)
			return
		}
		writeMappedError(w, err)
		return
	}

	clearThirdPartyStateCookie(w)
	writeAuthCookie(w, token, session.ExpiresAt)

	// If this third-party login was kicked off by the OIDC OP's "login
	// required" signal, finish the OIDC flow instead of bouncing the user
	// to state.RedirectTo (which would land them on the Yggdrasil home
	// page with no authorization code for the original OIDC client).
	// Two steps:
	//   1. Bind collaborator_id on the auth_request so authRequestView.Done()
	//      flips to true (storage.go:248).
	//   2. Redirect to <issuer>/authorize/callback?id=<auth_request_id> —
	//      the path zitadel/oidc OP serves for AuthCallbackURL. The OP
	//      then issues the authorization code and 302s back to the
	//      original client's redirect_uri.
	if state.AuthRequestID != "" {
		if requestUUID, parseErr := uuid.Parse(state.AuthRequestID); parseErr == nil {
			if bindErr := repository.BindOIDCAuthRequestCollaborator(r.Context(), s.db, requestUUID, collaborator.ID); bindErr != nil {
				writeMappedError(w, bindErr)
				return
			}
			callback := strings.TrimRight(s.oidcIssuerURL, "/") + "/authorize/callback?id=" + url.QueryEscape(state.AuthRequestID)
			http.Redirect(w, r, callback, http.StatusFound)
			return
		}
	}

	redirectTo := normalizePostAuthRedirect(state.RedirectTo)
	if queryBool(r, "response_as_json") {
		writeJSON(w, http.StatusOK, authThirdPartyLoginResponse{
			Collaborator: collaborator,
			Identity:     identity,
			Session:      session,
			Token:        token,
		})
		return
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, model.AuthSessionEnvelope{Authenticated: false})
		return
	}

	session, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			writeJSON(w, http.StatusUnauthorized, model.AuthSessionEnvelope{Authenticated: false})
			return
		}
		writeMappedError(w, err)
		return
	}

	// Best-effort MFA enrollment lookup: ignore "not found" / lookup errors
	// so callers without an auth_identity row (e.g. SSO-only users) still
	// get a valid session payload. Nil MFAEnrolledAt is the safe default
	// because the FE guard treats it as "needs enrollment".
	var mfaEnrolledAt *time.Time
	if identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collaborator.ID); err == nil {
		mfaEnrolledAt = identity.MFAEnrolledAt
	}

	// Best-effort permission resolution. Errors fail-closed (empty list) so
	// the FE hides actions instead of silently allowing them.
	permissions, err := repository.ResolveYggdrasilPermissions(r.Context(), s.db, collaborator.ID, collaborator.Traits)
	if err != nil {
		fmt.Printf("auth.session: resolve permissions for %s: %v\n", collaborator.ID, err)
		permissions = []string{}
	}

	writeJSON(w, http.StatusOK, model.AuthSessionEnvelope{
		Authenticated: true,
		Collaborator:  &collaborator,
		Session:       &session,
		MFAEnrolledAt: mfaEnrolledAt,
		Permissions:   permissions,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		clearAuthCookie(w)
		writeJSON(w, http.StatusOK, model.AuthSessionEnvelope{Authenticated: false})
		return
	}

	session, err := repository.RevokeAuthSession(r.Context(), s.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			writeJSON(w, http.StatusOK, model.AuthSessionEnvelope{Authenticated: false})
			return
		}
		writeMappedError(w, err)
		return
	}

	clearAuthCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": false,
		"session":       session,
	})
}

func (s *Server) handleThirdPartyIdentityList(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	identities, err := repository.ListThirdPartyIdentities(r.Context(), s.db, model.ListThirdPartyIdentitiesRequest{
		CollaboratorID: queryString(r, "collaborator_id"),
		Provider:       queryString(r, "provider"),
		Status:         queryString(r, "status"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, thirdPartyIdentitiesResponse{Identities: identities})
}

func (s *Server) handleThirdPartyIdentityUpsert(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	var req model.UpsertThirdPartyIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	identity, collaborator, err := repository.UpsertThirdPartyIdentity(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"identity":     identity,
		"collaborator": collaborator,
	})
}

func (s *Server) handleThirdPartyIdentityDelete(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	identity, collaborator, err := repository.DeleteThirdPartyIdentity(r.Context(), s.db, model.DeleteThirdPartyIdentityRequest{
		Provider: r.PathValue("provider"),
		Subject:  r.PathValue("subject"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"identity":     identity,
		"collaborator": collaborator,
	})
}

func (s *Server) handleThirdPartyAuthProviderList(w http.ResponseWriter, r *http.Request) {
	providers, err := repository.ListThirdPartyAuthProviders(r.Context(), s.db, model.ListThirdPartyAuthProvidersRequest{
		Type:   queryString(r, "type"),
		Status: queryString(r, "status"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, thirdPartyAuthProvidersResponse{Providers: providers})
}

func (s *Server) handleThirdPartyAuthProviderGet(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	provider, err := repository.GetThirdPartyAuthProvider(r.Context(), s.db, model.GetThirdPartyAuthProviderRequest{
		Name: r.PathValue("provider"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": provider})
}

func (s *Server) handleThirdPartyAuthProviderUpsert(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	var req model.UpsertThirdPartyAuthProviderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := s.materializeThirdPartyAuthProviderClientSecret(r.Context(), &req); err != nil {
		writeMappedError(w, err)
		return
	}
	provider, err := repository.UpsertThirdPartyAuthProvider(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"provider": provider})
}

func (s *Server) materializeThirdPartyAuthProviderClientSecret(
	ctx context.Context,
	req *model.UpsertThirdPartyAuthProviderRequest,
) error {
	if s == nil || req == nil {
		return nil
	}

	clientSecret := strings.TrimSpace(req.ClientSecret)
	if clientSecret == "" {
		return nil
	}

	providerName := strings.ToLower(strings.TrimSpace(req.Name))
	if providerName == "" {
		return fmt.Errorf("third-party auth provider name is required")
	}

	namespace := "global"
	name := fmt.Sprintf("auth-provider/%s/client-secret", providerName)
	key := "value"

	if ref := strings.TrimSpace(req.ClientSecretRef); ref != "" {
		refNamespace, refName, refKey, err := parseManagedSecretWriteRef(ref)
		if err != nil {
			return fmt.Errorf("third-party auth provider client_secret_ref: %w", err)
		}
		namespace = refNamespace
		name = refName
		if refKey != "" {
			key = refKey
		}
	}

	secret, err := repository.UpsertManagedSecret(ctx, s.db, model.UpsertManagedSecretRequest{
		Namespace: namespace,
		Name:      name,
		Status:    "active",
		Data: map[string]string{
			key: clientSecret,
		},
		Metadata: map[string]any{
			"source_kind": "auth_provider",
			"auth_provider": map[string]any{
				"name": providerName,
			},
		},
		Rotation: model.ManagedSecretRotationPolicy{Mode: "manual"},
	})
	if err != nil {
		return err
	}

	req.ClientSecret = ""
	req.ClientSecretRef = fmt.Sprintf("secret://%s/%s#%s", secret.Namespace, secret.Name, key)
	return nil
}

func parseManagedSecretWriteRef(ref string) (namespace string, name string, key string, err error) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "secret://") {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://", ref)
	}

	target := strings.TrimPrefix(ref, "secret://")
	parts := strings.SplitN(target, "#", 2)
	pathPart := strings.Trim(parts[0], "/")
	if len(parts) == 2 {
		key = strings.TrimSpace(parts[1])
	}

	pathSegments := strings.Split(pathPart, "/")
	if len(pathSegments) < 2 {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://<namespace>/<name>[#key]", ref)
	}

	namespace = strings.ToLower(strings.TrimSpace(pathSegments[0]))
	name = strings.ToLower(strings.TrimSpace(strings.Join(pathSegments[1:], "/")))
	if namespace == "" || name == "" {
		return "", "", "", fmt.Errorf("secret ref %q must use secret://<namespace>/<name>[#key]", ref)
	}
	if strings.TrimSpace(key) == "" {
		key = "value"
	}
	return namespace, name, key, nil
}

func (s *Server) handleThirdPartyAuthProviderDelete(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeMappedError(w, err)
		return
	}

	provider, err := repository.DeleteThirdPartyAuthProvider(r.Context(), s.db, model.DeleteThirdPartyAuthProviderRequest{
		Name: r.PathValue("provider"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": provider})
}

func writeAuthCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

func extractAuthToken(r *http.Request) (string, bool) {
	if cookie, err := r.Cookie(authSessionCookieName()); err == nil {
		if value := strings.TrimSpace(cookie.Value); value != "" {
			return value, true
		}
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		if token := strings.TrimSpace(authHeader[7:]); token != "" {
			return token, true
		}
	}

	if token := strings.TrimSpace(r.Header.Get("X-Session-Token")); token != "" {
		return token, true
	}

	return "", false
}

func mergeAuthMetadata(input map[string]any, r *http.Request) map[string]any {
	output := cloneAnyMap(input)
	if output == nil {
		output = map[string]any{}
	}

	if surface := strings.TrimSpace(r.Header.Get("X-Yggdrasil-Surface")); surface != "" {
		output["surface"] = surface
	}
	if userAgent := strings.TrimSpace(r.UserAgent()); userAgent != "" {
		output["user_agent"] = userAgent
	}
	if remoteAddr := strings.TrimSpace(r.RemoteAddr); remoteAddr != "" {
		output["remote_addr"] = remoteAddr
		// Postgres `inet` rejects "host:port"; strip the port so the typed
		// auth_sessions.ip_address column gets a parseable value. Falls
		// back to the raw remoteAddr if the parse fails (covers x-forwarded
		// pre-stripped values too).
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
			output["ip_address"] = host
		} else {
			output["ip_address"] = remoteAddr
		}
	}
	if fp := strings.TrimSpace(r.Header.Get("X-Device-Fingerprint")); fp != "" {
		output["device_fingerprint"] = fp
	}

	return output
}

func authSessionCookieName() string {
	if value := strings.TrimSpace(os.Getenv("AUTH_SESSION_COOKIE_NAME")); value != "" {
		return value
	}
	return "yggdrasil_session"
}

func authSessionCookieDomain() string {
	return strings.TrimSpace(os.Getenv("AUTH_SESSION_COOKIE_DOMAIN"))
}

// authSessionCookieSecure resolves the Secure flag for the session cookie.
//
// SECURITY (audit 2026-05-27 A3): the default MUST be `true`. yggdrasil
// is deployed behind TLS in every production tenant (yggdrasil.dakasa.me
// + ingress termination), so the session cookie should never traverse
// plaintext. The previous default-false meant that a misconfigured
// deployment (empty env var) would silently emit cookies usable over
// HTTP — exactly what an attacker on a coffee-shop WiFi can exploit.
//
// Local-dev escape hatch: set AUTH_SESSION_COOKIE_SECURE=false explicitly
// when running yggdrasil-core on plain HTTP (e.g. docker-compose without
// TLS termination). Any other value — including an unparseable garbage
// string — falls back to the secure default (fail-closed).
func authSessionCookieSecure() bool {
	value := strings.TrimSpace(os.Getenv("AUTH_SESSION_COOKIE_SECURE"))
	if value == "" {
		return true
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return parsed
}

func authSessionTTL() time.Duration {
	value := strings.TrimSpace(os.Getenv("AUTH_SESSION_TTL_HOURS"))
	if value == "" {
		return 30 * 24 * time.Hour
	}

	hours, err := strconv.Atoi(value)
	if err != nil || hours <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(hours) * time.Hour
}

func authThirdPartyStateSecret() string {
	if value := strings.TrimSpace(os.Getenv("AUTH_THIRD_PARTY_STATE_SECRET")); value != "" {
		return value
	}
	return "yggdrasil-dev-third-party-state-secret"
}

func authThirdPartyStateCookieName() string {
	return "yggdrasil_third_party_state"
}

func writeThirdPartyStateCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authThirdPartyStateCookieName(),
		Value:    token,
		Path:     "/api/v1/auth/third-party/",
		Expires:  time.Now().UTC().Add(10 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

func clearThirdPartyStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authThirdPartyStateCookieName(),
		Value:    "",
		Path:     "/api/v1/auth/third-party/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

func authSurfaceBaseURL(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Yggdrasil-Surface-Base-URL")); value != "" {
		return strings.TrimRight(value, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return scheme + "://" + host
}

func authThirdPartyCallbackURL(r *http.Request, provider string) string {
	return authSurfaceBaseURL(r) + "/api/v1/auth/third-party/callback/" + url.PathEscape(strings.TrimSpace(provider))
}

func normalizePostAuthRedirect(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return "/"
	case strings.HasPrefix(value, "/"):
		return value
	case strings.HasPrefix(value, "http://"), strings.HasPrefix(value, "https://"):
		return value
	default:
		return "/"
	}
}

func buildThirdPartyAuthorizeURL(provider coreauth.OAuthResolvedProvider, redirectURI string, nonce string) (string, error) {
	authURL, err := url.Parse(provider.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse provider authorize_url: %w", err)
	}
	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", provider.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", nonce)
	if len(provider.Scopes) > 0 {
		query.Set("scope", strings.Join(provider.Scopes, " "))
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func (s *Server) resolveAuthProvider(ctx context.Context, providerName string) (coreauth.OAuthResolvedProvider, error) {
	provider, err := repository.GetThirdPartyAuthProvider(ctx, s.db, model.GetThirdPartyAuthProviderRequest{Name: providerName})
	if err != nil {
		return coreauth.OAuthResolvedProvider{}, err
	}
	if strings.ToLower(strings.TrimSpace(provider.Status)) != "active" {
		return coreauth.OAuthResolvedProvider{}, fmt.Errorf("third-party auth provider %q is not active", provider.Name)
	}

	clientSecretAny, err := repository.ResolveSecretRef(ctx, s.db, provider.ClientSecretRef)
	if err != nil {
		return coreauth.OAuthResolvedProvider{}, err
	}
	clientSecret, err := coerceThirdPartyClientSecret(clientSecretAny)
	if err != nil {
		return coreauth.OAuthResolvedProvider{}, err
	}

	authorizeURL := provider.AuthorizeURL
	tokenURL := provider.TokenURL
	userInfoURL := provider.UserInfoURL
	if strings.ToLower(strings.TrimSpace(provider.Type)) == "oidc" && provider.IssuerURL != "" &&
		(authorizeURL == "" || tokenURL == "" || userInfoURL == "") {
		discovery, err := coreauth.ResolveOIDCDiscovery(ctx, http.DefaultClient, provider.IssuerURL)
		if err != nil {
			return coreauth.OAuthResolvedProvider{}, err
		}
		if authorizeURL == "" {
			authorizeURL = discovery.AuthorizationEndpoint
		}
		if tokenURL == "" {
			tokenURL = discovery.TokenEndpoint
		}
		if userInfoURL == "" {
			userInfoURL = discovery.UserInfoEndpoint
		}
	}

	return coreauth.OAuthResolvedProvider{
		Name:             provider.Name,
		Type:             provider.Type,
		AuthorizeURL:     authorizeURL,
		TokenURL:         tokenURL,
		UserInfoURL:      userInfoURL,
		ClientID:         provider.ClientID,
		ClientSecret:     clientSecret,
		Scopes:           provider.Scopes,
		AutoLinkByEmail:  provider.AutoLinkByEmail,
		SubjectField:     provider.SubjectField,
		LoginField:       provider.LoginField,
		EmailField:       provider.EmailField,
		DisplayNameField: provider.DisplayNameField,
		AvatarURLField:   provider.AvatarURLField,
		ProfileURLField:  provider.ProfileURLField,
	}, nil
}

func coerceThirdPartyClientSecret(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return "", fmt.Errorf("third-party auth provider client secret is empty")
		}
		return typed, nil
	case map[string]any:
		if len(typed) == 1 {
			for _, item := range typed {
				return coerceThirdPartyClientSecret(item)
			}
		}
	case map[string]string:
		if len(typed) == 1 {
			for _, item := range typed {
				return coerceThirdPartyClientSecret(item)
			}
		}
	}
	return "", fmt.Errorf("third-party auth provider client secret must resolve to one scalar value")
}

func isAuthUnauthorizedError(err error) bool {
	switch err {
	case nil:
		return false
	case repository.ErrAuthInvalidCredentials,
		repository.ErrAuthSessionNotFound,
		repository.ErrAuthSessionExpired,
		repository.ErrPasswordCredentialNotFound,
		repository.ErrCollaboratorNotFound,
		repository.ErrThirdPartyIdentityNotFound:
		return true
	default:
		return false
	}
}
