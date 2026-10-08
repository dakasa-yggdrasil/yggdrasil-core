package httpapi

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type contactMFAOption struct {
	Available bool `json:"available"`
	Enrolled  bool `json:"enrolled"`
}

type contactOTPRequest struct {
	Token          string `json:"token,omitempty"`
	Channel        string `json:"channel"`
	ChallengeToken string `json:"challenge_token,omitempty"`
	Code           string `json:"code,omitempty"`
}

type contactOTPResponse struct {
	ChallengeToken string    `json:"challenge_token"`
	Channel        string    `json:"channel"`
	ExpiresAt      time.Time `json:"expires_at"`
	RetryAfter     int       `json:"retry_after"`
}

type contactDeliveryConfig struct {
	Integration model.ManifestSelector
	From        string
}

// Delivery stays provider-neutral. Configuration names an operator-owned
// integration instance; no request can select a provider or recipient.
func loadContactDeliveryConfig(channel string) (contactDeliveryConfig, bool) {
	namespace, name, ok := mfa.ContactDeliverySelector(channel)
	if !ok {
		return contactDeliveryConfig{}, false
	}
	return contactDeliveryConfig{
		Integration: model.ManifestSelector{Namespace: namespace, Name: name},
		From:        strings.TrimSpace(os.Getenv("AUTH_EMAIL_FROM")),
	}, true
}

// Public auth routes do not carry session claims through the global CSRF
// middleware. Resolve and bind the live session here, enforcing CSRF on every
// session-mode mutation, including when the global middleware is in warn mode.
func (s *Server) resolveContactEnrollment(r *http.Request, token string, mutation bool) (model.Collaborator, string, error) {
	if token != "" {
		collab, err := s.resolveCollaboratorFromEnrollToken(r.Context(), token)
		return collab, "enroll-token:" + hashEnrollToken(token), err
	}
	raw, ok := extractAuthToken(r)
	if !ok {
		return model.Collaborator{}, "", repository.ErrAuthSessionNotFound
	}
	session, collab, err := repository.ResolveAuthSession(r.Context(), s.db, raw)
	if err != nil {
		return model.Collaborator{}, "", err
	}
	if mutation && !hmac.Equal([]byte(strings.TrimSpace(r.Header.Get(csrfHeaderName))), []byte(computeCSRFToken(session.ID))) {
		return model.Collaborator{}, "", errContactCSRF
	}
	return collab, "session:" + session.ID.String(), nil
}

var errContactCSRF = errors.New("contact MFA requires session CSRF proof")

func (s *Server) contactMFAOptions(ctx context.Context, id uuid.UUID) (map[string]contactMFAOption, error) {
	factors, err := repository.ListContactMFAFactors(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	out := map[string]contactMFAOption{}
	for _, channel := range []string{"email", "sms"} {
		_, configured := loadContactDeliveryConfig(channel)
		binding, bindingErr := repository.ReadContactBinding(ctx, s.db, id, channel)
		if bindingErr != nil && !errors.Is(bindingErr, repository.ErrContactUnavailable) {
			return nil, bindingErr
		}
		// An SMS contact must also be decryptable before promising delivery.
		if channel == "sms" && configured && bindingErr == nil {
			phone, phoneErr := repository.GetPhoneContact(ctx, s.db, s.envelope, id)
			configured = phoneErr == nil && phone != nil
		}
		option := contactMFAOption{Available: configured && bindingErr == nil && binding != ""}
		for _, factor := range factors {
			if factor.Channel == channel && factor.ContactBinding == binding {
				option.Enrolled = true
			}
		}
		out[channel] = option
	}
	return out, nil
}

func (s *Server) handleMFAContactOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	collab, _, err := s.resolveContactEnrollment(r, strings.TrimSpace(r.URL.Query().Get("token")), false)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	options, err := s.contactMFAOptions(r.Context(), collab.ID)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleMFAContactBegin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req contactOTPRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, binding, err := s.resolveContactEnrollment(r, strings.TrimSpace(req.Token), true)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	if err := repository.UpsertAuthIdentity(r.Context(), s.db, collab.ID, collab.PrimaryEmail); err != nil {
		writeMappedError(w, err)
		return
	}
	s.beginContactOTP(w, r, collab, req.Channel, "enroll", binding)
}

func (s *Server) handleMFAContactLoginBegin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
		Channel    string `json:"channel"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, binding, err := repository.VerifyPasswordCredentialForContactOTP(r.Context(), s.db, model.LoginWithPasswordRequest{Identifier: req.Identifier, Password: req.Password})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := mfa.EnforceMFAEnrolled(r.Context(), s.db, collab.ID); err != nil {
		writeMappedError(w, err)
		return
	}
	options, err := s.contactMFAOptions(r.Context(), collab.ID)
	if err != nil || !options[req.Channel].Available || !options[req.Channel].Enrolled {
		if err == nil {
			err = repository.ErrContactUnavailable
		}
		writeContactMFAError(w, r, err)
		return
	}
	s.beginContactOTP(w, r, collab, req.Channel, "login", binding)
}

func (s *Server) beginContactOTP(w http.ResponseWriter, r *http.Request, collab model.Collaborator, channel, purpose, contextBinding string) {
	cfg, configured := loadContactDeliveryConfig(channel)
	if !configured {
		writeContactMFAError(w, r, repository.ErrContactUnavailable)
		return
	}
	contactBinding, recipient, err := s.contactOTPRecipient(r.Context(), collab.ID, channel)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	rawToken, code, err := mfa.GenerateContactOTP()
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	challenge, err := repository.IssueContactOTP(r.Context(), s.db, collab.ID, channel, purpose, contextBinding, contactBinding, rawToken, code)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	if err := s.deliverContactOTP(r.Context(), cfg, channel, recipient, code); err != nil {
		// No usable token leaves Core on failed/uncertain provider acceptance.
		// Adapter errors may contain message bodies: never log them here.
		writeContactMFAError(w, r, repository.ErrContactUnavailable)
		return
	}
	if err := repository.ActivateContactOTP(r.Context(), s.db, mfa.HashContactOTPToken(rawToken)); err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, contactOTPResponse{ChallengeToken: rawToken, Channel: channel, ExpiresAt: challenge.ExpiresAt, RetryAfter: 60})
}

// Recipient and binding come from one database snapshot. A later contact
// change is rejected again by issuance and verification under row locks.
func (s *Server) contactOTPRecipient(ctx context.Context, id uuid.UUID, channel string) (string, string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	binding, err := repository.ReadContactBinding(ctx, tx, id, channel)
	if err != nil {
		return "", "", err
	}
	var recipient string
	if channel == "email" {
		if err := tx.QueryRowContext(ctx, `SELECT primary_email FROM public.collaborators WHERE id=$1`, id).Scan(&recipient); err != nil {
			return "", "", err
		}
	} else if channel == "sms" {
		phone, err := repository.GetPhoneContact(ctx, tx, s.envelope, id)
		if err != nil || phone == nil {
			return "", "", repository.ErrContactUnavailable
		}
		recipient = phone.PhoneE164
	} else {
		return "", "", repository.ErrContactUnavailable
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return binding, strings.TrimSpace(recipient), nil
}

func (s *Server) deliverContactOTP(ctx context.Context, cfg contactDeliveryConfig, channel, recipient, code string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	brand, err := repository.GetTenantBrand(ctx, s.db)
	if err != nil {
		brand = model.TenantBrand{}
	}
	subject, body := contactOTPCopy(brand, code)
	operation := "send_email"
	input := map[string]any{"recipient": recipient, "to_addresses": []string{recipient}, "subject": subject, "body": body, "text_body": body}
	if cfg.From != "" {
		input["from"], input["from_email"] = cfg.From, cfg.From
	}
	if channel == "sms" {
		operation = "send_sms"
		input = map[string]any{"phone_number": recipient, "message": body, "sms_type": "Transactional"}
	}
	result, err := executeAuthEmailIntegration(ctx, s.rabbitmq, s.db, model.ExecuteIntegrationRequest{Integration: cfg.Integration, Operation: operation, Capability: operation, Input: input})
	if err != nil || result.Status != "sent" {
		return repository.ErrContactUnavailable
	}
	return nil
}

func contactOTPCopy(brand model.TenantBrand, code string) (string, string) {
	label := strings.TrimSpace(brand.ProductLabel)
	if label == "" {
		label = strings.TrimSpace(brand.Name)
	}
	if label == "" {
		label = "Yggdrasil"
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(brand.Locale)), "pt") || strings.TrimSpace(brand.Locale) == "" {
		return fmt.Sprintf("Código de verificação do %s", label), fmt.Sprintf("%s: seu código de verificação é %s. Válido por 5 minutos, para uso único. Não compartilhe este código. Se não foi você, ignore esta mensagem.", label, code)
	}
	return fmt.Sprintf("%s verification code", label), fmt.Sprintf("%s: your verification code is %s. Valid for 5 minutes, for one use. Do not share this code. If you did not request it, ignore this message.", label, code)
}

func (s *Server) handleMFAContactFinish(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req contactOTPRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, contextBinding, err := s.resolveContactEnrollment(r, strings.TrimSpace(req.Token), true)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	contactBinding, err := repository.ReadContactBinding(r.Context(), s.db, collab.ID, req.Channel)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	if err := repository.VerifyAndEnrollContactOTP(r.Context(), s.db, collab.ID, req.Channel, "enroll", contextBinding, contactBinding, req.ChallengeToken, req.Code, hashes); err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	s.recordAuthAuditCollaborator(r, AuditAuthMFAEnrolled, collab.ID, AuditOutcomeSuccess, map[string]any{"factor": req.Channel})
	writeJSON(w, http.StatusOK, map[string]any{"mfa_enrolled": true, "codes": codes, "displayed_once": true})
}

func (s *Server) handleMFAContactDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	collab, _, err := s.resolveContactEnrollment(r, "", true)
	if err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	channel := r.PathValue("channel")
	if err := repository.DisableContactMFAFactor(r.Context(), s.db, collab.ID, channel); err != nil {
		writeContactMFAError(w, r, err)
		return
	}
	s.recordAuthAuditCollaborator(r, AuditAuthMFAUnenrolled, collab.ID, AuditOutcomeSuccess, map[string]any{"factor": channel})
	w.WriteHeader(http.StatusNoContent)
}

func writeContactMFAError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := http.StatusServiceUnavailable, httperr.CodeAuthMFADeliveryUnavailable, "Verification code delivery is unavailable. Try another factor or contact your administrator."
	switch {
	case errors.Is(err, repository.ErrAuthInvalidCredentials), errors.Is(err, repository.ErrAuthAccountLocked):
		writeMappedError(w, err)
		return
	case errors.Is(err, errContactCSRF):
		status, code, detail = http.StatusForbidden, "csrf.token_mismatch", "CSRF token is required for changing MFA factors."
	case errors.Is(err, repository.ErrContactOTPRateLimited):
		status, code, detail = http.StatusTooManyRequests, httperr.CodeRateLimitExceeded, "Wait before requesting another verification code."
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, repository.ErrContactOTPInvalid):
		status, code, detail = http.StatusUnauthorized, httperr.CodeAuthMFAInvalid, "The verification code is invalid, expired, or already used."
	case errors.Is(err, repository.ErrLastMFAFactor):
		status, code, detail = http.StatusConflict, httperr.CodeAuthMFALastFactor, "Add another MFA factor before removing this one."
	case errors.Is(err, repository.ErrAuthSessionNotFound), errors.Is(err, repository.ErrAuthSessionExpired), errors.Is(err, repository.ErrMFAEnrollTokenNotFound), errors.Is(err, repository.ErrMFAEnrollTokenAlreadyConsumed), errors.Is(err, repository.ErrMFAEnrollTokenExpired):
		status, code, detail = http.StatusUnauthorized, httperr.CodeAuthUnauthenticated, "A valid enrollment link or session is required."
	}
	httperr.WriteProblem(w, status, code, "MFA verification", detail, httperr.WithInstance(r.URL.Path))
}

func (s *Server) verifyContactLoginOTP(r *http.Request, id uuid.UUID, contextBinding string, req model.LoginWithPasswordRequest) (model.AuthSession, string, error) {
	_, configured := loadContactDeliveryConfig(req.OTPChannel)
	if !configured {
		return model.AuthSession{}, "", repository.ErrContactUnavailable
	}
	contactBinding, err := repository.ReadContactBinding(r.Context(), s.db, id, req.OTPChannel)
	if err != nil {
		return model.AuthSession{}, "", err
	}
	session, token, err := repository.VerifyContactOTPAndCreateSession(r.Context(), s.db, id, req.OTPChannel, contextBinding, contactBinding, req.OTPChallengeToken, req.OTPCode, req, authSessionTTL())
	outcome, auditOutcome, auditAction := metrics.AuthMFAVerifySucceeded, AuditOutcomeSuccess, AuditAuthMFAVerifySucceeded
	if err != nil {
		outcome, auditOutcome, auditAction = metrics.AuthMFAVerifyFailed, AuditOutcomeFailure, AuditAuthMFAVerifyFailed
	}
	metrics.IncAuthMFAVerify(outcome, req.OTPChannel)
	s.recordAuthAuditCollaborator(r, auditAction, id, auditOutcome, map[string]any{"factor": req.OTPChannel})
	return session, token, err
}
