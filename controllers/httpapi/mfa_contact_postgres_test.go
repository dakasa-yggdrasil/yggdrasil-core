package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/rabbitmq/amqp091-go"
)

func contactOTPHTTPPostgres(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_MFA_CONTACT_POSTGRES") == "true" {
		t.Fatal("mandatory MFA HTTP PostgreSQL gate has no DB_URL")
	}
	return directoryHTTPPostgres(t)
}

func contactOTPHTTPPassword(t *testing.T, db *sql.DB, person model.Collaborator) string {
	t.Helper()
	plain := "cadernos-azuis-na-estante-73"
	if err := repository.UpsertAuthIdentity(context.Background(), db, person.ID, person.PrimaryEmail); err != nil {
		t.Fatal("MFA HTTP identity fixture failed")
	}
	scheme, hash, err := password.Hash(plain)
	if err != nil {
		t.Fatal("MFA HTTP password fixture failed")
	}
	if err := repository.SetPasswordHash(context.Background(), db, person.ID, hash, string(scheme), time.Now().Add(time.Hour)); err != nil {
		t.Fatal("MFA HTTP password persistence failed")
	}
	return plain
}

func contactOTPHTTPPhone(t *testing.T, db *sql.DB, person model.Collaborator) string {
	t.Helper()
	return contactOTPHTTPDeclarePhone(t, db, person, "+12025550108")
}

func contactOTPHTTPDeclarePhone(t *testing.T, db *sql.DB, person model.Collaborator, phone string) string {
	t.Helper()
	envelope, err := contactphone.EnvelopeFromEnv()
	if err != nil {
		t.Fatal("MFA HTTP contact encryption fixture failed")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("MFA HTTP contact transaction failed")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := repository.SetPhoneContactTx(context.Background(), tx, envelope, person.ID, phone, "collaborator:"+person.ID.String(), "self_profile"); err != nil {
		t.Fatal("MFA HTTP contact fixture failed")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal("MFA HTTP contact fixture commit failed")
	}
	return phone
}

func contactOTPHTTPEnrollLink(t *testing.T, db *sql.DB, person model.Collaborator) string {
	t.Helper()
	raw := uuid.NewString()
	if _, err := repository.IssueMFAEnrollToken(context.Background(), db, person.ID, hashEnrollToken(raw), time.Now().Add(time.Hour)); err != nil {
		t.Fatal("MFA HTTP enrollment authority fixture failed")
	}
	return raw
}

func contactOTPHTTPRequest(t *testing.T, handler http.Handler, method, path string, payload any, cookie, csrf string, client int) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal("MFA HTTP request fixture failed")
	}
	r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	// Distinct clients keep these owner-bound protocol checks independent of
	// the separately tested per-IP burst limiter. Database quotas still apply.
	r.RemoteAddr = fmt.Sprintf("192.0.2.%d:32001", client)
	r.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: cookie})
	}
	if csrf != "" {
		r.Header.Set(csrfHeaderName, csrf)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func contactOTPHTTPChallenge(t *testing.T, w *httptest.ResponseRecorder) contactOTPResponse {
	t.Helper()
	var challenge contactOTPResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &challenge) != nil || !mfa.ValidContactOTPToken(challenge.ChallengeToken) {
		t.Fatalf("MFA HTTP challenge status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || challenge.ExpiresAt.IsZero() || challenge.RetryAfter != 60 {
		t.Fatal("MFA HTTP challenge omitted privacy or expiry contract")
	}
	return challenge
}

func contactOTPHTTPCode(t *testing.T, req model.ExecuteIntegrationRequest) string {
	t.Helper()
	body, _ := req.Input["body"].(string)
	if req.Operation == "send_sms" {
		body, _ = req.Input["message"].(string)
	}
	code := regexp.MustCompile(`\b[0-9]{6}\b`).FindString(body)
	if !mfa.ValidContactOTPCode(code) {
		t.Fatal("delivery adapter did not receive a six-digit OTP")
	}
	return code
}

func contactOTPHTTPPosture(t *testing.T, db *sql.DB, id uuid.UUID, proved bool, sessions int) {
	t.Helper()
	var hasProof bool
	var storedFactors, storedSessions int
	if db.QueryRow(`SELECT mfa_enrolled_at IS NOT NULL FROM public.auth_identities WHERE collaborator_id=$1`, id).Scan(&hasProof) != nil || hasProof != proved {
		t.Fatal("automatic contact availability changed proof posture without successful authentication")
	}
	if db.QueryRow(`SELECT COUNT(*) FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1`, id).Scan(&storedFactors) != nil || storedFactors != 0 {
		t.Fatal("automatic contact login created or required contact enrollment rows")
	}
	if db.QueryRow(`SELECT COUNT(*) FROM public.auth_sessions WHERE collaborator_id=$1`, id).Scan(&storedSessions) != nil || storedSessions != sessions {
		t.Fatal("automatic contact login created a session before valid OTP proof")
	}
}

func contactOTPHTTPLogin(t *testing.T, w *httptest.ResponseRecorder) authLoginResponse {
	t.Helper()
	var login authLoginResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil || login.Session.ID == uuid.Nil || login.Token == "" || login.MFAEnrollmentRequired || login.MFAEnrollURL != "" {
		t.Fatalf("automatic contact OTP did not create a proved session: status=%d", w.Code)
	}
	sessionCookie, csrfCookie := false, false
	for _, cookie := range w.Result().Cookies() {
		sessionCookie = sessionCookie || cookie.Name == authSessionCookieName() && cookie.HttpOnly && cookie.Value == login.Token
		csrfCookie = csrfCookie || cookie.Name == csrfTokenCookieName && cookie.Value == computeCSRFToken(login.Session.ID)
	}
	if !sessionCookie || !csrfCookie {
		t.Fatal("automatic contact login omitted its authenticated or CSRF cookie")
	}
	return login
}

func TestMFAContactOTPHTTPPostgres(t *testing.T) {
	db := contactOTPHTTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("AUTH_EMAIL_INTEGRATION", "mfa-tests/mail")
	t.Setenv("AUTH_SMS_INTEGRATION", "mfa-tests/text")
	t.Setenv("AUTH_EMAIL_FROM", "security@example.test")

	for _, channel := range []string{"email", "sms"} {
		t.Run(channel+"_automatic_password_login", func(t *testing.T) {
			handler := directoryHTTPHandler(t, db)
			person := directoryHTTPPerson(t, db, false)
			plain := contactOTPHTTPPassword(t, db, person)
			recipient, operation, instance := person.PrimaryEmail, "send_email", "mail"
			if channel == "sms" {
				recipient = contactOTPHTTPPhone(t, db, person)
				operation, instance = "send_sms", "text"
			}
			previousExecute := executeAuthEmailIntegration
			t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
			var deliveredCode string
			sends := 0
			executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
				sends++
				if req.Operation != operation || req.Capability != operation || req.Integration.Namespace != "mfa-tests" || req.Integration.Name != instance {
					t.Fatal("automatic OTP changed the configured delivery selector")
				}
				key := "recipient"
				if channel == "sms" {
					key = "phone_number"
					if req.Input["sms_type"] != "Transactional" {
						t.Fatal("automatic SMS omitted transactional delivery purpose")
					}
				}
				if req.Input[key] != recipient {
					t.Fatal("automatic OTP escaped its current canonical recipient")
				}
				deliveredCode = contactOTPHTTPCode(t, req)
				return model.ExecuteIntegrationResponse{Status: "sent", Output: map[string]any{"provider_private": "adapter-output-must-stay-private"}}, nil
			}
			contactOTPHTTPPosture(t, db, person.ID, false, 0)
			rawAuthority := contactOTPHTTPEnrollLink(t, db, person)
			w := contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/mfa/contact/options?token="+rawAuthority, nil, "", "", 1)
			var options map[string]json.RawMessage
			var selectedOption struct {
				Available bool `json:"available"`
				Automatic bool `json:"automatic"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &options) != nil || json.Unmarshal(options[channel], &selectedOption) != nil || !selectedOption.Available || !selectedOption.Automatic || strings.Contains(w.Body.String(), `"enrolled"`) {
				t.Fatal("saved contact required opt-in instead of being automatically available")
			}
			var passwordLoginAvailable bool
			if json.Unmarshal(options["password_login_available"], &passwordLoginAvailable) != nil || !passwordLoginAvailable {
				t.Fatal("password-bearing account cannot reach automatic contact login")
			}
			credentials := map[string]any{"identifier": person.PrimaryEmail, "password": plain}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 2)
			var required authMFARequiredResponse
			if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &required) != nil || len(w.Result().Cookies()) != 0 {
				t.Fatal("first password login requested contact enrollment or skipped OTP proof")
			}
			found := false
			for _, factor := range required.Factors {
				found = found || factor == channel
			}
			if !found {
				t.Fatal("first password login omitted its automatic saved contact")
			}
			loginBegin := map[string]any{"identifier": person.PrimaryEmail, "password": "incorrect-password", "channel": channel}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 3)
			if w.Code != http.StatusUnauthorized || sends != 0 {
				t.Fatal("automatic OTP delivery did not require a server-verified password")
			}
			loginBegin["password"] = plain
			loginBegin["recipient"] = "attacker@example.test"
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 4)
			if w.Code < http.StatusBadRequest || sends != 0 {
				t.Fatal("automatic OTP accepted a caller-controlled recipient")
			}
			delete(loginBegin, "recipient")
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 5)
			challenge := contactOTPHTTPChallenge(t, w)
			if sends != 1 || strings.Contains(w.Body.String(), deliveredCode) || strings.Contains(w.Body.String(), recipient) || strings.Contains(w.Body.String(), "adapter-output-must-stay-private") {
				t.Fatal("automatic OTP challenge disclosed its code, recipient or adapter output")
			}
			contactOTPHTTPPosture(t, db, person.ID, false, 0)
			wrongCode := "000000"
			if wrongCode == deliveredCode {
				wrongCode = "000001"
			}
			credentials["otp_channel"], credentials["otp_challenge_token"], credentials["otp_code"] = channel, challenge.ChallengeToken, wrongCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 6)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatal("wrong automatic OTP established an authenticated session")
			}
			contactOTPHTTPPosture(t, db, person.ID, false, 0)
			if _, err := db.Exec(`UPDATE public.auth_identities SET password_must_change=TRUE WHERE collaborator_id=$1`, person.ID); err != nil {
				t.Fatal("automatic OTP forced-password-change fixture failed")
			}
			credentials["otp_code"] = deliveredCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 7)
			login := contactOTPHTTPLogin(t, w)
			if !login.PasswordChangeRequired {
				t.Fatal("automatic OTP lost the forced-password-change posture")
			}
			contactOTPHTTPPosture(t, db, person.ID, true, 1)
			w = contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/session", nil, login.Token, "", 8)
			var session struct {
				Authenticated      bool       `json:"authenticated"`
				MFAEnrolledAt      *time.Time `json:"mfa_enrolled_at"`
				RecentContactProof bool       `json:"recent_contact_mfa_verified"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &session) != nil || !session.Authenticated || session.MFAEnrolledAt == nil || !session.RecentContactProof {
				t.Fatal("automatic contact proof did not cross the existing session guards")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 9)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatal("consumed automatic OTP created another session")
			}
			newPassword := "estante-laranja-com-cadernos-94"
			change := map[string]any{"current_password": plain, "new_password": newPassword, "use_recent_contact_mfa": true}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/passwords/change", change, login.Token, "", 10)
			if w.Code != http.StatusForbidden {
				t.Fatal("recent contact proof changed a password without matching CSRF")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/passwords/change", change, login.Token, computeCSRFToken(login.Session.ID), 11)
			if w.Code != http.StatusOK {
				t.Fatalf("automatic contact-only account was stranded during forced password change: status=%d", w.Code)
			}
			change["current_password"], change["new_password"] = newPassword, "cadernos-roxos-perto-da-janela-81"
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/passwords/change", change, login.Token, computeCSRFToken(login.Session.ID), 12)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("recent contact proof authorized another password change after being consumed")
			}
			// An updated profile contact is immediately available; pending proof
			// from the previous declaration cannot transfer to the new contact.
			if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=clock_timestamp()-INTERVAL '61 seconds' WHERE collaborator_id=$1`, person.ID); err != nil {
				t.Fatal("automatic OTP contact-change timing fixture failed")
			}
			loginBegin["password"] = newPassword
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 13)
			oldContact := contactOTPHTTPChallenge(t, w)
			oldCode := deliveredCode
			if channel == "email" {
				recipient = person.ID.String() + "-changed@example.test"
				if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, person.ID, recipient); err != nil {
					t.Fatal("automatic OTP email-change fixture failed")
				}
				loginBegin["identifier"], credentials["identifier"] = recipient, recipient
			} else {
				recipient = contactOTPHTTPDeclarePhone(t, db, person, "+12025550109")
			}
			credentials["password"], credentials["otp_challenge_token"], credentials["otp_code"] = newPassword, oldContact.ChallengeToken, oldCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 14)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatal("old contact proof survived a profile recipient change")
			}
			if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=clock_timestamp()-INTERVAL '61 seconds' WHERE collaborator_id=$1`, person.ID); err != nil {
				t.Fatal("automatic OTP new-contact timing fixture failed")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 15)
			newContact := contactOTPHTTPChallenge(t, w)
			credentials["otp_challenge_token"], credentials["otp_code"] = newContact.ChallengeToken, deliveredCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 16)
			_ = contactOTPHTTPLogin(t, w)
			contactOTPHTTPPosture(t, db, person.ID, true, 2)
		})
	}

	t.Run("contact_login_preserves_classic_factor_confirmation", func(t *testing.T) {
		for _, scenario := range []struct {
			name          string
			confirmed     bool
			beginAfterOTP bool
		}{
			{name: "pending_begin_only"},
			{name: "confirmed_totp", confirmed: true},
			{name: "pending_after_contact", beginAfterOTP: true},
		} {
			t.Run(scenario.name, func(t *testing.T) {
				handler := directoryHTTPHandler(t, db)
				person := directoryHTTPPerson(t, db, false)
				plain := contactOTPHTTPPassword(t, db, person)
				rawAuthority := contactOTPHTTPEnrollLink(t, db, person)
				var w *httptest.ResponseRecorder
				var begun totpBeginResponse
				if !scenario.beginAfterOTP {
					w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/totp/begin", map[string]any{"token": rawAuthority}, "", "", 1)
					if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &begun) != nil || begun.Secret == "" {
						t.Fatal("classic TOTP begin fixture did not generate an unconfirmed secret")
					}
				}
				if scenario.confirmed {
					code, err := totp.GenerateCode(begun.Secret, time.Now())
					if err != nil {
						t.Fatal("classic TOTP confirmation fixture failed")
					}
					w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/totp/finish", map[string]any{"token": rawAuthority, "code": code}, "", "", 2)
					if w.Code != http.StatusOK {
						t.Fatal("classic TOTP finish fixture did not confirm the factor")
					}
				}
				var beforeCiphertext, beforeDEK []byte
				var wasConfirmed bool
				if db.QueryRow(`SELECT totp_secret_ciphertext,totp_secret_dek,mfa_enrolled_at IS NOT NULL FROM public.auth_identities WHERE collaborator_id=$1`, person.ID).Scan(&beforeCiphertext, &beforeDEK, &wasConfirmed) != nil || wasConfirmed != scenario.confirmed || !scenario.beginAfterOTP && (len(beforeCiphertext) == 0 || len(beforeDEK) == 0) {
					t.Fatal("classic factor fixture has the wrong confirmation posture")
				}
				previousExecute := executeAuthEmailIntegration
				t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
				var contactCode string
				executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
					contactCode = contactOTPHTTPCode(t, req)
					return model.ExecuteIntegrationResponse{Status: "sent"}, nil
				}
				w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", map[string]any{"identifier": person.PrimaryEmail, "password": plain, "channel": "email"}, "", "", 3)
				challenge := contactOTPHTTPChallenge(t, w)
				w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"identifier": person.PrimaryEmail, "password": plain, "otp_channel": "email", "otp_challenge_token": challenge.ChallengeToken, "otp_code": contactCode}, "", "", 4)
				login := contactOTPHTTPLogin(t, w)
				if scenario.beginAfterOTP {
					w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/totp/begin", map[string]any{}, login.Token, computeCSRFToken(login.Session.ID), 5)
					if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &begun) != nil || begun.Secret == "" {
						t.Fatal("classic TOTP begin after contact authentication failed")
					}
				}
				var afterCiphertext, afterDEK []byte
				if db.QueryRow(`SELECT totp_secret_ciphertext,totp_secret_dek FROM public.auth_identities WHERE collaborator_id=$1`, person.ID).Scan(&afterCiphertext, &afterDEK) != nil {
					t.Fatal("post-contact classic factor observation failed")
				}
				if scenario.beginAfterOTP {
					if len(afterCiphertext) == 0 || len(afterDEK) == 0 {
						t.Fatal("post-contact TOTP begin did not persist an encrypted pending seed")
					}
				} else if !bytes.Equal(beforeCiphertext, afterCiphertext) || !bytes.Equal(beforeDEK, afterDEK) {
					t.Fatal("automatic contact login changed the separate classic enrollment state")
				}
				w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"identifier": person.PrimaryEmail, "password": plain}, "", "", 5)
				var required authMFARequiredResponse
				if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &required) != nil || len(w.Result().Cookies()) != 0 {
					t.Fatal("post-contact password login did not require another second-factor proof")
				}
				offersTOTP := false
				for _, factor := range required.Factors {
					offersTOTP = offersTOTP || factor == "totp"
				}
				if offersTOTP != scenario.confirmed {
					t.Fatal("automatic contact login lost the distinction between pending and confirmed TOTP")
				}
				if !scenario.confirmed {
					code, err := totp.GenerateCode(begun.Secret, time.Now())
					if err != nil {
						t.Fatal("pending classic confirmation code fixture failed")
					}
					w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/totp/finish", map[string]any{"code": code}, login.Token, computeCSRFToken(login.Session.ID), 6)
					if w.Code != http.StatusOK {
						t.Fatal("pending TOTP could not be confirmed independently after contact authentication")
					}
					w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"identifier": person.PrimaryEmail, "password": plain}, "", "", 7)
					if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &required) != nil {
						t.Fatal("confirmed classic factor login inventory unavailable")
					}
					offersTOTP = false
					for _, factor := range required.Factors {
						offersTOTP = offersTOTP || factor == "totp"
					}
					if !offersTOTP {
						t.Fatal("independent confirmation did not make the pending classic factor available")
					}
				}
				contactOTPHTTPPosture(t, db, person.ID, true, 1)
			})
		}
	})

	t.Run("sso_only_options_never_offer_password_login", func(t *testing.T) {
		handler := directoryHTTPHandler(t, db)
		person := directoryHTTPPerson(t, db, false)
		if err := repository.UpsertAuthIdentity(context.Background(), db, person.ID, person.PrimaryEmail); err != nil {
			t.Fatal("SSO-only option fixture failed")
		}
		authority := contactOTPHTTPEnrollLink(t, db, person)
		w := contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/mfa/contact/options?token="+authority, nil, "", "", 1)
		var options struct {
			Email                  contactMFAOption `json:"email"`
			PasswordLoginAvailable bool             `json:"password_login_available"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &options) != nil || !options.Email.Available || !options.Email.Automatic || options.PasswordLoginAvailable {
			t.Fatal("SSO-only profile metadata promised a local password login")
		}
	})

	t.Run("failed_delivery_never_activates_or_discloses_a_challenge", func(t *testing.T) {
		for _, outcome := range []string{"failed", "pending", "provider_error"} {
			t.Run(outcome, func(t *testing.T) {
				handler := directoryHTTPHandler(t, db)
				person := directoryHTTPPerson(t, db, false)
				plain := contactOTPHTTPPassword(t, db, person)
				previousExecute := executeAuthEmailIntegration
				t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
				var code string
				executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
					code = contactOTPHTTPCode(t, req)
					if outcome == "provider_error" {
						return model.ExecuteIntegrationResponse{}, fmt.Errorf("adapter echoed %s %s provider-detail", person.PrimaryEmail, code)
					}
					return model.ExecuteIntegrationResponse{Status: outcome, Output: map[string]any{"code": code}}, nil
				}
				w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", map[string]any{"identifier": person.PrimaryEmail, "password": plain, "channel": "email"}, "", "", 1)
				if w.Code != http.StatusServiceUnavailable || code == "" || strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), person.PrimaryEmail) || strings.Contains(w.Body.String(), "provider-detail") || strings.Contains(w.Body.String(), "challenge_token") {
					t.Fatal("uncertain automatic delivery disclosed provider material or a usable challenge")
				}
				var reserved, active int
				if err := db.QueryRow(`SELECT COUNT(*),COUNT(delivered_at) FROM public.auth_mfa_contact_challenges WHERE collaborator_id=$1`, person.ID).Scan(&reserved, &active); err != nil || reserved != 1 || active != 0 {
					t.Fatal("failed automatic delivery escaped its sending budget or activated a challenge")
				}
				contactOTPHTTPPosture(t, db, person.ID, false, 0)
			})
		}
	})

	t.Run("no_contact_activation_or_disable_routes", func(t *testing.T) {
		handler := directoryHTTPHandler(t, db)
		person := directoryHTTPPerson(t, db, false)
		_ = contactOTPHTTPPassword(t, db, person)
		session, rawSession, err := repository.CreateAuthSession(context.Background(), db, person.ID, nil, time.Hour)
		if err != nil {
			t.Fatal("removed-contact-route session fixture failed")
		}
		for _, route := range []struct{ method, path string }{
			{http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin"},
			{http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish"},
			{http.MethodDelete, "/api/v1/auth/mfa/factors/contact/email"},
			{http.MethodDelete, "/api/v1/auth/mfa/factors/contact/sms"},
		} {
			w := contactOTPHTTPRequest(t, handler, route.method, route.path, map[string]any{"channel": "email"}, rawSession, computeCSRFToken(session.ID), 1)
			if w.Code != http.StatusNotFound {
				t.Fatal("contact channel retained an enrollment, activation or disable route")
			}
		}
		contactOTPHTTPPosture(t, db, person.ID, false, 1)
	})

	t.Run("setup_uses_automatic_contact_without_creating_session", func(t *testing.T) {
		handler := directoryHTTPHandler(t, db)
		person := directoryHTTPPerson(t, db, false)
		raw := uuid.NewString()
		if _, err := repository.IssueCredentialToken(context.Background(), db, repository.IssueCredentialTokenInput{CollaboratorID: person.ID, Purpose: model.CredentialTokenPurposeSetup, TokenHash: password.HashToken(raw), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal("automatic-contact setup fixture failed")
		}
		w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/passwords/setup", map[string]any{"token": raw, "new_password": "livros-amarelos-em-cima-da-mesa-76"}, "", "", 1)
		var setup struct {
			Status             string `json:"status"`
			Next               string `json:"next"`
			EnrollmentRequired bool   `json:"mfa_enrollment_required"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &setup) != nil || setup.Status != "password_set" || setup.Next != "login" || setup.EnrollmentRequired || len(w.Result().Cookies()) != 0 {
			t.Fatal("password setup required contact activation or created a session without OTP")
		}
		contactOTPHTTPPosture(t, db, person.ID, false, 0)
	})

	t.Run("expired_recent_contact_proof_cannot_change_password", func(t *testing.T) {
		handler := directoryHTTPHandler(t, db)
		person := directoryHTTPPerson(t, db, false)
		plain := contactOTPHTTPPassword(t, db, person)
		previousExecute := executeAuthEmailIntegration
		t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
		var code string
		executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
			code = contactOTPHTTPCode(t, req)
			return model.ExecuteIntegrationResponse{Status: "sent"}, nil
		}
		w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", map[string]any{"identifier": person.PrimaryEmail, "password": plain, "channel": "email"}, "", "", 1)
		challenge := contactOTPHTTPChallenge(t, w)
		w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"identifier": person.PrimaryEmail, "password": plain, "otp_channel": "email", "otp_challenge_token": challenge.ChallengeToken, "otp_code": code}, "", "", 2)
		login := contactOTPHTTPLogin(t, w)
		if _, err := db.Exec(`UPDATE public.auth_contact_session_proofs SET verified_at=clock_timestamp()-INTERVAL '6 minutes' WHERE session_id=$1`, login.Session.ID); err != nil {
			t.Fatal("expired recent-contact proof fixture failed")
		}
		w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/passwords/change", map[string]any{"current_password": plain, "new_password": "arvore-laranja-perto-do-portao-39", "use_recent_contact_mfa": true}, login.Token, computeCSRFToken(login.Session.ID), 3)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("stale contact proof authorized a password change")
		}
		if repository.VerifyPassword(context.Background(), db, person.ID, plain) != nil {
			t.Fatal("rejected stale proof changed the password")
		}
	})
}
