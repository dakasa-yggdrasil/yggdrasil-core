package httpapi

import (
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
	envelope, err := contactphone.EnvelopeFromEnv()
	if err != nil {
		t.Fatal("MFA HTTP contact encryption fixture failed")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal("MFA HTTP contact transaction failed")
	}
	defer func() { _ = tx.Rollback() }()
	phone := "+12025550108"
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

func TestMFAContactOTPHTTPPostgres(t *testing.T) {
	db := contactOTPHTTPPostgres(t)
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("AUTH_EMAIL_INTEGRATION", "mfa-tests/mail")
	t.Setenv("AUTH_SMS_INTEGRATION", "mfa-tests/text")
	t.Setenv("AUTH_EMAIL_FROM", "security@example.test")

	for _, channel := range []string{"email", "sms"} {
		t.Run(channel+"_enrollment_and_password_login", func(t *testing.T) {
			handler := directoryHTTPHandler(t, db)
			person := directoryHTTPPerson(t, db, false)
			plain := contactOTPHTTPPassword(t, db, person)
			recipient, operation, instance := person.PrimaryEmail, "send_email", "mail"
			if channel == "sms" {
				recipient = contactOTPHTTPPhone(t, db, person)
				operation, instance = "send_sms", "text"
			}
			rawEnroll := contactOTPHTTPEnrollLink(t, db, person)
			previousExecute := executeAuthEmailIntegration
			t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
			var deliveredCode string
			sends := 0
			executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
				sends++
				if req.Operation != operation || req.Capability != operation || req.Integration.Namespace != "mfa-tests" || req.Integration.Name != instance {
					t.Fatal("MFA HTTP request changed the configured delivery selector")
				}
				key := "recipient"
				if channel == "sms" {
					key = "phone_number"
					if req.Input["sms_type"] != "Transactional" {
						t.Fatal("MFA SMS omitted transactional delivery purpose")
					}
				}
				if req.Input[key] != recipient {
					t.Fatal("MFA HTTP delivery escaped the canonical recipient")
				}
				deliveredCode = contactOTPHTTPCode(t, req)
				return model.ExecuteIntegrationResponse{Status: "sent", Output: map[string]any{"provider_private": "adapter-output-must-stay-private"}}, nil
			}
			w := contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/mfa/contact/options?token="+rawEnroll, nil, "", "", 1)
			var options map[string]contactMFAOption
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &options) != nil || !options[channel].Available || options[channel].Enrolled {
				t.Fatal("MFA enrollment options did not expose the available canonical contact")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin", map[string]any{"token": rawEnroll, "channel": channel, "recipient": "attacker@example.test"}, "", "", 2)
			if w.Code < http.StatusBadRequest || sends != 0 {
				t.Fatal("MFA request accepted a caller-controlled recipient")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin", map[string]any{"token": rawEnroll, "channel": channel}, "", "", 2)
			challenge := contactOTPHTTPChallenge(t, w)
			if sends != 1 || strings.Contains(w.Body.String(), deliveredCode) || strings.Contains(w.Body.String(), recipient) || strings.Contains(w.Body.String(), "adapter-output-must-stay-private") {
				t.Fatal("MFA challenge disclosed the code, recipient or adapter output")
			}
			wrongCode := "000000"
			if wrongCode == deliveredCode {
				wrongCode = "000001"
			}
			finish := map[string]any{"token": rawEnroll, "channel": channel, "challenge_token": challenge.ChallengeToken, "code": wrongCode}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish", finish, "", "", 3)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("wrong OTP enrolled a contact factor")
			}
			finish["code"] = deliveredCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish", finish, "", "", 4)
			var enrollment struct {
				Enrolled bool     `json:"mfa_enrolled"`
				Codes    []string `json:"codes"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &enrollment) != nil || !enrollment.Enrolled || len(enrollment.Codes) != mfa.RecoveryCodeCount || len(w.Result().Cookies()) != 0 {
				t.Fatal("contact enrollment did not persist MFA and one-time recovery codes without a session")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish", finish, "", "", 5)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("enrollment authority or OTP could be replayed")
			}
			credentials := map[string]any{"identifier": person.PrimaryEmail, "password": plain}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 6)
			var required authMFARequiredResponse
			if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &required) != nil || len(w.Result().Cookies()) != 0 {
				t.Fatal("password-only login bypassed the contact MFA gate")
			}
			found := false
			for _, factor := range required.Factors {
				found = found || factor == channel
			}
			if !found {
				t.Fatal("password login omitted the enrolled contact factor")
			}
			if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=NOW()-INTERVAL '61 seconds' WHERE collaborator_id=$1`, person.ID); err != nil {
				t.Fatal("MFA resend timing fixture failed")
			}
			loginBegin := map[string]any{"identifier": person.PrimaryEmail, "password": "incorrect-password", "channel": channel}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 7)
			if w.Code != http.StatusUnauthorized || sends != 1 {
				t.Fatal("contact OTP delivery did not require a server-verified password")
			}
			if _, err := db.Exec(`UPDATE public.auth_identities SET password_must_change=TRUE WHERE collaborator_id=$1`, person.ID); err != nil {
				t.Fatal("MFA forced-password-change fixture failed")
			}
			loginBegin["password"] = plain
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 8)
			loginChallenge := contactOTPHTTPChallenge(t, w)
			credentials["otp_channel"], credentials["otp_challenge_token"], credentials["otp_code"] = channel, loginChallenge.ChallengeToken, deliveredCode
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 9)
			var login authLoginResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil || login.Session.ID == uuid.Nil || login.Token == "" || !login.PasswordChangeRequired {
				t.Fatalf("contact OTP login did not create a session: status=%d", w.Code)
			}
			sessionCookie, csrfCookie := false, false
			for _, cookie := range w.Result().Cookies() {
				sessionCookie = sessionCookie || cookie.Name == authSessionCookieName() && cookie.HttpOnly && cookie.Value == login.Token
				csrfCookie = csrfCookie || cookie.Name == csrfTokenCookieName && cookie.Value == computeCSRFToken(login.Session.ID)
			}
			if !sessionCookie || !csrfCookie {
				t.Fatal("contact OTP login omitted its authenticated or CSRF cookie")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/session", nil, login.Token, "", 10)
			var session model.AuthSessionEnvelope
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &session) != nil || !session.Authenticated || session.MFAEnrolledAt == nil {
				t.Fatal("contact OTP login did not create a usable authenticated session")
			}
			w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 11)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatal("consumed login OTP created another session")
			}
			if channel == "email" {
				if _, err := db.Exec(`UPDATE public.auth_mfa_contact_challenges SET created_at=NOW()-INTERVAL '61 seconds' WHERE collaborator_id=$1`, person.ID); err != nil {
					t.Fatal("MFA email-change timing fixture failed")
				}
				w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/contact/login/begin", loginBegin, "", "", 12)
				beforeEmailChange := contactOTPHTTPChallenge(t, w)
				credentials["otp_challenge_token"], credentials["otp_code"] = beforeEmailChange.ChallengeToken, deliveredCode
				if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, person.ID, person.ID.String()+"-changed@example.test"); err != nil {
					t.Fatal("MFA email-change fixture failed")
				}
				if _, err := db.Exec(`UPDATE public.collaborators SET primary_email=$2 WHERE id=$1`, person.ID, person.PrimaryEmail); err != nil {
					t.Fatal("MFA email-revert fixture failed")
				}
				w = contactOTPHTTPRequest(t, handler, http.MethodGet, "/api/v1/auth/mfa/contact/options", nil, login.Token, "", 13)
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &options) != nil || options["email"].Enrolled {
					t.Fatal("changing and reverting an email revived its old MFA factor")
				}
				w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/login", credentials, "", "", 14)
				if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
					t.Fatal("changing and reverting an email revived its old OTP challenge")
				}
			}
		})
	}

	t.Run("failed_delivery_never_activates_or_discloses_a_challenge", func(t *testing.T) {
		for _, outcome := range []string{"failed", "pending", "provider_error"} {
			t.Run(outcome, func(t *testing.T) {
				handler := directoryHTTPHandler(t, db)
				person := directoryHTTPPerson(t, db, false)
				rawEnroll := contactOTPHTTPEnrollLink(t, db, person)
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
				w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin", map[string]any{"token": rawEnroll, "channel": "email"}, "", "", 1)
				if w.Code != http.StatusServiceUnavailable || code == "" || strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), person.PrimaryEmail) || strings.Contains(w.Body.String(), "provider-detail") || strings.Contains(w.Body.String(), "challenge_token") {
					t.Fatal("failed or uncertain OTP delivery disclosed provider material or a usable challenge")
				}
				var reserved, active int
				if err := db.QueryRow(`SELECT COUNT(*),COUNT(delivered_at) FROM public.auth_mfa_contact_challenges WHERE collaborator_id=$1`, person.ID).Scan(&reserved, &active); err != nil || reserved != 1 || active != 0 {
					t.Fatal("failed delivery escaped its sending budget or activated a challenge")
				}
			})
		}
	})

	t.Run("session_enrollment_requires_live_csrf_even_in_warn_mode", func(t *testing.T) {
		t.Setenv("YGGDRASIL_CSRF_ENFORCE", "warn")
		handler := directoryHTTPHandler(t, db)
		person := directoryHTTPPerson(t, db, false)
		_ = contactOTPHTTPPassword(t, db, person)
		session, rawSession, err := repository.CreateAuthSession(context.Background(), db, person.ID, nil, time.Hour)
		if err != nil {
			t.Fatal("MFA HTTP session fixture failed")
		}
		previousExecute := executeAuthEmailIntegration
		t.Cleanup(func() { executeAuthEmailIntegration = previousExecute })
		sends := 0
		var code string
		executeAuthEmailIntegration = func(_ context.Context, _ *amqp091.Connection, _ *sql.DB, req model.ExecuteIntegrationRequest) (model.ExecuteIntegrationResponse, error) {
			sends++
			code = contactOTPHTTPCode(t, req)
			return model.ExecuteIntegrationResponse{Status: "sent"}, nil
		}
		for index, csrf := range []string{"", computeCSRFToken(uuid.New())} {
			w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin", map[string]any{"channel": "email"}, rawSession, csrf, index+1)
			if w.Code != http.StatusForbidden || sends != 0 {
				t.Fatal("session enrollment delivered OTP without matching CSRF proof")
			}
		}
		w := contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/begin", map[string]any{"channel": "email"}, rawSession, computeCSRFToken(session.ID), 3)
		challenge := contactOTPHTTPChallenge(t, w)
		finish := map[string]any{"channel": "email", "challenge_token": challenge.ChallengeToken, "code": code}
		w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish", finish, rawSession, "", 4)
		if w.Code != http.StatusForbidden {
			t.Fatal("session enrollment finish skipped CSRF proof")
		}
		if _, err := db.Exec(`UPDATE public.auth_sessions SET status='revoked',revoked_at=NOW() WHERE id=$1`, session.ID); err != nil {
			t.Fatal("MFA HTTP session revocation fixture failed")
		}
		w = contactOTPHTTPRequest(t, handler, http.MethodPost, "/api/v1/auth/mfa/factors/contact/finish", finish, rawSession, computeCSRFToken(session.ID), 5)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("revoked enrollment session enabled a contact factor")
		}
		var factors int
		if db.QueryRow(`SELECT COUNT(*) FROM public.auth_mfa_contact_factors WHERE collaborator_id=$1`, person.ID).Scan(&factors) != nil || factors != 0 {
			t.Fatal("revoked session persisted a contact MFA factor")
		}
	})
}
