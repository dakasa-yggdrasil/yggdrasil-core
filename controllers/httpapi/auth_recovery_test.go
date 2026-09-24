package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// The reset email must never be built from request headers: /forgot is
// anonymous, so a forged X-Forwarded-Host would mail a real token to an
// attacker's domain. Without a configured origin, delivery is off.
func TestPasswordResetEmailConfigRequiresConfiguredOrigin(t *testing.T) {
	t.Setenv("AUTH_EMAIL_INTEGRATION", "dakasa/integration-aws-dakasa")
	t.Setenv("YGGDRASIL_CONSOLE_URL", "")
	t.Setenv("YGGDRASIL_PUBLIC_BASE_URL", "")
	if _, ok := loadPasswordResetEmailConfig(); ok {
		t.Fatal("delivery must be off without a configured console origin")
	}

	t.Setenv("YGGDRASIL_PUBLIC_BASE_URL", "not a url")
	if _, ok := loadPasswordResetEmailConfig(); ok {
		t.Fatal("an unparseable origin must not enable delivery")
	}

	t.Setenv("YGGDRASIL_CONSOLE_URL", "https://yggdrasil.example.com/")
	cfg, ok := loadPasswordResetEmailConfig()
	if !ok {
		t.Fatal("delivery should be on with an integration and a console origin")
	}
	if cfg.linkBase != "https://yggdrasil.example.com" {
		t.Fatalf("link base: got %q", cfg.linkBase)
	}
	if cfg.integration.Namespace != "dakasa" || cfg.integration.Name != "integration-aws-dakasa" {
		t.Fatalf("integration selector: got %+v", cfg.integration)
	}
}

func TestPasswordResetEmailConfigRequiresIntegration(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_URL", "https://yggdrasil.example.com")
	for _, ref := range []string{"", "no-slash", "/name", "namespace/"} {
		t.Setenv("AUTH_EMAIL_INTEGRATION", ref)
		if _, ok := loadPasswordResetEmailConfig(); ok {
			t.Fatalf("AUTH_EMAIL_INTEGRATION=%q must not enable delivery", ref)
		}
	}
}

func TestBuildPasswordResetURLEscapesToken(t *testing.T) {
	got := buildPasswordResetURL("https://y.example.com/", "a+b/c=")
	want := "https://y.example.com/reset?token=a%2Bb%2Fc%3D"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPasswordResetEmailFollowsTenantLocale(t *testing.T) {
	link := "https://y.example.com/reset?token=abc"

	subject, body := passwordResetEmail(model.TenantBrand{ProductLabel: "Yggdrasil", Locale: "pt-BR", SupportEmail: "suporte@example.com"}, "Lucas", link, 24*time.Hour)
	if !strings.Contains(subject, "Redefinição de senha") {
		t.Fatalf("pt subject: %q", subject)
	}
	for _, want := range []string{"Olá, Lucas,", link, "24 horas", "suporte@example.com", "verificação em duas etapas"} {
		if !strings.Contains(body, want) {
			t.Fatalf("pt body missing %q:\n%s", want, body)
		}
	}

	subject, body = passwordResetEmail(model.TenantBrand{Name: "Acme", Locale: "en-US"}, "", link, 2*time.Hour)
	if subject != "Reset your Acme password" {
		t.Fatalf("en subject: %q", subject)
	}
	if !strings.Contains(body, "Hi,") || !strings.Contains(body, "2 hours") || !strings.Contains(body, link) {
		t.Fatalf("en body:\n%s", body)
	}
	if strings.ContainsAny(subject+body, "\u2014\u2013") {
		t.Fatal("email copy must not contain em or en dashes")
	}
}

func TestPasswordPolicyReasonIsStable(t *testing.T) {
	cases := map[error]string{
		password.ErrPasswordTooShort:         "too_short",
		password.ErrPasswordContainsIdentity: "contains_identity",
		password.ErrPasswordTooCommon:        "too_common",
		errors.New("something else"):         "policy",
	}
	for err, want := range cases {
		if got := passwordPolicyReason(err); got != want {
			t.Errorf("%v: got %q, want %q", err, got, want)
		}
	}
}

// Regression for the 12-character trap: the email domain is an identity
// token, so a password built on the company name is refused server-side.
// The console mirrors this rule; this pins the server behavior it mirrors.
func TestPasswordPolicyRejectsEmailDomain(t *testing.T) {
	err := password.ValidateStrength("Dakasa@2026!", 12, map[string]struct{}{}, []string{"lucas@dakasa.me", "lucas", "Lucas"})
	if !errors.Is(err, password.ErrPasswordContainsIdentity) {
		t.Fatalf("got %v, want ErrPasswordContainsIdentity", err)
	}
}

func TestClassifyResetToken(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	tokenID, collabID := uuid.New(), uuid.New()

	cases := []struct {
		name       string
		consumedAt sql.NullTime
		expiresAt  time.Time
		err        error
		wantStatus int
		wantReason string
	}{
		{"not found", sql.NullTime{}, time.Time{}, sql.ErrNoRows, http.StatusUnauthorized, "not_found"},
		{"already used", sql.NullTime{Time: now, Valid: true}, now.Add(time.Hour), nil, http.StatusUnauthorized, "already_used"},
		{"expired", sql.NullTime{}, now.Add(-time.Minute), nil, http.StatusUnauthorized, "expired"},
		{"db error", sql.NullTime{}, time.Time{}, errors.New("boom"), http.StatusInternalServerError, ""},
		{"usable", sql.NullTime{}, now.Add(time.Hour), nil, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotToken, gotCollab, _, rej := classifyResetToken(tokenID, collabID, tc.expiresAt, tc.consumedAt, tc.err, now)
			if tc.wantStatus == 0 {
				if rej != nil {
					t.Fatalf("unexpected rejection %+v", rej)
				}
				if gotToken != tokenID || gotCollab != collabID {
					t.Fatal("usable token must return its ids")
				}
				return
			}
			if rej == nil || rej.status != tc.wantStatus {
				t.Fatalf("got %+v, want status %d", rej, tc.wantStatus)
			}
			if tc.wantReason != "" {
				if rej.code != httperr.CodeAuthResetTokenInvalid || rej.extras["reason"] != tc.wantReason {
					t.Fatalf("got code=%s reason=%v, want %s", rej.code, rej.extras["reason"], tc.wantReason)
				}
			}
		})
	}
}

func TestInlineResetFactors(t *testing.T) {
	if got := inlineResetFactors(repository.CredentialAccountState{HasTOTP: true}); len(got) != 0 {
		t.Fatalf("unenrolled identity must offer no inline factor, got %v", got)
	}
	got := inlineResetFactors(repository.CredentialAccountState{MFAEnrolled: true, HasTOTP: true, HasRecoveryCodes: true, PasskeyCount: 2})
	if strings.Join(got, ",") != "totp,recovery_code" {
		t.Fatalf("got %v", got)
	}
	// Passkey-only accounts cannot prove a factor inline yet: the page must
	// route them to an administrator instead of an unusable form.
	if got := inlineResetFactors(repository.CredentialAccountState{MFAEnrolled: true, PasskeyCount: 1}); len(got) != 0 {
		t.Fatalf("passkey-only identity: got %v", got)
	}
}

func TestForgotOptionsReportsDelivery(t *testing.T) {
	t.Setenv("AUTH_EMAIL_INTEGRATION", "")
	w := httptest.NewRecorder()
	(&Server{}).handleForgotOptions(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/passwords/forgot/options", nil))
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || body["email_delivery"] != false {
		t.Fatalf("status=%d body=%v", w.Code, body)
	}

	t.Setenv("AUTH_EMAIL_INTEGRATION", "dakasa/integration-aws-dakasa")
	t.Setenv("YGGDRASIL_CONSOLE_URL", "https://yggdrasil.example.com")
	w = httptest.NewRecorder()
	(&Server{}).handleForgotOptions(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/passwords/forgot/options", nil))
	body = map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["email_delivery"] != true {
		t.Fatalf("body=%v", body)
	}
}

func TestResetPreflightMissingToken(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).handleResetPreflight(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/passwords/reset/preflight", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestPasswordResetMissingToken(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/reset", strings.NewReader(`{"new_password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	(&Server{}).handlePasswordReset(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLinkValidityNeverOverPromises(t *testing.T) {
	cases := []struct {
		ttl    time.Duration
		pt, en string
	}{
		{24 * time.Hour, "24 horas", "24 hours"},
		{time.Hour, "1 hora", "1 hour"},
		{30 * time.Minute, "30 minutos", "30 minutes"},
		{90 * time.Minute, "90 minutos", "90 minutes"},
		{time.Minute, "1 minuto", "1 minute"},
	}
	for _, tc := range cases {
		pt, en := linkValidity(tc.ttl)
		if pt != tc.pt || en != tc.en {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.ttl, pt, en, tc.pt, tc.en)
		}
	}
}

// The credential events are schema-validated inside EmitEvent; a payload
// the schema rejects is silently lost (best-effort emits) or rolls back the
// admin reset (in-transaction emit). Pin the exact shapes the handlers build.
func TestCredentialEventPayloadsMatchTheirSchemas(t *testing.T) {
	adminID := uuid.New().String()
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		eventType string
		payload   map[string]any
	}{
		{repository.EventTypeCredentialSetupTokenIssued, map[string]any{
			"token_id": uuid.New().String(), "collaborator_id": uuid.New().String(),
			"expires_at": expires, "purpose": "setup", "issued_by_id": adminID, "mfa_reset": true,
		}},
		{repository.EventTypeCredentialResetTokenIssued, map[string]any{
			"token_id": uuid.New().String(), "collaborator_id": uuid.New().String(),
			"expires_at": expires, "source": "self_service", "purpose": "reset",
		}},
		{repository.EventTypeCredentialMFAReset, map[string]any{
			"collaborator_id": uuid.New().String(), "source": "admin_setup_link", "issued_by_id": adminID,
		}},
		{repository.EventTypeCollaboratorSessionTerminated, map[string]any{
			"collaborator_id": uuid.New().String(), "reason": repository.SessionRevocationReasonMFAReset,
			"revocation_id": uuid.New().String(), "emitted_at": expires, "primary_email": "lucas@example.com",
		}},
	}
	for _, tc := range cases {
		if err := contracts.ValidateEventPayload(tc.eventType, "v1", tc.payload); err != nil {
			t.Errorf("%s: %v", tc.eventType, err)
		}
	}
	// A raw time.Time is what used to be sent: the schema must keep refusing
	// it, which is why the handlers format the timestamp.
	if err := contracts.ValidateEventPayload(repository.EventTypeCredentialSetupTokenIssued, "v1", map[string]any{
		"token_id": uuid.New().String(), "collaborator_id": uuid.New().String(),
		"expires_at": time.Now(), "purpose": "setup",
	}); err == nil {
		t.Error("a time.Time expires_at should not validate")
	}
}

func TestAuthAdminPrincipalAttribution(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup-tokens", nil)
	r.Header.Set("User-Agent", "ops-cli")

	machine := authAdminPrincipal{}
	if machine.auditActor() != "service:auth-admin-token" {
		t.Fatalf("machine audit actor: %q", machine.auditActor())
	}
	if a := machine.eventActor(r); a.Type != "service" || a.ID != "auth-admin-token" || a.Context["user_agent"] != "ops-cli" {
		t.Fatalf("machine event actor: %+v", a)
	}

	id := uuid.New()
	human := authAdminPrincipal{CollaboratorID: id}
	if human.auditActor() != "user:"+id.String() {
		t.Fatalf("human audit actor: %q", human.auditActor())
	}
	if a := human.eventActor(r); a.Type != "collaborator" || a.ID != id.String() {
		t.Fatalf("human event actor: %+v", a)
	}
}

func TestResolveAuthAdminPrincipalStaticToken(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "s3cret-admin")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passwords/setup-tokens", nil)
	if _, err := resolveAuthAdminPrincipal(r, nil); err == nil {
		t.Fatal("a request without credentials must not be authorized")
	}
	r.Header.Set("X-Yggdrasil-Auth-Admin-Token", "s3cret-admin")
	p, err := resolveAuthAdminPrincipal(r, nil)
	if err != nil || p.CollaboratorID != uuid.Nil {
		t.Fatalf("static token: principal=%+v err=%v", p, err)
	}
}
