package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// Password-reset email delivery.
//
// The core owns the reset token but never talks to a mail provider: it asks
// an integration instance that exposes the `send_email` capability to do it
// (Lego principle, INTEGRATION_CONTRACT.md). Which instance is configuration:
//
//	AUTH_EMAIL_INTEGRATION  "<namespace>/<name>" of the send_email instance
//	AUTH_EMAIL_FROM         sender address (optional; the adapter falls back
//	                        to its own instance config when empty)
//
// The link in the email is built ONLY from configured origins
// (YGGDRASIL_CONSOLE_URL, then YGGDRASIL_PUBLIC_BASE_URL), never from the
// request's Host or X-Forwarded-Host. /forgot is anonymous, so a request
// host would let anyone mail a victim a genuine reset token pointing at an
// attacker's domain (password-reset poisoning).
//
// When either the integration or the link origin is missing, self-service
// reset is reported as unavailable by /forgot/options and the console sends
// people to an administrator instead of promising an email that never comes.

const passwordResetEmailTimeout = 30 * time.Second

// executeAuthEmailIntegration is the integration round-trip, swappable in tests.
var executeAuthEmailIntegration = messagecontroller.ExecuteIntegration

type passwordResetEmailConfig struct {
	integration model.ManifestSelector
	from        string
	linkBase    string
}

// loadPasswordResetEmailConfig resolves the delivery config from the
// environment. ok is false when self-service reset cannot deliver a link.
func loadPasswordResetEmailConfig() (passwordResetEmailConfig, bool) {
	ref := strings.TrimSpace(os.Getenv("AUTH_EMAIL_INTEGRATION"))
	namespace, name, found := strings.Cut(ref, "/")
	namespace, name = strings.TrimSpace(namespace), strings.TrimSpace(name)
	if !found || namespace == "" || name == "" {
		return passwordResetEmailConfig{}, false
	}
	base := configuredConsoleOrigin()
	if base == "" {
		return passwordResetEmailConfig{}, false
	}
	return passwordResetEmailConfig{
		integration: model.ManifestSelector{Namespace: namespace, Name: name},
		from:        strings.TrimSpace(os.Getenv("AUTH_EMAIL_FROM")),
		linkBase:    base,
	}, true
}

// configuredConsoleOrigin returns the operator-configured console origin, or
// "" when none is set. Unlike consoleBaseURL it never falls back to request
// headers: links that leave the system by email must not be attacker-shaped.
func configuredConsoleOrigin() string {
	for _, key := range []string{"YGGDRASIL_CONSOLE_URL", "YGGDRASIL_PUBLIC_BASE_URL"} {
		raw := strings.TrimRight(strings.TrimSpace(os.Getenv(key)), "/")
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		return raw
	}
	return ""
}

func buildPasswordResetURL(base, raw string) string {
	return strings.TrimRight(base, "/") + "/reset?token=" + url.QueryEscape(raw)
}

// passwordResetEmail renders the subject and plain-text body. The copy
// follows the tenant locale: Portuguese for pt-*, English otherwise.
func passwordResetEmail(brand model.TenantBrand, displayName, link string, ttl time.Duration) (subject, body string) {
	product := strings.TrimSpace(brand.ProductLabel)
	if product == "" {
		product = strings.TrimSpace(brand.Name)
	}
	if product == "" {
		product = "Yggdrasil"
	}
	hours := int(ttl.Round(time.Hour) / time.Hour)
	if hours < 1 {
		hours = 1
	}
	name := strings.TrimSpace(displayName)
	support := strings.TrimSpace(brand.SupportEmail)

	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(brand.Locale)), "pt") || strings.TrimSpace(brand.Locale) == "" {
		greeting := "Olá,"
		if name != "" {
			greeting = fmt.Sprintf("Olá, %s,", name)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n\n", greeting)
		fmt.Fprintf(&b, "Recebemos um pedido para redefinir a sua senha do %s.\n\n", product)
		fmt.Fprintf(&b, "Abra o link abaixo para escolher uma nova senha. Ele vale por %d horas e só funciona uma vez:\n\n%s\n\n", hours, link)
		b.WriteString("Para concluir, você vai confirmar com a sua verificação em duas etapas (app autenticador ou código de emergência). Ao trocar a senha, todas as sessões abertas são encerradas.\n\n")
		b.WriteString("Se não foi você, ignore este e-mail. A sua senha atual continua valendo.")
		if support != "" {
			fmt.Fprintf(&b, "\n\nDúvidas: %s", support)
		}
		return fmt.Sprintf("Redefinição de senha do %s", product), b.String()
	}

	greeting := "Hi,"
	if name != "" {
		greeting = fmt.Sprintf("Hi %s,", name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", greeting)
	fmt.Fprintf(&b, "We received a request to reset your %s password.\n\n", product)
	fmt.Fprintf(&b, "Open the link below to choose a new password. It is valid for %d hours and works only once:\n\n%s\n\n", hours, link)
	b.WriteString("To finish, you will confirm with your second factor (authenticator app or a recovery code). Changing the password signs out every open session.\n\n")
	b.WriteString("If this was not you, ignore this email. Your current password keeps working.")
	if support != "" {
		fmt.Fprintf(&b, "\n\nQuestions: %s", support)
	}
	return fmt.Sprintf("Reset your %s password", product), b.String()
}

// dispatchPasswordResetEmail sends the reset link in the background so the
// /forgot response time does not depend on whether the account exists (the
// handler answers 202 for every input). Failures are logged without the
// token or the full address.
func (s *Server) dispatchPasswordResetEmail(cfg passwordResetEmailConfig, collab model.Collaborator, rawToken string, ttl time.Duration) {
	link := buildPasswordResetURL(cfg.linkBase, rawToken)
	to := strings.TrimSpace(collab.PrimaryEmail)
	if to == "" {
		s.logWarn("password reset email skipped: collaborator has no primary email",
			zap.String("collaborator_id", collab.ID.String()))
		return
	}
	goroutine.SafeGo("password_reset_email", func() {
		ctx, cancel := context.WithTimeout(context.Background(), passwordResetEmailTimeout)
		defer cancel()

		brand, err := repository.GetTenantBrand(ctx, s.db)
		if err != nil {
			brand = model.TenantBrand{}
		}
		subject, body := passwordResetEmail(brand, collab.DisplayName, link, ttl)
		// Keys cover both send_email adapters in the catalog: integration-aws
		// (to_addresses / text_body) and integration-google-workspace
		// (recipient / body). Each adapter ignores the keys it does not read.
		input := map[string]any{
			"recipient":    to,
			"to_addresses": []string{to},
			"subject":      subject,
			"body":         body,
			"text_body":    body,
		}
		if cfg.from != "" {
			input["from"] = cfg.from
			input["from_email"] = cfg.from
		}
		if _, err := executeAuthEmailIntegration(ctx, s.rabbitmq, s.db, model.ExecuteIntegrationRequest{
			Integration: cfg.integration,
			Operation:   "send_email",
			Capability:  "send_email",
			Input:       input,
		}); err != nil {
			s.logWarn("password reset email delivery failed",
				zap.String("collaborator_id", collab.ID.String()),
				zap.String("integration", cfg.integration.Namespace+"/"+cfg.integration.Name),
				zap.Error(err))
		}
	})
}

func (s *Server) logWarn(msg string, fields ...zap.Field) {
	if s.logger != nil {
		s.logger.Warn(msg, fields...)
	}
}
