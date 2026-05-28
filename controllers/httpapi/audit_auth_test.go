package httpapi

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestRecordAuthAuditSync_InsertsRowWithActorAndAction verifies that an
// auth audit emission lands an audit_events row with the actor derived
// from the collaborator UUID and a stable action code.
//
// Audit ref: reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md A5/G1
// (zero audit_events rows for any auth action in production).
func TestRecordAuthAuditSync_InsertsRowWithActorAndAction(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	collabID := uuid.NewString()
	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO public.audit_events
			(actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::jsonb, NULLIF($8, ''), NULLIF($9, ''))
	`)).WithArgs(
		"user:"+collabID,
		AuditAuthLoginSucceeded,
		"collaborator",
		collabID,
		AuditOutcomeSuccess,
		"",            // tenant_slug
		sqlmock.AnyArg(), // metadata jsonb
		"",            // trace_id
		"",            // span_id
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	r.RemoteAddr = "203.0.113.10:5555"

	if err := s.recordAuthAuditSync(r, "user:"+collabID, AuditAuthLoginSucceeded, collabID, AuditOutcomeSuccess, map[string]any{
		"source_ip":  "203.0.113.10",
		"user_agent": "",
	}); err != nil {
		t.Fatalf("recordAuthAuditSync error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRecordAuthAuditSync_AnonymousActorForUnknownCollaborator verifies
// the anonymous-actor branch (pre-auth failed login by unknown identifier).
func TestRecordAuthAuditSync_AnonymousActorForUnknownCollaborator(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`
		INSERT INTO public.audit_events
			(actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::jsonb, NULLIF($8, ''), NULLIF($9, ''))
	`)).WithArgs(
		"anonymous",
		AuditAuthLoginFailed,
		"collaborator",
		"",
		AuditOutcomeFailure,
		"",
		sqlmock.AnyArg(),
		"",
		"",
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)

	if err := s.recordAuthAuditSync(r, "anonymous", AuditAuthLoginFailed, "", AuditOutcomeFailure, map[string]any{
		"identifier_hint": "nobody@example.com",
	}); err != nil {
		t.Fatalf("recordAuthAuditSync error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestAuditAuthActionCodes_AreStableConstants pins the canonical action
// codes so an accidental rename in a future refactor breaks the build —
// SIEM consumers downstream rely on these literal strings.
func TestAuditAuthActionCodes_AreStableConstants(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"auth.login.succeeded":              AuditAuthLoginSucceeded,
		"auth.login.failed":                 AuditAuthLoginFailed,
		"auth.login.rate_limited":           AuditAuthLoginRateLimited,
		"auth.login.account_locked":         AuditAuthLoginAccountLocked,
		"auth.logout":                       AuditAuthLogout,
		"auth.mfa.verify.succeeded":         AuditAuthMFAVerifySucceeded,
		"auth.mfa.verify.failed":            AuditAuthMFAVerifyFailed,
		"auth.mfa.enrolled":                 AuditAuthMFAEnrolled,
		"auth.mfa.unenrolled":               AuditAuthMFAUnenrolled,
		"auth.session.created":              AuditAuthSessionCreated,
		"auth.session.revoked":              AuditAuthSessionRevoked,
		"auth.password.changed":             AuditAuthPasswordChanged,
		"auth.third_party.login.succeeded":  AuditAuthThirdPartyLogin,
	}
	for literal, constant := range want {
		if literal != constant {
			t.Fatalf("audit code drift: expected %q, got %q", literal, constant)
		}
		if !strings.HasPrefix(constant, "auth.") {
			t.Fatalf("audit code MUST be under the auth.* namespace: %q", constant)
		}
	}
}
