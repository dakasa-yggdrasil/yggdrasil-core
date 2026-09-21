package httpapi

import (
	"database/sql/driver"
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

// auditEventInsert is the exact statement repository.RecordAuditEvent runs;
// the trace tests match it so a change in the column list is caught.
const auditEventInsert = `
		INSERT INTO public.audit_events
			(actor, action, resource_kind, resource_id, outcome, tenant_slug, metadata, trace_id, span_id)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::jsonb, NULLIF($8, ''), NULLIF($9, ''))
	`

// auditColumn stands in for one VARCHAR column of audit_events (migration
// 00017: trace_id VARCHAR(64), span_id VARCHAR(32)). Postgres rejects the
// whole row when a value does not fit, so a value wider than the column is a
// mismatch here for the same reason it is a lost row in production; the
// matcher also pins the exact value the writer must store.
type auditColumn struct {
	want  string
	width int
}

func (c auditColumn) Match(v driver.Value) bool {
	s, ok := v.(string)
	return ok && len(s) <= c.width && s == c.want
}

func auditTraceColumns(traceID, spanID string) (sqlmock.Argument, sqlmock.Argument) {
	return auditColumn{want: traceID, width: 64}, auditColumn{want: spanID, width: 32}
}

// auditActorColumn stands in for audit_events.actor (migration 00017:
// VARCHAR(255) NOT NULL) the same way: a declared actor wider than the column
// is a lost row in production.
func auditActorColumn(want string) sqlmock.Argument {
	return auditColumn{want: want, width: 255}
}

// TestRecordAuthAuditSync_OversizedTraceparentStillLandsTheRow proves that a
// traceparent the audit_events columns cannot hold does not suppress the
// login trail: the writer drops the malformed reference and the row is
// inserted with an empty trace_id and span_id. Storing the raw header made
// Postgres refuse the row (value too long for type character varying(64)),
// so a caller could erase its own auth.login or auth.mfa audit line by
// sending a 200 character header.
func TestRecordAuthAuditSync_OversizedTraceparentStillLandsTheRow(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	collabID := uuid.NewString()
	traceCol, spanCol := auditTraceColumns("", "")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		"user:"+collabID,
		AuditAuthMFAVerifySucceeded,
		"collaborator",
		collabID,
		AuditOutcomeSuccess,
		"",
		sqlmock.AnyArg(),
		traceCol,
		spanCol,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/auth/mfa/verify", nil)
	r.Header.Set("traceparent", strings.Repeat("a", 200))

	if err := s.recordAuthAuditSync(r, "user:"+collabID, AuditAuthMFAVerifySucceeded, collabID, AuditOutcomeSuccess, nil); err != nil {
		t.Fatalf("the audit row was suppressed by the traceparent header: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRecordAuthAuditSync_WellFormedTraceparentFillsTraceAndSpan proves the
// other half of the contract: a valid W3C header lands its trace-id and
// parent-id in the row, split into the two columns, never the header itself.
func TestRecordAuthAuditSync_WellFormedTraceparentFillsTraceAndSpan(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	collabID := uuid.NewString()
	traceCol, spanCol := auditTraceColumns("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		"user:"+collabID,
		AuditAuthLoginSucceeded,
		"collaborator",
		collabID,
		AuditOutcomeSuccess,
		"",
		sqlmock.AnyArg(),
		traceCol,
		spanCol,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")

	if err := s.recordAuthAuditSync(r, "user:"+collabID, AuditAuthLoginSucceeded, collabID, AuditOutcomeSuccess, nil); err != nil {
		t.Fatalf("recordAuthAuditSync error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
