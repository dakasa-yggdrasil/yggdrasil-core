package httpapi

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestRecordAudit_OversizedTraceparentStillLandsTheRow proves that the
// handler audit path (manifest create and delete, workflow template
// instantiation) keeps its row when the caller sends a traceparent the audit_events columns
// cannot hold: the reference is dropped and the row is inserted with an
// empty trace_id and span_id. The raw header used to be handed to the
// insert, and Postgres refused the row.
func TestRecordAudit_OversizedTraceparentStillLandsTheRow(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	traceCol, spanCol := auditTraceColumns("", "")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		"service:bearer-token",
		"manifest.create",
		"manifest",
		"default/example",
		"success",
		"",
		sqlmock.AnyArg(),
		traceCol,
		spanCol,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/manifests?kind=workflow", nil)
	r.Header.Set("Authorization", "Bearer machine-credential")
	r.Header.Set("traceparent", strings.Repeat("a", 200))

	event := requestAuditEvent(r, "manifest.create", "manifest", "default/example", "success", map[string]any{"kind": "workflow"})
	if err := s.recordAuditSync(event); err != nil {
		t.Fatalf("the audit row was suppressed by the traceparent header: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRecordAudit_WellFormedTraceparentFillsTraceAndSpan proves a valid W3C
// header lands its trace-id and parent-id in the two columns, never the
// header itself.
func TestRecordAudit_WellFormedTraceparentFillsTraceAndSpan(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	traceCol, spanCol := auditTraceColumns("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		"user:operator",
		"workflow_template.instantiate",
		"workflow_template",
		"default/onboarding",
		"success",
		"",
		sqlmock.AnyArg(),
		traceCol,
		spanCol,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("POST", "/api/v1/workflow-templates/default/onboarding/instantiate", nil)
	r.Header.Set("X-Yggdrasil-Actor", "user:operator")
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")

	if err := s.recordAuditSync(requestAuditEvent(r, "workflow_template.instantiate", "workflow_template", "default/onboarding", "success", nil)); err != nil {
		t.Fatalf("recordAuditSync error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestRequestTraceIDs_NilRequest pins the nil-safe contract the auth writer
// relies on: an audit emitted without a request carries no trace reference
// instead of panicking.
func TestRequestTraceIDs_NilRequest(t *testing.T) {
	t.Parallel()

	if trace, span := requestTraceIDs(nil); trace != "" || span != "" {
		t.Fatalf("requestTraceIDs(nil)=(%q,%q), want empty", trace, span)
	}
}
