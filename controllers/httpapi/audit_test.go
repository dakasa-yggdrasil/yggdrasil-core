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

// TestRecordAudit_OversizedActorHeaderStillLandsTheRow proves that an
// X-Yggdrasil-Actor header the actor column cannot hold does not suppress the
// row: the declared actor is dropped and the row is attributed to the
// credential. Stored raw, a 256 character header made Postgres refuse the
// row (value too long for type character varying(255)), the same way an
// oversized traceparent did.
func TestRecordAudit_OversizedActorHeaderStillLandsTheRow(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	traceCol, spanCol := auditTraceColumns("", "")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		auditActorColumn("service:bearer-token"),
		"manifest.delete",
		"manifest",
		"3f6c1b2e-9a4d-4c8e-b1f0-5d2a7c9e8b11",
		"success",
		"",
		sqlmock.AnyArg(),
		traceCol,
		spanCol,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	s := &Server{db: db}
	r := httptest.NewRequest("DELETE", "/api/v1/manifests/3f6c1b2e-9a4d-4c8e-b1f0-5d2a7c9e8b11", nil)
	r.Header.Set("Authorization", "Bearer machine-credential")
	r.Header.Set("X-Yggdrasil-Actor", "user:"+strings.Repeat("a", 251))

	event := requestAuditEvent(r, "manifest.delete", "manifest", "3f6c1b2e-9a4d-4c8e-b1f0-5d2a7c9e8b11", "success", nil)
	if err := s.recordAuditSync(event); err != nil {
		t.Fatalf("the audit row was suppressed by the actor header: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestActorFromRequest pins which declared actors reach the row as sent and
// which are dropped in favour of the actor derived from the credential.
func TestActorFromRequest(t *testing.T) {
	t.Parallel()

	widestUser := "user:" + strings.Repeat("a", 250) // 255 characters, the actor column width
	cases := []struct {
		name   string
		actor  string
		bearer bool
		want   string
	}{
		{name: "absent with bearer", bearer: true, want: "service:bearer-token"},
		{name: "absent without credential", want: "anonymous"},
		{name: "user id kept", actor: "user:3f6c1b2e-9a4d-4c8e-b1f0-5d2a7c9e8b11", want: "user:3f6c1b2e-9a4d-4c8e-b1f0-5d2a7c9e8b11"},
		{name: "service name kept", actor: "service:manifest-sync@cluster/prod", bearer: true, want: "service:manifest-sync@cluster/prod"},
		{name: "widest value the column holds kept", actor: widestUser, want: widestUser},
		{name: "one character past the column dropped", actor: widestUser + "a", bearer: true, want: "service:bearer-token"},
		{name: "one character past the column dropped to anonymous", actor: widestUser + "a", want: "anonymous"},
		{name: "no prefix dropped", actor: "operator", bearer: true, want: "service:bearer-token"},
		{name: "uppercase prefix dropped", actor: "User:operator", want: "anonymous"},
		{name: "empty id dropped", actor: "user:", want: "anonymous"},
		{name: "whitespace dropped", actor: "user:op erator", want: "anonymous"},
		{name: "non ascii dropped", actor: "user:opérateur", want: "anonymous"},
		{name: "quote dropped", actor: `service:x"y`, want: "anonymous"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("POST", "/api/v1/manifests?kind=workflow", nil)
			if tc.actor != "" {
				r.Header.Set("X-Yggdrasil-Actor", tc.actor)
			}
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer machine-credential")
			}
			if got := actorFromRequest(r); got != tc.want {
				t.Fatalf("actorFromRequest()=%q, want %q", got, tc.want)
			}
		})
	}
}
