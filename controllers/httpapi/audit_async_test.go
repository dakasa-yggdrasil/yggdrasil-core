package httpapi

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// waitForAuditRow polls the sqlmock expectations until the detached audit
// goroutine has landed the row, or fails the test when it has not within
// timeout. sqlmock leaves an expectation unmatched when the writer hands it
// arguments it did not expect, so a row built from a raw header never
// satisfies it.
func waitForAuditRow(t *testing.T, mock sqlmock.Sqlmock, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := mock.ExpectationsWereMet()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit row never landed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRecordAudit_AsyncPathDropsOversizedHeaders exercises the production
// entry point the handlers call, recordAudit, not the synchronous helper the
// other tests use: the row is built on the caller's goroutine and inserted on
// a detached one, and this test would stay green if either header were read
// raw again inside that goroutine. Both caller-controlled headers are wider
// than their columns; the row must land with the trace columns empty and the
// actor derived from the credential.
func TestRecordAudit_AsyncPathDropsOversizedHeaders(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New error: %v", err)
	}
	defer db.Close()

	traceCol, spanCol := auditTraceColumns("", "")
	mock.ExpectExec(regexp.QuoteMeta(auditEventInsert)).WithArgs(
		auditActorColumn("service:bearer-token"),
		"manifest.create",
		"workflow",
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
	r.Header.Set("X-Yggdrasil-Actor", "user:"+strings.Repeat("a", 251))

	s.recordAudit(r, "manifest.create", "workflow", "default/example", "success", map[string]any{"version": 1})

	waitForAuditRow(t, mock, 2*time.Second)
}
