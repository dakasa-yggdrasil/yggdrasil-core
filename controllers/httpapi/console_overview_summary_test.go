package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 6 — handleConsoleOverviewSummary tests.
//
// The aggregate replaces 6 separate OverviewPage queries; these tests lock
// the request shape, the response shape, and the gating contract.

// TestHandleConsoleOverviewSummary_HappyPath verifies the canonical
// shape: people counts (total/active/pending), teams total, identity
// counts (saml/scim), health (db ok + migration version), and a small
// audit slice.  All in one HTTP roundtrip.
func TestHandleConsoleOverviewSummary_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// 1) people counts — grouped SELECT
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WillReturnRows(sqlmock.NewRows([]string{"total", "active_count", "pending_count"}).
			AddRow(12, 9, 2))

	// 2) team count
	mock.ExpectQuery(`(?i)SELECT\s+COUNT\(\*\).*FROM\s+public\.teams`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))

	// 3) saml count
	mock.ExpectQuery(`(?i)FROM\s+public\.saml_service_providers`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// 4) scim count
	mock.ExpectQuery(`(?i)FROM\s+public\.scim_clients`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// 5) migration version (db.Ping is a no-op against sqlmock that returns
	// nil by default — we don't need to expect it)
	mock.ExpectQuery(`(?i)FROM\s+public\.goose_db_version`).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(47))

	// 6) audit events — ListOpsAuditEvents appends [limit, offset] as the
	// last two args.  Match with sqlmock.AnyArg() x 2. Scan expects
	// string for request_body / result (COALESCE(::text)).
	mock.ExpectQuery(`(?i)FROM\s+public\.audit_events`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "actor", "actor_collaborator_id", "actor_session_id",
			"action", "resource_kind", "resource_id", "result_status",
			"correlation_id", "request_body", "result", "created_at",
		}).AddRow(
			uuid.New(), "alice", "", "",
			"collaborator.created", "collaborator", "abc", "success", "",
			"{}", "{}", time.Now(),
		))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/overview-summary", nil)
	w := httptest.NewRecorder()
	s.handleConsoleOverviewSummary(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	var got consoleOverviewSummary
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.People.Total != 12 || got.People.Active != 9 || got.People.Pending != 2 {
		t.Errorf("people: got %+v want {12,9,2}", got.People)
	}
	if got.Teams.Total != 4 {
		t.Errorf("teams.total: got %d want 4", got.Teams.Total)
	}
	if got.Identity.SAMLProviders != 1 || got.Identity.SCIMClients != 2 {
		t.Errorf("identity: got %+v want {1,2}", got.Identity)
	}
	if !got.Health.DBHealthy {
		t.Errorf("health.db_healthy: expected true")
	}
	if got.Health.AppliedMigration != 47 {
		t.Errorf("health.applied_migration: got %d want 47", got.Health.AppliedMigration)
	}
	if len(got.RecentAuditEvents) != 1 {
		t.Errorf("recent_audit_events: got %d want 1 (body=%s)", len(got.RecentAuditEvents), w.Body.String())
	} else if got.RecentAuditEvents[0].Action != "collaborator.created" {
		t.Errorf("audit action: got %q want collaborator.created", got.RecentAuditEvents[0].Action)
	}
}

// TestHandleConsoleOverviewSummary_EmptyDatasetReturnsZeros: a fresh
// cluster with no data must NOT 500 — every counter must default to 0
// and the audit slice must serialize as `[]` (not null) so the TS side
// doesn't crash on `.map`.
func TestHandleConsoleOverviewSummary_EmptyDatasetReturnsZeros(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WillReturnRows(sqlmock.NewRows([]string{"total", "active_count", "pending_count"}).
			AddRow(0, 0, 0))
	mock.ExpectQuery(`(?i)FROM\s+public\.teams`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.saml_service_providers`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.scim_clients`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.goose_db_version`).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.audit_events`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "actor", "actor_collaborator_id", "actor_session_id",
			"action", "resource_kind", "resource_id", "result_status",
			"correlation_id", "request_body", "result", "created_at",
		}))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/overview-summary", nil)
	w := httptest.NewRecorder()
	s.handleConsoleOverviewSummary(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	// Audit slice must serialize as `[]` not `null` to keep the TS side
	// safe for .map() without defensive handling.
	if !strings.Contains(w.Body.String(), `"recent_audit_events":[]`) {
		t.Errorf("expected recent_audit_events to be empty array, got %s", w.Body.String())
	}
}

// TestHandleConsoleOverviewSummary_ContractFieldNames locks down the
// keys the TS surface depends on. If anyone renames `people` to `users`
// or drops `recent_audit_events` this test catches it before the
// surface refactor diverges.
func TestHandleConsoleOverviewSummary_ContractFieldNames(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).
		WillReturnRows(sqlmock.NewRows([]string{"total", "active_count", "pending_count"}).AddRow(0, 0, 0))
	mock.ExpectQuery(`(?i)FROM\s+public\.teams`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.saml_service_providers`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.scim_clients`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`(?i)FROM\s+public\.goose_db_version`).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(1))
	mock.ExpectQuery(`(?i)FROM\s+public\.audit_events`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "actor", "actor_collaborator_id", "actor_session_id",
			"action", "resource_kind", "resource_id", "result_status",
			"correlation_id", "request_body", "result", "created_at",
		}))

	s := &Server{db: db, logger: zap.NewNop()}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/overview-summary", nil)
	w := httptest.NewRecorder()
	s.handleConsoleOverviewSummary(w, r)

	body := w.Body.String()
	for _, key := range []string{
		`"people"`, `"teams"`, `"identity"`, `"health"`, `"recent_audit_events"`, `"checked_at"`,
		`"total"`, `"active"`, `"pending"`,
		`"saml_providers"`, `"scim_clients"`,
		`"db_healthy"`, `"applied_migration"`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("response missing canonical field %s (body=%s)", key, body)
		}
	}
}
