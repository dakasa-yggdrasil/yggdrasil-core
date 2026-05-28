package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestListTeamMembershipsByCollaboratorIDs_EmptyInput returns empty slice
// without touching the DB — protects callers that may pass nil from a
// surprise SQL error.
func TestListTeamMembershipsByCollaboratorIDs_EmptyInput(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	out, err := ListTeamMembershipsByCollaboratorIDs(context.Background(), db, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil, got %v", out)
	}
}

// TestListTeamMembershipsByCollaboratorIDs_OneRoundTrip is the heart of
// the F2 win: ONE SQL query covers N collaborator ids using IN(...). The
// test asserts the WHERE clause is the IN-list and that all rows come
// back in one Query, not one query per id.
func TestListTeamMembershipsByCollaboratorIDs_OneRoundTrip(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	collab1 := uuid.New()
	collab2 := uuid.New()
	team1 := uuid.New()
	team2 := uuid.New()
	memb1 := uuid.New()
	memb2 := uuid.New()
	now := time.Now().UTC()

	// The query is dynamic on the count of placeholders; assert the
	// IN($1,$2) shape + the ORDER BY tail so the scan order stays
	// deterministic.
	mock.ExpectQuery(regexp.QuoteMeta(
		"WHERE tm.collaborator_id IN ($1,$2)",
	)).WithArgs(collab1, collab2).WillReturnRows(sqlmock.NewRows([]string{
		"id", "team_id", "team_slug", "collaborator_id", "collab_slug",
		"role", "active", "source", "starts_at", "ends_at", "metadata",
		"created_at", "updated_at",
	}).
		AddRow(memb1, team1, "engineering", collab1, "alice",
			"member", true, "manual", now, nil, []byte("{}"), now, now).
		AddRow(memb2, team2, "platform", collab2, "bob",
			"lead", true, "manual", now, nil, []byte("{}"), now, now))

	out, err := ListTeamMembershipsByCollaboratorIDs(
		context.Background(), db, []uuid.UUID{collab1, collab2}, true,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].CollaboratorID != collab1 || out[1].CollaboratorID != collab2 {
		t.Errorf("collaborator id order off: %v %v", out[0].CollaboratorID, out[1].CollaboratorID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestListTeamMembershipsByCollaboratorIDs_ActiveOnlyFalse_OmitsFilter
// verifies the active=TRUE clause is omitted when activeOnly=false —
// otherwise the caller can't see inactive (offboarded) memberships.
func TestListTeamMembershipsByCollaboratorIDs_ActiveOnlyFalse_OmitsFilter(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	collab1 := uuid.New()

	// active=TRUE MUST NOT appear in the query.
	mock.ExpectQuery(regexp.QuoteMeta(
		"WHERE tm.collaborator_id IN ($1) ORDER BY t.slug, c.slug",
	)).WithArgs(collab1).WillReturnRows(sqlmock.NewRows([]string{
		"id", "team_id", "team_slug", "collaborator_id", "collab_slug",
		"role", "active", "source", "starts_at", "ends_at", "metadata",
		"created_at", "updated_at",
	}))

	_, err = ListTeamMembershipsByCollaboratorIDs(
		context.Background(), db, []uuid.UUID{collab1}, false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
