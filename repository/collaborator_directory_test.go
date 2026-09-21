package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// authorizationTeamMembershipsQuery pins the SQL of the directory oracle's
// membership source. The WHERE clause is the same authorization predicate the
// RBAC projection uses (directAuthorizationTeamsQuery in
// identity_authorization_subjects_test.go): an active membership of an
// active team inside its starts_at/ends_at window. Keep both in sight when
// one changes.
const authorizationTeamMembershipsQuery = `
	SELECT
		tm.id,
		tm.team_id,
		t.slug,
		tm.collaborator_id,
		c.slug,
		tm.role,
		tm.active,
		tm.source,
		tm.starts_at,
		tm.ends_at,
		tm.metadata,
		tm.created_at,
		tm.updated_at
	FROM public.team_memberships tm
	JOIN public.teams t ON t.id = tm.team_id
	JOIN public.collaborators c ON c.id = tm.collaborator_id
	WHERE
		tm.collaborator_id = $1
		AND tm.active = TRUE
		AND t.status = 'active'
		AND (tm.starts_at IS NULL OR tm.starts_at <= NOW())
		AND (tm.ends_at IS NULL OR tm.ends_at >= NOW())
	ORDER BY t.slug, c.slug
`

func TestListAuthorizationTeamMembershipsAppliesTheAuthorizationPredicate(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	collaboratorID, teamID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	endsAt := now.Add(24 * time.Hour)
	mock.ExpectQuery(authorizationTeamMembershipsQuery).WithArgs(collaboratorID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata", "created_at", "updated_at",
		}).AddRow(uuid.New(), teamID, "social", collaboratorID, "ana-souza", "member", true, "manual", nil, endsAt, []byte(`{}`), now, now)).
		RowsWillBeClosed()

	memberships, err := ListAuthorizationTeamMemberships(context.Background(), db, collaboratorID)
	if err != nil {
		t.Fatalf("list authorization memberships: %v", err)
	}
	if len(memberships) != 1 || memberships[0].TeamID != teamID || memberships[0].TeamSlug != "social" || memberships[0].EndsAt == nil {
		t.Fatalf("memberships=%+v", memberships)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListAuthorizationTeamMembershipsReturnsAnEmptySliceWithoutRows(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	collaboratorID := uuid.New()
	mock.ExpectQuery(authorizationTeamMembershipsQuery).WithArgs(collaboratorID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "team_slug", "collaborator_id", "collaborator_slug",
			"role", "active", "source", "starts_at", "ends_at", "metadata", "created_at", "updated_at",
		}))

	memberships, err := ListAuthorizationTeamMemberships(context.Background(), db, collaboratorID)
	if err != nil {
		t.Fatal(err)
	}
	if memberships == nil || len(memberships) != 0 {
		t.Fatalf("memberships=%#v, want an empty, non-nil slice", memberships)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
