package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Keep the SELECT independent from the implementation: SQL mocks returning
// twelve columns for an unchecked eleven-column query would mask this bug.
const directAuthorizationTeamsQuery = `
	SELECT t.id, t.slug, t.name, t.type, t.status, t.email,
	       t.parent_team_id, t.owners, t.traits, t.metadata, t.created_at, t.updated_at
	FROM public.team_memberships tm
	JOIN public.teams t ON t.id = tm.team_id
	WHERE tm.collaborator_id = $1
	  AND tm.active = TRUE
	  AND t.status = 'active'
	  AND (tm.starts_at IS NULL OR tm.starts_at <= NOW())
	  AND (tm.ends_at IS NULL OR tm.ends_at >= NOW())
	ORDER BY t.name, t.slug
`

var authorizationTeamColumns = []string{
	"id", "slug", "name", "type", "status", "email", "parent_team_id",
	"owners", "traits", "metadata", "created_at", "updated_at",
}

func expectAuthorizationCollaborator(mock sqlmock.Sqlmock, id uuid.UUID, now time.Time) {
	mock.ExpectQuery(collaboratorLookupQuery(id.String())).WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "slug", "status", "display_name", "primary_email", "manager_id", "primary_team_id",
			"personal_data", "employment_data", "third_party_identities", "traits", "metadata", "version", "created_at", "updated_at",
		}).AddRow(id, "operator", "active", "Operator", "operator@example.test", nil, nil,
			[]byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), 0, now, now))
}

func TestResolveAuthorizationSubjectsScansTeamEmailAndAncestors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		email any
		want  string
	}{
		{"populated email", "operators@example.test", "operators@example.test"},
		{"null email", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			collaboratorID, childID, parentID := uuid.New(), uuid.New(), uuid.New()
			now := time.Now().UTC()
			expectAuthorizationCollaborator(mock, collaboratorID, now)
			mock.ExpectQuery(directAuthorizationTeamsQuery).WithArgs(collaboratorID).
				WillReturnRows(sqlmock.NewRows(authorizationTeamColumns).AddRow(
					childID, "operators", "Operators", "team", "active", tc.email, parentID.String(),
					[]byte(`["owner"]`), []byte(`{"scope":"operations"}`), []byte(`{"source":"fixture"}`), now, now,
				)).RowsWillBeClosed()
			mock.ExpectQuery(`
				SELECT id, slug, name, type, status, email, parent_team_id,
				       owners, traits, metadata, created_at, updated_at
				FROM public.teams WHERE id = $1
			`).WithArgs(parentID).WillReturnRows(sqlmock.NewRows(authorizationTeamColumns).AddRow(
				parentID, "platform", "Platform", "team", "active", nil, nil,
				[]byte(`[]`), []byte(`{}`), []byte(`{}`), now, now,
			))

			collaborator, teams, subjects, err := ResolveAuthorizationSubjects(context.Background(), db, collaboratorID.String())
			if err != nil {
				t.Fatalf("resolve human authorization subjects: %v", err)
			}
			if collaborator.ID != collaboratorID || len(teams) != 2 {
				t.Fatalf("lost collaborator or ancestor: collaborator=%v teams=%v", collaborator.ID, teams)
			}
			child := teams[0]
			if child.ID != childID || child.Email != tc.want || child.ParentTeamID == nil || *child.ParentTeamID != parentID {
				t.Fatalf("email/parent projection drift: %+v", child)
			}
			if !reflect.DeepEqual(child.Owners, []string{"owner"}) || child.Traits["scope"] != "operations" || child.Metadata["source"] != "fixture" {
				t.Fatalf("team payload columns shifted: %+v", child)
			}
			if !child.CreatedAt.Equal(now) || !child.UpdatedAt.Equal(now) || teams[1].Email != "" {
				t.Error("timestamp or nullable ancestor email decoding changed")
			}
			wantSubjects := []model.RBACSubject{
				{Type: "collaborator", ID: "operator"},
				{Type: "team", ID: "operators"},
				{Type: "team", ID: "platform"},
			}
			if !reflect.DeepEqual(subjects, wantSubjects) {
				t.Fatalf("subject expansion changed: got %v, want %v", subjects, wantSubjects)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResolveAuthorizationSubjectsWithoutTeamsOrWithLookupFailure(t *testing.T) {
	lookupErr := errors.New("team lookup unavailable")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no eligible memberships", nil},
		{"query failure stays closed", lookupErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := uuid.New()
			expectAuthorizationCollaborator(mock, id, time.Now().UTC())
			query := mock.ExpectQuery(directAuthorizationTeamsQuery).WithArgs(id)
			if tc.err != nil {
				query.WillReturnError(tc.err)
			} else {
				query.WillReturnRows(sqlmock.NewRows(authorizationTeamColumns)).RowsWillBeClosed()
			}
			collaborator, teams, subjects, err := ResolveAuthorizationSubjects(context.Background(), db, id.String())
			if !errors.Is(err, tc.err) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}
			if tc.err != nil {
				if collaborator.ID != uuid.Nil || len(teams) != 0 || len(subjects) != 0 {
					t.Fatal("failed lookup returned partial authorization subjects")
				}
			} else if len(teams) != 0 || !reflect.DeepEqual(subjects, []model.RBACSubject{{Type: "collaborator", ID: "operator"}}) {
				t.Fatalf("unexpected subjects without eligible teams: %v", subjects)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
