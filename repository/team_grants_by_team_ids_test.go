package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

var teamGrantProjectionColumns = []string{"id", "team_id", "integration_instance_namespace", "integration_instance_name", "action_name", "scope", "granted_at", "granted_by"}

func TestListTeamGrantsByTeamIDsReadsEveryTeamInOneStatement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	alpha := uuid.New()
	beta := uuid.New()
	grantedBy := "giovanni"

	// The duplicate alpha is bound once; no team lookup precedes the read.
	mock.ExpectQuery(`SELECT id, team_id, integration_instance_namespace, integration_instance_name,\s+action_name, scope, granted_at, granted_by\s+FROM public\.team_grants\s+WHERE team_id IN \(\$1, \$2\)\s+ORDER BY team_id, integration_instance_namespace, integration_instance_name, action_name`).
		WithArgs(alpha, beta).
		WillReturnRows(sqlmock.NewRows(teamGrantProjectionColumns).
			AddRow(uuid.New().String(), alpha.String(), "dakasa", "tartaro-dakasa-validation", "tartaro:read_user", []byte(`{"region":"br"}`), time.Now(), grantedBy).
			AddRow(uuid.New().String(), beta.String(), "dakasa", "yggdrasil-self", "*", []byte(`{}`), time.Now(), nil))

	grants, err := ListTeamGrantsByTeamIDs(context.Background(), db, []uuid.UUID{alpha, beta, alpha})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants=%+v", grants)
	}
	if grants[0].TeamID != alpha.String() || grants[0].ActionName != "tartaro:read_user" || grants[0].Scope["region"] != "br" ||
		grants[0].GrantedBy == nil || *grants[0].GrantedBy != grantedBy {
		t.Fatalf("first grant=%+v", grants[0])
	}
	if grants[1].TeamID != beta.String() || grants[1].IntegrationInstanceName != "yggdrasil-self" || grants[1].ActionName != "*" || grants[1].GrantedBy != nil {
		t.Fatalf("second grant=%+v", grants[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListTeamGrantsByTeamIDsWithoutTeamsIssuesNoQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, teamIDs := range [][]uuid.UUID{nil, {}} {
		grants, err := ListTeamGrantsByTeamIDs(context.Background(), db, teamIDs)
		if err != nil || grants == nil || len(grants) != 0 {
			t.Fatalf("grants=%v err=%v, want an empty non-nil list", grants, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListTeamGrantsByTeamIDsSurfacesReadFailures(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	team := uuid.New()
	driverErr := errors.New("pq: connection reset")
	mock.ExpectQuery(`FROM public\.team_grants\s+WHERE team_id IN \(\$1\)`).WithArgs(team).WillReturnError(driverErr)
	if _, err := ListTeamGrantsByTeamIDs(context.Background(), db, []uuid.UUID{team}); !errors.Is(err, driverErr) {
		t.Fatalf("err=%v, want the driver error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
