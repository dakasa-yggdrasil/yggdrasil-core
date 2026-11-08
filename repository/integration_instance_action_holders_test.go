package repository

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestActionHolderCandidatesQueryReusesTheAuthorizationMembershipPredicate(t *testing.T) {
	// The roster and the effective-actions read must apply one membership
	// predicate (ADR-0107); a copy would drift.
	if !strings.Contains(integrationInstanceActionHolderCandidatesQuery, authorizationMembershipPredicate) {
		t.Fatal("the roster statement does not embed authorizationMembershipPredicate verbatim")
	}
	for _, fragment := range []string{
		"g.integration_instance_namespace = $1",
		"g.integration_instance_name = $2",
		"(g.action_name = $3 OR g.action_name = '*')",
		"JOIN public.teams t ON t.id = tm.team_id",
		"WHERE c.status = 'active'",
		"EXISTS (SELECT 1 FROM instance_grants WHERE action_name = '*')",
		"FROM (SELECT 1) AS anchor",
	} {
		if !strings.Contains(integrationInstanceActionHolderCandidatesQuery, fragment) {
			t.Fatalf("the roster statement lost %q", fragment)
		}
	}
	if strings.Contains(integrationInstanceActionHolderCandidatesQuery, "parent_team_id") {
		t.Fatal("the roster must count direct memberships only, like the effective-actions grant walk")
	}
}

func TestListIntegrationInstanceActionHolderCandidatesRefusesNonConcreteActions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, action := range []string{"", "  ", "*"} {
		if _, err := ListIntegrationInstanceActionHolderCandidates(context.Background(), db, "dakasa", "tartaro", action); !errors.Is(err, ErrInvalidActionHolderQuery) {
			t.Fatalf("action %q: err=%v", action, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestListIntegrationInstanceActionHolderCandidatesScansTheSnapshot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	columns := []string{"instance_has_wildcard_grant", "id", "status", "admin_trait", "exact_grant", "wildcard_grant"}
	query := regexp.QuoteMeta("FROM (SELECT 1) AS anchor")

	t.Run("empty set keeps the wildcard flag of the anchor row", func(t *testing.T) {
		mock.ExpectQuery(query).WithArgs("dakasa", "tartaro", "tartaro:suspend_user").
			WillReturnRows(sqlmock.NewRows(columns).AddRow(true, nil, nil, nil, nil, nil))
		got, err := ListIntegrationInstanceActionHolderCandidates(context.Background(), db, "dakasa", "tartaro", "tartaro:suspend_user")
		if err != nil || !got.InstanceHasWildcardGrant || got.Candidates == nil || len(got.Candidates) != 0 {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	})

	t.Run("candidates keep their flags and raw admin trait", func(t *testing.T) {
		first, second := uuid.New(), uuid.New()
		mock.ExpectQuery(query).WithArgs("dakasa", "tartaro", "tartaro:suspend_user").
			WillReturnRows(sqlmock.NewRows(columns).
				AddRow(false, first.String(), "active", nil, true, false).
				AddRow(false, second.String(), "active", []byte(`"1"`), false, true).
				AddRow(false, second.String(), "active", []byte(`"1"`), false, true))
		got, err := ListIntegrationInstanceActionHolderCandidates(context.Background(), db, "dakasa", "tartaro", "tartaro:suspend_user")
		if err != nil || got.InstanceHasWildcardGrant || len(got.Candidates) != 2 {
			t.Fatalf("got=%+v err=%v", got, err)
		}
		if c := got.Candidates[0]; c.CollaboratorID != first || c.Status != "active" || c.AdminTrait != nil || !c.ExactGrant || c.WildcardGrant {
			t.Fatalf("first=%+v", c)
		}
		if c := got.Candidates[1]; c.CollaboratorID != second || string(c.AdminTrait) != `"1"` || c.ExactGrant || !c.WildcardGrant {
			t.Fatalf("second=%+v", c)
		}
	})

	t.Run("read failure is returned", func(t *testing.T) {
		mock.ExpectQuery(query).WillReturnError(errors.New("connection reset"))
		if _, err := ListIntegrationInstanceActionHolderCandidates(context.Background(), db, "dakasa", "tartaro", "tartaro:suspend_user"); err == nil {
			t.Fatal("read failure swallowed")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
