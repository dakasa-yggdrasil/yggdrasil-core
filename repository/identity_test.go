package repository

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestBuildListCollaboratorsQuerySearch(t *testing.T) {
	cases := []struct {
		name        string
		req         model.ListCollaboratorsRequest
		wantClause  string
		wantArg     string
		wantNoWhere bool
	}{
		{
			name:        "no filters omits WHERE",
			req:         model.ListCollaboratorsRequest{},
			wantNoWhere: true,
		},
		{
			name:       "search matches display_name slug primary_email",
			req:        model.ListCollaboratorsRequest{Search: "maria"},
			wantClause: "display_name ILIKE",
			wantArg:    "%maria%",
		},
		{
			name:       "escapes LIKE wildcards in user input",
			req:        model.ListCollaboratorsRequest{Search: "50%_off"},
			wantClause: "ILIKE",
			wantArg:    `%50\%\_off%`,
		},
		{
			name:       "combines status and search with AND",
			req:        model.ListCollaboratorsRequest{Status: "active", Search: "ana"},
			wantClause: "status = $1 AND",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, args := buildListCollaboratorsQuery(tc.req)
			if tc.wantNoWhere {
				if strings.Contains(q, "WHERE") {
					t.Fatalf("expected no WHERE clause, got: %s", q)
				}
				return
			}
			if !strings.Contains(q, tc.wantClause) {
				t.Fatalf("query missing %q: %s", tc.wantClause, q)
			}
			if tc.wantArg != "" {
				found := false
				for _, a := range args {
					if s, ok := a.(string); ok && s == tc.wantArg {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected arg %q in %v", tc.wantArg, args)
				}
			}
		})
	}
}

func TestCountCollaboratorsQueryShape(t *testing.T) {
	// CountCollaborators rebuilds the listing SQL with COUNT(*). Verify the
	// string surgery still finds the FROM clause when buildListCollaborators
	// changes shape (e.g. someone reformats the SELECT block).
	q, _ := buildListCollaboratorsQuery(model.ListCollaboratorsRequest{Search: "x"})
	if !strings.Contains(q, "FROM public.collaborators") {
		t.Fatalf("buildListCollaboratorsQuery dropped its FROM marker — CountCollaborators will break: %s", q)
	}
}

func TestExpandAncestorTeams(t *testing.T) {
	rootID := uuid.New()
	parentID := uuid.New()
	childID := uuid.New()

	parentMap := map[uuid.UUID]model.Team{
		parentID: {
			ID:           parentID,
			Slug:         "team:parent",
			Name:         "Parent",
			Type:         "team",
			Status:       "active",
			ParentTeamID: &rootID,
		},
		rootID: {
			ID:     rootID,
			Slug:   "team:root",
			Name:   "Root",
			Type:   "team",
			Status: "active",
		},
	}

	teams, err := expandAncestorTeams([]model.Team{
		{
			ID:           childID,
			Slug:         "team:child",
			Name:         "Child",
			Type:         "team",
			Status:       "active",
			ParentTeamID: &parentID,
		},
	}, func(parentTeamID uuid.UUID) (model.Team, error) {
		team, ok := parentMap[parentTeamID]
		if !ok {
			return model.Team{}, ErrTeamNotFound
		}
		return team, nil
	})
	if err != nil {
		t.Fatalf("expandAncestorTeams error: %v", err)
	}

	if len(teams) != 3 {
		t.Fatalf("expected child, parent and root teams, got %#v", teams)
	}
	if teams[0].Slug != "team:child" || teams[1].Slug != "team:parent" || teams[2].Slug != "team:root" {
		t.Fatalf("unexpected team order: %#v", teams)
	}
}

func TestExpandAncestorTeamsSkipsCyclesAndMissingParents(t *testing.T) {
	firstID := uuid.New()
	secondID := uuid.New()

	teams, err := expandAncestorTeams([]model.Team{
		{
			ID:           firstID,
			Slug:         "team:first",
			Name:         "First",
			Type:         "team",
			Status:       "active",
			ParentTeamID: &secondID,
		},
	}, func(parentTeamID uuid.UUID) (model.Team, error) {
		if parentTeamID != secondID {
			return model.Team{}, ErrTeamNotFound
		}

		return model.Team{
			ID:           secondID,
			Slug:         "team:second",
			Name:         "Second",
			Type:         "team",
			Status:       "active",
			ParentTeamID: &firstID,
		}, nil
	})
	if err != nil {
		t.Fatalf("expandAncestorTeams error: %v", err)
	}

	if len(teams) != 2 {
		t.Fatalf("expected cycle to stop at two teams, got %#v", teams)
	}
}
