package repository

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

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
