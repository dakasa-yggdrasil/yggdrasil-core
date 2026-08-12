package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// TestTeamAdd_EmitsTeamMembershipAddedEvent is the regression guard for the
// "added to a team but still 403" bug. The lifecycle team-add endpoint used to
// write only public.lifecycle_events (not a reactor source) and NEVER emitted
// the team_membership.added canon event, so effective access never propagated.
// This test proves the endpoint now lands the canon event in event_log in the
// same transaction as the membership row, which is what drives the tartaro
// reactor and the ground-truth effective-actions endpoint.
func TestTeamAdd_EmitsTeamMembershipAddedEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "team-add")
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug: "lh-test-team-add",
		Name: "Reactive Add Team",
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	srv := newLifecycleTestServer(t, db)

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/team-add", map[string]any{
		"team_id":      team.ID.String(),
		"role_in_team": "member",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("team-add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// The membership row must be active.
	memberships, err := repository.ListTeamMemberships(context.Background(), db, model.ListTeamMembershipsRequest{
		CollaboratorID: collabID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 1 {
		t.Fatalf("expected 1 active membership, got %d", len(memberships))
	}

	// The canon event must be in event_log so the reactor fires. Without the
	// fix this assertion is what fails: zero rows.
	evResp, err := repository.PullEvents(context.Background(), db, model.PullEventsRequest{
		Limit: 10,
		Filters: model.PullEventsFilters{
			Types:         []string{repository.EventTypeTeamMembershipAdded},
			AggregateType: "team_membership",
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	var found bool
	for _, ev := range evResp.Events {
		var payload map[string]any
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			continue
		}
		if payload["collaborator_id"] == collabID.String() && payload["team_id"] == team.ID.String() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a team_membership.added event for collaborator %s team %s, got %d events", collabID, team.ID, len(evResp.Events))
	}
}

// TestTeamRemove_EmitsTeamMembershipRemovedEvent proves the ungrant side is
// reactive too: removing a collaborator from a team emits team_membership.removed
// in-tx so the reactor recomputes the trait and effective access drops.
func TestTeamRemove_EmitsTeamMembershipRemovedEvent(t *testing.T) {
	db := dbForLifecycleHandlerTest(t)
	defer func() { _ = db.Close() }()
	cleanLifecycleFixtures(t, db)

	collabID := seedActiveCollaborator(t, db, "team-remove")
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug: "lh-test-team-remove",
		Name: "Reactive Remove Team",
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	srv := newLifecycleTestServer(t, db)

	// Add first so there is something to remove.
	if rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/team-add", map[string]any{
		"team_id": team.ID.String(),
	}); rr.Code != http.StatusOK {
		t.Fatalf("seed team-add: %d body=%s", rr.Code, rr.Body.String())
	}

	rr := postJSON(t, srv, "/api/v1/collaborators/"+collabID.String()+"/team-remove", map[string]any{
		"team_id": team.ID.String(),
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("team-remove: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// No active membership remains.
	memberships, err := repository.ListTeamMemberships(context.Background(), db, model.ListTeamMembershipsRequest{
		CollaboratorID: collabID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 0 {
		t.Fatalf("expected 0 active memberships after remove, got %d", len(memberships))
	}

	evResp, err := repository.PullEvents(context.Background(), db, model.PullEventsRequest{
		Limit: 10,
		Filters: model.PullEventsFilters{
			Types:         []string{repository.EventTypeTeamMembershipRemoved},
			AggregateType: "team_membership",
		},
	})
	if err != nil {
		t.Fatalf("PullEvents: %v", err)
	}
	var found bool
	for _, ev := range evResp.Events {
		var payload map[string]any
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			continue
		}
		if payload["collaborator_id"] == collabID.String() && payload["team_id"] == team.ID.String() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a team_membership.removed event for collaborator %s team %s, got %d events", collabID, team.ID, len(evResp.Events))
	}
}
