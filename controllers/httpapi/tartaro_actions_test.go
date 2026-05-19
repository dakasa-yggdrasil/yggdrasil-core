package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func openTartaroActionsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping tartaro actions integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func newTartaroActionsTestServer(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	srv, err := New("yggdrasil-core-test", db, nil, logger)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return srv
}

// seedTartaroCollaborator inserts a minimal active collaborator for tartaro tests.
func seedTartaroCollaborator(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("tartaro-test-%s", uuid.New().String()[:8])
	collab, err := repository.CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:         slug,
		DisplayName:  "Tartaro Test",
		PrimaryEmail: slug + "@dakasa.test",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_memberships WHERE collaborator_id = $1`, collab.ID)
		_, _ = db.Exec(`DELETE FROM public.event_log WHERE aggregate_id = $1`, collab.ID.String())
		_, _ = db.Exec(`DELETE FROM public.collaborators WHERE id = $1`, collab.ID)
	})
	return collab.ID
}

// seedTartaroTeam inserts a minimal active team for tartaro tests.
func seedTartaroTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("tartaro-team-%s", uuid.New().String()[:8])
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "Tartaro Team Test",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("seed team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_grants WHERE team_id = $1`, team.ID)
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})
	return team.ID
}

// addCollaboratorToTeam inserts a team_membership row.
func addCollaboratorToTeam(t *testing.T, db *sql.DB, collabID, teamID uuid.UUID) {
	t.Helper()
	active := true
	_, err := repository.UpsertTeamMembership(context.Background(), db, model.UpsertTeamMembershipRequest{
		TeamID:         teamID.String(),
		CollaboratorID: collabID.String(),
		Active:         &active,
	})
	if err != nil {
		t.Fatalf("add collaborator to team: %v", err)
	}
}

// addTartaroGrant grants an action of integration-tartaro-dakasa to a team.
func addTartaroGrant(t *testing.T, db *sql.DB, teamID uuid.UUID, namespace, name, action string) {
	t.Helper()
	grant, err := repository.GrantTeamAction(context.Background(), db, model.GrantTeamActionRequest{
		TeamID:                       teamID.String(),
		IntegrationInstanceNamespace: namespace,
		IntegrationInstanceName:      name,
		ActionName:                   action,
	})
	if err != nil {
		t.Fatalf("add tartaro grant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_grants WHERE id = $1`, grant.ID)
	})
}

func TestEffectiveTartaroActions(t *testing.T) {
	db := openTartaroActionsTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	srv := newTartaroActionsTestServer(t, db)

	collabID := seedTartaroCollaborator(t, db)
	teamID := seedTartaroTeam(t, db)
	addCollaboratorToTeam(t, db, collabID, teamID)
	addTartaroGrant(t, db, teamID, "dakasa", "integration-tartaro-dakasa", "tartaro:moderate_post")
	// Trait left empty on purpose — endpoint should compute and report drift=true

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+collabID.String()+"/effective-tartaro-actions", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		TraitTartaroActions    []string `json:"trait_tartaro_actions"`
		ComputedTartaroActions []string `json:"computed_tartaro_actions"`
		EffectiveViaTeams      []struct {
			TeamID  string   `json:"team_id"`
			Actions []string `json:"actions"`
		} `json:"effective_via_teams"`
		Drift bool `json:"drift"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Drift {
		t.Fatal("expected drift=true since trait is empty")
	}
	if len(resp.ComputedTartaroActions) != 1 || resp.ComputedTartaroActions[0] != "tartaro:moderate_post" {
		t.Fatalf("expected computed=[tartaro:moderate_post], got %v", resp.ComputedTartaroActions)
	}
	if len(resp.EffectiveViaTeams) != 1 || len(resp.EffectiveViaTeams[0].Actions) != 1 {
		t.Fatalf("expected 1 team with 1 action, got %+v", resp.EffectiveViaTeams)
	}
}

func TestSyncTartaroActionsEmitsSyntheticEvent(t *testing.T) {
	db := openTartaroActionsTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	srv := newTartaroActionsTestServer(t, db)

	collabID := seedTartaroCollaborator(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collaborators/"+collabID.String()+"/sync-tartaro-actions", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM event_log WHERE aggregate_id = $1 AND type = 'team_membership.added'`, collabID.String()).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected synthetic team_membership.added event in event_log")
	}
}

func TestEffectiveTartaroActionsReturns404ForUnknownCollab(t *testing.T) {
	db := openTartaroActionsTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	srv := newTartaroActionsTestServer(t, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/00000000-0000-0000-0000-000000000000/effective-tartaro-actions", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
