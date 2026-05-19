package httpapi

import (
	"context"
	"database/sql"
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

func openTeamGrantTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping team grant integration test")
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

func newTeamGrantTestServer(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	srv, err := New("yggdrasil-core-test", db, nil, logger)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return srv
}

// seedTeamGrantRow inserts a team_grant row and registers cleanup.
func seedTeamGrantRow(t *testing.T, db *sql.DB, teamID uuid.UUID, namespace, name, action string) string {
	t.Helper()
	grant, err := repository.GrantTeamAction(context.Background(), db, model.GrantTeamActionRequest{
		TeamID:                       teamID.String(),
		IntegrationInstanceNamespace: namespace,
		IntegrationInstanceName:      name,
		ActionName:                   action,
	})
	if err != nil {
		t.Fatalf("seed team grant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_grants WHERE id = $1`, grant.ID)
	})
	return grant.ID
}

// seedActiveTeamForGrants is a local variant of seedActiveTeam that uses a
// distinct slug prefix so it doesn't collide with parallel tests seeding teams.
func seedActiveTeamForGrants(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("team-grant-test-%s", uuid.New().String()[:8])
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "Team Grant Test",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("seed team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})
	return team.ID
}

func TestTeamGrantCreateEmitsCanonEvent(t *testing.T) {
	db := openTeamGrantTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedActiveTeamForGrants(t, db)
	srv := newTeamGrantTestServer(t, db)

	body := strings.NewReader(`{
		"integration_instance_namespace": "dakasa",
		"integration_instance_name": "integration-tartaro-dakasa",
		"action_name": "tartaro:moderate_post"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+teamID.String()+"/grants", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("expected 201/200, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	// Verify the grant was created.
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_grants WHERE team_id = $1`, teamID)
	})

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team_grant.added' AND aggregate_type = 'team_grant'
	`).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected event_log row for team_grant.added, got 0")
	}
}

func TestTeamGrantRevokeEmitsCanonEvent(t *testing.T) {
	db := openTeamGrantTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedActiveTeamForGrants(t, db)
	grantID := seedTeamGrantRow(t, db, teamID, "dakasa", "integration-tartaro-dakasa", "tartaro:review_post")
	srv := newTeamGrantTestServer(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/"+teamID.String()+"/grants/"+grantID, nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusNoContent {
		t.Fatalf("expected 200/204, got %d (body=%s)", rr.Code, rr.Body.String())
	}

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team_grant.revoked' AND aggregate_type = 'team_grant' AND aggregate_id = $1
	`, grantID).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected event_log row for team_grant.revoked, got 0")
	}
}
