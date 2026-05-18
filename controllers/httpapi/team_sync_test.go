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
)

func openTeamSyncTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping team sync integration test")
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

// seedActiveTeam inserts a minimal active team row and registers cleanup.
func seedActiveTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("team-sync-test-%s", uuid.New().String()[:8])
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "Team Sync Test",
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

// newTeamSyncServer wires a minimal Server + mux exposing only the sync route.
func newTeamSyncServer(db *sql.DB) http.Handler {
	server := &Server{
		serviceName: "yggdrasil-core-test",
		db:          db,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/teams/{id}/sync", server.handleTeamSync)
	return mux
}

func TestPostTeamSyncEmitsTeamCreated(t *testing.T) {
	db := openTeamSyncTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedActiveTeam(t, db)

	h := newTeamSyncServer(db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+teamID.String()+"/sync", strings.NewReader(""))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"events_emitted"`) {
		t.Fatalf("expected events_emitted in response, got: %s", rr.Body.String())
	}

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM event_log
		WHERE type = 'team.created' AND aggregate_id = $1
	`, teamID.String()).Scan(&count); err != nil {
		t.Fatalf("query event_log: %v", err)
	}
	if count == 0 {
		t.Fatal("expected event_log row for team.created")
	}
}

func TestPostTeamSyncReturns404ForUnknownTeam(t *testing.T) {
	db := openTeamSyncTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	h := newTeamSyncServer(db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/"+uuid.NewString()+"/sync", strings.NewReader(""))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestPostTeamSyncReturns400ForBadUUID(t *testing.T) {
	db := openTeamSyncTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	srv := newTeamSyncServer(db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/not-a-uuid/sync", strings.NewReader(""))
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid team id") {
		t.Fatalf("expected 'invalid team id' in body, got: %s", rr.Body.String())
	}
}
