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
// seedIntegrationInstanceForSync inserts a minimal integration_instance manifest
// and returns its manifest ID. The manifest ID is used both as the
// integration_instance_id (in team_provisioning_log) and as the
// integration_type_manifest_id (in integration_event_reactions, for test simplicity).
func seedIntegrationInstanceForSync(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	name := fmt.Sprintf("team-sync-instance-%s", uuid.New().String()[:8])
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx for integration_instance seed: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "team-sync-test",
		},
		Spec: []byte(`{}`),
	}
	m, err := repository.CreateManifestVersionTx(context.Background(), tx, doc, "sha256:test")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed integration_instance manifest: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit integration_instance seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE id = $1`, m.ID)
	})
	return m.ID
}

func newTeamSyncServer(db *sql.DB) http.Handler {
	server := &Server{
		serviceName: "yggdrasil-core-test",
		db:          db,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/teams/{id}/sync", server.handleTeamSync)
	mux.HandleFunc("GET /api/v1/teams/{id}/provisioning-status", server.handleTeamProvisioningStatus)
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

func TestGetTeamProvisioningStatus(t *testing.T) {
	db := openTeamSyncTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	srv := newTeamSyncServer(db)

	teamID := seedActiveTeam(t, db)
	slackInstance := seedIntegrationInstanceForSync(t, db)
	githubInstance := seedIntegrationInstanceForSync(t, db)

	// One mirror present (slack), one missing (github) but with a pending reaction.
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log
		    (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'C123', 'team.created')
	`, teamID, slackInstance); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM team_provisioning_log WHERE team_id = $1`, teamID)
	})

	// Seed event_log row + pending reaction for github
	var eventID uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO event_log (type, schema_version, aggregate_type, aggregate_id, payload)
		VALUES ('team.created', 'v1', 'team', $1, '{}'::jsonb)
		RETURNING event_id
	`, teamID.String()).Scan(&eventID); err != nil {
		t.Fatalf("seed event_log: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM event_log WHERE event_id = $1`, eventID)
	})

	if _, err := db.Exec(`
		INSERT INTO integration_event_reactions
		    (event_id, event_type, integration_instance_id, integration_type_manifest_id, capability, status, next_attempt_at)
		VALUES ($1, 'team.created', $2, $2, 'on_team_created', 'pending', NOW())
	`, eventID, githubInstance); err != nil {
		t.Fatalf("seed reaction: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM integration_event_reactions WHERE event_id = $1`, eventID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+teamID.String()+"/provisioning-status", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	for _, want := range []string{`"provisioning"`, `"pending"`, `"dead_lettered"`, `"C123"`, `"on_team_created"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("expected %s in body, got: %s", want, rr.Body.String())
		}
	}
}
