package teamreconcile

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		t.Skip("DB_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping: %v", err)
	}
	return db
}

func seedTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("tr-test-team-%s", uuid.New().String()[:8])
	team, err := repository.CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "Team Reconcile Test Team",
		Type:   "team",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.teams WHERE id = $1`, team.ID)
	})
	return team.ID
}

// seedIntegrationInstanceWithTeamReactor creates an integration_type manifest
// whose spec declares a team.created reactor, then creates a matching
// integration_instance manifest. Returns the integration_instance manifest ID.
func seedIntegrationInstanceWithTeamReactor(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()

	name := fmt.Sprintf("tr-test-%s", uuid.New().String()[:8])

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx for integration_type seed: %v", err)
	}

	// Create the integration_type manifest with a team.created reactor in spec.
	typeDoc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_type",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "tr-test",
		},
		Spec: []byte(`{"reactors":[{"event_type":"team.created","capability":"on_team_created"}]}`),
	}
	_, err = repository.CreateManifestVersionTx(context.Background(), tx, typeDoc, "sha256:trtype-"+name)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed integration_type manifest: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit integration_type seed: %v", err)
	}

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE kind = 'integration_type' AND namespace = 'tr-test' AND name = $1`, name)
	})

	// Create the integration_instance manifest that references the type.
	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx for integration_instance seed: %v", err)
	}
	instanceDoc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "tr-test",
		},
		Spec: []byte(fmt.Sprintf(`{"type_ref":{"namespace":"tr-test","name":%q}}`, name)),
	}
	m, err := repository.CreateManifestVersionTx(context.Background(), tx2, instanceDoc, "sha256:trinst-"+name)
	if err != nil {
		_ = tx2.Rollback()
		t.Fatalf("seed integration_instance manifest: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit integration_instance seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE id = $1`, m.ID)
	})

	return m.ID
}

func TestListUnprovisionedPairsFindsGap(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	teamID := seedTeam(t, db)
	slack := seedIntegrationInstanceWithTeamReactor(t, db)
	github := seedIntegrationInstanceWithTeamReactor(t, db)

	// Provision slack but not github.
	if _, err := db.Exec(`
		INSERT INTO team_provisioning_log
		    (team_id, integration_instance_id, external_id, last_event_type)
		VALUES ($1, $2, 'C123', 'team.created')
	`, teamID, slack); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM team_provisioning_log WHERE team_id = $1`, teamID)
	})

	pairs, err := ListUnprovisionedPairs(context.Background(), db)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	gotGitHub := false
	for _, p := range pairs {
		if p.TeamID == teamID && p.IntegrationInstanceID == github {
			gotGitHub = true
		}
		if p.TeamID == teamID && p.IntegrationInstanceID == slack {
			t.Fatalf("slack pair already provisioned but appeared in unprovisioned list")
		}
	}
	if !gotGitHub {
		t.Fatal("expected github pair in unprovisioned list")
	}
}

func TestReactorPauseTeamReconcileSkipsAndResumesGap(t *testing.T) {
	db := openTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	actorID := uuid.New()
	teamID := seedTeam(t, db)
	instanceID := seedIntegrationInstanceWithTeamReactor(t, db)
	var namespace, name string
	if err := db.QueryRow(`SELECT namespace, name FROM public.manifests WHERE id = $1`, instanceID).Scan(&namespace, &name); err != nil {
		t.Fatalf("lookup instance: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.integration_reactor_dispatch_policies WHERE namespace = $1 AND name = $2`, namespace, name)
		_, _ = db.Exec(`DELETE FROM public.event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String())
	})
	if _, err := repository.ReplaceIntegrationReactorDispatchPolicy(ctx, db, namespace, name, []string{repository.EventTypeTeamCreated}, 0, actorID); err != nil {
		t.Fatalf("pause team reactor: %v", err)
	}
	assertPair := func(want bool) {
		t.Helper()
		pairs, err := ListUnprovisionedPairs(ctx, db)
		if err != nil {
			t.Fatalf("list pairs: %v", err)
		}
		found := false
		for _, p := range pairs {
			if p.TeamID == teamID && p.IntegrationInstanceID == instanceID {
				found = true
			}
		}
		if found != want {
			t.Fatalf("gap found=%v, want %v", found, want)
		}
	}
	assertPair(false)
	if err := (&Runner{DB: db}).tick(ctx); err != nil {
		t.Fatalf("paused reconcile tick: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("paused synthetic events=%d, err=%v", count, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin normal team event: %v", err)
	}
	normalID, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		AggregateType: "team",
		AggregateID:   teamID.String(),
		Payload:       map[string]any{"id": teamID.String(), "slug": "pause-ci", "name": "Pause CI"},
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("emit normal team event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit normal team event: %v", err)
	}
	if _, err := repository.ReplaceIntegrationReactorDispatchPolicy(ctx, db, namespace, name, []string{}, 1, actorID); err != nil {
		t.Fatalf("resume team reactor: %v", err)
	}
	assertPair(false) // the durable normal reaction must drain before reconcile
	if err := (&Runner{DB: db}).tick(ctx); err != nil {
		t.Fatalf("resumed reconcile tick: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("normal backlog amplified on resume: events=%d, err=%v", count, err)
	}
	if _, err := db.Exec(`UPDATE public.integration_event_reactions SET status='dead_lettered' WHERE event_id=$1`, normalID); err != nil {
		t.Fatalf("mark normal reaction terminal: %v", err)
	}
	assertPair(true)
	if err := (&Runner{DB: db}).tick(ctx); err != nil {
		t.Fatalf("terminal gap reconcile tick: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.event_log WHERE type = 'team.created' AND aggregate_id = $1`, teamID.String()).Scan(&count); err != nil || count != 2 {
		t.Fatalf("terminal gap not reconciled: events=%d, err=%v", count, err)
	}
}
