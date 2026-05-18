package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping team_provisioning_log integration test")
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

// seedTeam inserts a minimal team row and returns its ID.
func seedTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	slug := fmt.Sprintf("tpl-test-team-%s", uuid.New().String()[:8])
	team, err := CreateTeam(context.Background(), db, model.CreateTeamRequest{
		Slug:   slug,
		Name:   "TPL Test Team",
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

// seedIntegrationInstance inserts a minimal integration_instance manifest
// and returns its manifest ID (which is what team_provisioning_log.integration_instance_id references).
func seedIntegrationInstance(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	name := fmt.Sprintf("tpl-test-instance-%s", uuid.New().String()[:8])
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx for integration_instance seed: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:      name,
			Namespace: "tpl-test",
		},
		Spec: []byte(`{}`),
	}
	m, err := CreateManifestVersionTx(context.Background(), tx, doc, "sha256:test")
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

func TestUpsertTeamProvisioningLogInsertsThenUpdates(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	instanceID := seedIntegrationInstance(t, db)

	first, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "C123",
		ExternalMetadata:      map[string]any{"channel_name": "team-eng"},
		LastEventType:         "team.created",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.ExternalID != "C123" {
		t.Fatalf("expected external_id C123, got %s", first.ExternalID)
	}

	second, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            "C123",
		ExternalMetadata:      map[string]any{"channel_name": "team-eng-renamed"},
		LastEventType:         "team.updated",
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected same id on conflict (got %s vs %s)", first.ID, second.ID)
	}
	if second.LastEventType != "team.updated" {
		t.Fatalf("expected last_event_type team.updated, got %s", second.LastEventType)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) && !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("expected updated_at to advance, got first=%v second=%v", first.UpdatedAt, second.UpdatedAt)
	}

	// Cleanup
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_provisioning_log WHERE team_id = $1`, teamID)
	})
}

func TestListTeamProvisioningLogByTeam(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	teamID := seedTeam(t, db)
	instance1 := seedIntegrationInstance(t, db)
	instance2 := seedIntegrationInstance(t, db)

	for _, inst := range []uuid.UUID{instance1, instance2} {
		if _, err := UpsertTeamProvisioningLog(context.Background(), db, model.UpsertTeamProvisioningLogRequest{
			TeamID:                teamID,
			IntegrationInstanceID: inst,
			ExternalID:            "ext-" + inst.String(),
			LastEventType:         "team.created",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	rows, err := ListTeamProvisioningLogByTeam(context.Background(), db, teamID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	// Cleanup
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.team_provisioning_log WHERE team_id = $1`, teamID)
	})
}
