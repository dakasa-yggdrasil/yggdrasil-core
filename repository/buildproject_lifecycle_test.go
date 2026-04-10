package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertTestBuildProject creates a minimal build_project row directly in the
// database, bypassing the CreateBuildProject function. Used to set up
// lifecycle tests with precise control over expires_at and status.
func insertTestBuildProject(t *testing.T, db *sql.DB, id uuid.UUID, buildName, envType, expiresAt string, ephemeral bool, status string) {
	t.Helper()

	// Insert a dummy topology_nodes row first for FK compliance.
	nodeID := uuid.New()
	_, err := db.Exec(`
		INSERT INTO public.topology_nodes (id, slug, kind, name, description, status, metadata)
		VALUES ($1, $2, 'project', 'Test Project', '', 'active', '{}')
	`, nodeID, "test-project-"+nodeID.String()[:8])
	if err != nil {
		t.Fatalf("insert test topology_node: %v", err)
	}

	// Insert a dummy infra-map document for FK.
	infraMapID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO public.topology_documents (id, node_id, kind, name, body)
		VALUES ($1, $2, 'infra-map', 'test-infra-map', '{}')
	`, infraMapID, nodeID)
	if err != nil {
		t.Fatalf("insert infra-map document: %v", err)
	}

	// Insert a dummy project_env_resource document for FK.
	envResID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO public.topology_documents (id, node_id, kind, name, body)
		VALUES ($1, $2, 'project-env-resource', 'test-env-resource', '{}')
	`, envResID, nodeID)
	if err != nil {
		t.Fatalf("insert env resource document: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO public.topology_build_projects (
			id, project_node_id, infra_map_document_id, project_env_resource_id,
			build_name, env_type, cloud, ephemeral, expires_at,
			cluster_name, cluster_zone, immutable, lifecycle_status
		) VALUES ($1, $2, $3, $4, $5, $6, 'gcp', $7, $8, '', '', FALSE, $9)
	`, id, nodeID, infraMapID, envResID, buildName, envType, ephemeral, expiresAt, status)
	if err != nil {
		t.Fatalf("insert test build_project: %v", err)
	}
}

func cleanBuildProjects(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.topology_build_projects WHERE build_name LIKE 'lifecycle-test-%'`); err != nil {
		t.Fatalf("clean build_projects: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.topology_documents WHERE node_id IN (SELECT id FROM public.topology_nodes WHERE slug LIKE 'test-project-%')`); err != nil {
		t.Fatalf("clean topology_documents: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.topology_nodes WHERE slug LIKE 'test-project-%'`); err != nil {
		t.Fatalf("clean topology_nodes: %v", err)
	}
}

func TestFindExpiredBuildProjectCandidates_ReturnsOnlyExpiredEphemeralActive(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	future := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)

	// Arrange: 4 BPs — only 1 should match (expired + ephemeral + active)
	expiredEphemeralID := uuid.New()
	insertTestBuildProject(t, db, expiredEphemeralID, "lifecycle-test-expired", "ephemeral", past, true, "active")

	insertTestBuildProject(t, db, uuid.New(), "lifecycle-test-future", "ephemeral", future, true, "active")
	insertTestBuildProject(t, db, uuid.New(), "lifecycle-test-not-ephemeral", "prod", past, false, "active")
	insertTestBuildProject(t, db, uuid.New(), "lifecycle-test-already-expiring", "ephemeral", past, true, "expiring")

	// Act
	candidates, err := FindExpiredBuildProjectCandidates(ctx, db, 100)
	if err != nil {
		t.Fatalf("FindExpiredBuildProjectCandidates: %v", err)
	}

	// Assert: only the expired ephemeral active one should be found
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].ID != expiredEphemeralID {
		t.Errorf("unexpected candidate id: %s", candidates[0].ID)
	}
}

func TestTransitionBuildProjectToExpiring_OptimisticLocking(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	bpID := uuid.New()
	insertTestBuildProject(t, db, bpID, "lifecycle-test-lock", "ephemeral", past, true, "active")

	// First worker wins the transition
	tx1, _ := db.BeginTx(ctx, nil)
	transitioned1, err := TransitionBuildProjectToExpiring(ctx, tx1, bpID.String())
	if err != nil {
		t.Fatalf("first transition: %v", err)
	}
	if !transitioned1 {
		t.Error("first worker should have won the transition")
	}
	tx1.Commit()

	// Second worker sees affected = 0
	tx2, _ := db.BeginTx(ctx, nil)
	transitioned2, err := TransitionBuildProjectToExpiring(ctx, tx2, bpID.String())
	if err != nil {
		t.Fatalf("second transition: %v", err)
	}
	if transitioned2 {
		t.Error("second worker should NOT have won the transition")
	}
	tx2.Commit()

	// Verify the BP is in expiring state
	var status string
	err = db.QueryRow(`SELECT lifecycle_status FROM public.topology_build_projects WHERE id = $1`, bpID).Scan(&status)
	if err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "expiring" {
		t.Errorf("expected lifecycle_status=expiring, got %s", status)
	}
}

func TestTransitionBuildProjectToDeleted_AfterExpiring(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	bpID := uuid.New()
	insertTestBuildProject(t, db, bpID, "lifecycle-test-delete", "ephemeral", past, true, "expiring")

	tx, _ := db.BeginTx(ctx, nil)
	transitioned, err := TransitionBuildProjectToDeleted(ctx, tx, bpID.String())
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if !transitioned {
		t.Error("expected transition to succeed")
	}
	tx.Commit()

	var status string
	var deletedAt sql.NullTime
	err = db.QueryRow(`SELECT lifecycle_status, deleted_at FROM public.topology_build_projects WHERE id = $1`, bpID).Scan(&status, &deletedAt)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "deleted" {
		t.Errorf("expected status=deleted, got %s", status)
	}
	if !deletedAt.Valid {
		t.Error("expected deleted_at to be set")
	}
}

func TestExpireBuildProjectNow_ForcesActiveToExpiring(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	// Future expires_at — would NOT be picked up by FindExpiredBuildProjectCandidates
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	bpID := uuid.New()
	insertTestBuildProject(t, db, bpID, "lifecycle-test-force", "ephemeral", future, true, "active")

	tx, _ := db.BeginTx(ctx, nil)
	transitioned, err := ExpireBuildProjectNow(ctx, tx, bpID.String())
	if err != nil {
		t.Fatalf("expire_now: %v", err)
	}
	if !transitioned {
		t.Error("expected forced expiration to succeed")
	}
	tx.Commit()

	var status string
	err = db.QueryRow(`SELECT lifecycle_status FROM public.topology_build_projects WHERE id = $1`, bpID).Scan(&status)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "expiring" {
		t.Errorf("expected expiring, got %s", status)
	}
}

func TestExtendBuildProjectExpiry_UpdatesActiveExpiresAt(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(1 * time.Hour).Format(time.RFC3339)
	bpID := uuid.New()
	insertTestBuildProject(t, db, bpID, "lifecycle-test-extend", "ephemeral", old, true, "active")

	newExpiresAt := now.Add(48 * time.Hour)
	if err := ExtendBuildProjectExpiry(ctx, db, bpID.String(), newExpiresAt); err != nil {
		t.Fatalf("extend: %v", err)
	}

	var storedExpiresAt string
	var extendedAt sql.NullTime
	err := db.QueryRow(`SELECT expires_at, extended_at FROM public.topology_build_projects WHERE id = $1`, bpID).Scan(&storedExpiresAt, &extendedAt)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !extendedAt.Valid {
		t.Error("expected extended_at to be set")
	}
}

func TestHardDeleteBuildProjectsOlderThan_RespectsDeletedAtCutoff(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()
	cleanBuildProjects(t, db)

	ctx := context.Background()
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)

	// BP 1: deleted 48h ago (should be hard-deleted)
	oldID := uuid.New()
	insertTestBuildProject(t, db, oldID, "lifecycle-test-old-deleted", "ephemeral", past, true, "deleted")
	_, err := db.Exec(`UPDATE public.topology_build_projects SET deleted_at = NOW() - INTERVAL '48 hours' WHERE id = $1`, oldID)
	if err != nil {
		t.Fatalf("set deleted_at: %v", err)
	}

	// BP 2: deleted 1h ago (should survive)
	recentID := uuid.New()
	insertTestBuildProject(t, db, recentID, "lifecycle-test-recent-deleted", "ephemeral", past, true, "deleted")
	_, err = db.Exec(`UPDATE public.topology_build_projects SET deleted_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, recentID)
	if err != nil {
		t.Fatalf("set deleted_at: %v", err)
	}

	// Cutoff: 24h ago — only BP 1 should match
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	deleted, err := HardDeleteBuildProjectsOlderThan(ctx, db, cutoff)
	if err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 row deleted, got %d", deleted)
	}

	// Verify BP 1 is gone
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM public.topology_build_projects WHERE id = $1`, oldID).Scan(&count)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if count != 0 {
		t.Errorf("BP 1 should have been hard-deleted")
	}

	// Verify BP 2 survives
	err = db.QueryRow(`SELECT COUNT(*) FROM public.topology_build_projects WHERE id = $1`, recentID).Scan(&count)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if count != 1 {
		t.Errorf("BP 2 should have survived")
	}
}
