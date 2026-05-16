package externalidentity

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("DB_URL")
	if url == "" {
		t.Skip("DB_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", url)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	return db
}

func seedCollaborator(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO collaborators (id, slug, status, display_name, primary_email)
	                   VALUES ($1, $2, 'active', 'Test', $3)`,
		id, "test-"+id.String()[:8], id.String()+"@dakasa.me")
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborators WHERE id = $1`, id) })
	return id
}

func TestUpsert_InsertsNewRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()
	id, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_TEST_INSERT", ExternalMetadata: map[string]any{"display_name": "QA"},
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)
	assert.Equal(t, OutcomeInserted, outcome)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	identity, err := GetByID(ctx, db, id)
	require.NoError(t, err)
	assert.Equal(t, collabID, identity.CollaboratorID)
	assert.Equal(t, "U_TEST_INSERT", identity.ExternalID)
	assert.Nil(t, identity.UnlinkedAt)
}

func TestUpsert_ReLinksUnlinkedRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()
	id, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_RELINK", ExternalMetadata: map[string]any{"v": 1},
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err)
	id2, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_RELINK", ExternalMetadata: map[string]any{"v": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, id, id2)
	assert.Equal(t, OutcomeReLinked, outcome)

	identity, _ := GetByID(ctx, db, id)
	assert.Nil(t, identity.UnlinkedAt)
	assert.EqualValues(t, 2, identity.ExternalMetadata["v"])
}

func TestUpsert_RefreshesActiveSameCollab(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()
	id, _, _ := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_REFRESH", ExternalMetadata: map[string]any{"v": 1},
	})
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	id2, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_REFRESH", ExternalMetadata: map[string]any{"v": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, id, id2)
	assert.Equal(t, OutcomeRefreshed, outcome)
}

func TestUpsert_ConflictReturnsConflictError(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabA := seedCollaborator(t, db)
	collabB := seedCollaborator(t, db)
	instanceID := uuid.New()
	idA, _, _ := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabA, IntegrationInstanceID: instanceID,
		ExternalID: "U_CONFLICT", ExternalMetadata: nil,
	})
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, idA) })

	_, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabB, IntegrationInstanceID: instanceID,
		ExternalID: "U_CONFLICT", ExternalMetadata: nil,
	})
	assert.Equal(t, OutcomeConflict, outcome)
	var cerr *ConflictError
	require.ErrorAs(t, err, &cerr)
	assert.Equal(t, collabA, cerr.ExistingCollaboratorID)
	assert.Equal(t, collabB, cerr.IncomingCollaboratorID)
}

func TestSoftDelete_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	id, _, _ := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: uuid.New(),
		ExternalID: "U_SD", ExternalMetadata: nil,
	})
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	_, err := SoftDelete(ctx, db, id)
	require.NoError(t, err)
	_, err = SoftDelete(ctx, db, id)
	require.NoError(t, err, "second SoftDelete must be idempotent")
}

func TestActiveFor_ReturnsActiveOrNil(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()

	got, err := ActiveFor(ctx, db, collabID, instanceID)
	require.NoError(t, err)
	assert.Nil(t, got, "no identity yet -> nil")

	id, _, _ := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: "U_ACTIVE_FOR", ExternalMetadata: nil,
	})
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborator_external_identities WHERE id = $1`, id) })

	got, err = ActiveFor(ctx, db, collabID, instanceID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "U_ACTIVE_FOR", got.ExternalID)
}

func TestHardCleanup_DeletesOnlyOldUnlinked(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	oldID := uuid.New()
	recentID := uuid.New()
	_, err := db.Exec(`
		INSERT INTO collaborator_external_identities
		  (id, collaborator_id, integration_instance_id, external_id, unlinked_at)
		VALUES
		  ($1, $2, $3, 'OLD', NOW() - INTERVAL '31 days'),
		  ($4, $5, $6, 'RECENT', NOW() - INTERVAL '29 days')
	`, oldID, collabID, uuid.New(), recentID, collabID, uuid.New())
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM collaborator_external_identities WHERE id IN ($1, $2)`, oldID, recentID)
	})

	purged, err := HardCleanup(ctx, db, time.Now().UTC().Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Len(t, purged, 1)
	assert.Equal(t, oldID, purged[0].ID)
}
