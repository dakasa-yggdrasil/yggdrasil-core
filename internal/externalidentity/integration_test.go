package externalidentity

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExternalIdentityFullLifecycle exercises the link → relink → unlink →
// hard-cleanup path end-to-end, asserting both DB state and event emission
// at each step. Requires DB_URL pointing at a yggdrasil schema. Skipped
// otherwise.
func TestExternalIdentityFullLifecycle(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		t.Skip("DB_URL not set; skipping full lifecycle integration test")
	}
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabID := seedCollaborator(t, db)
	instanceID := uuid.New()
	extID := "U_LIFECYCLE_" + uuid.NewString()[:8]
	t.Cleanup(func() {
		db.Exec(`DELETE FROM collaborator_external_identities WHERE integration_instance_id = $1`, instanceID)
		db.Exec(`DELETE FROM event_log WHERE aggregate_id = $1`, collabID.String())
	})

	// 1. Initial Upsert → Inserted + LINKED event
	id1, outcome1, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{"v": 1},
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeInserted, outcome1)

	// Manually emit the linked event the way the reactor dispatcher would.
	require.NoError(t, EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, id1,
		BuildLinkedPayload(LinkedInputs{
			IdentityID: id1, CollaboratorID: collabID,
			IntegrationInstanceID: instanceID, ExternalID: extID,
			LinkedAt: time.Now().UTC(),
		})))
	assertEventEmitted(t, db, id1, repository.EventTypeExternalIdentityLinked)

	// 2. Re-Upsert (same triple) → Refreshed
	id2, outcome2, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{"v": 2},
	})
	require.NoError(t, err)
	assert.Equal(t, id1, id2, "Refreshed must return the same row id")
	assert.Equal(t, OutcomeRefreshed, outcome2)

	// 3. SoftDelete → unlinked_at populated
	deleted, err := SoftDelete(ctx, db, id1)
	require.NoError(t, err)
	require.NotNil(t, deleted.UnlinkedAt, "soft-delete must set unlinked_at")
	require.NoError(t, EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnlinked, id1,
		BuildUnlinkedPayload(UnlinkedInputs{
			IdentityID: id1, CollaboratorID: collabID,
			IntegrationInstanceID: instanceID, ExternalID: extID,
			UnlinkedAt: *deleted.UnlinkedAt,
		})))
	assertEventEmitted(t, db, id1, repository.EventTypeExternalIdentityUnlinked)

	// 4. Re-Upsert again → ReLinked + same id (row cleared of unlinked_at)
	id4, outcome4, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabID, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{"v": 3},
	})
	require.NoError(t, err)
	assert.Equal(t, OutcomeReLinked, outcome4)
	// The relinked row may reuse the same id (clearing unlinked_at) or
	// create a fresh one — both are valid. Just verify it's now active.
	rel, err := GetByID(ctx, db, id4)
	require.NoError(t, err)
	assert.Nil(t, rel.UnlinkedAt, "relinked row must be active")

	// 5. SoftDelete again, then back-date unlinked_at past retention
	_, err = SoftDelete(ctx, db, id4)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx,
		`UPDATE collaborator_external_identities SET unlinked_at = $1 WHERE id = $2`,
		time.Now().Add(-48*time.Hour), id4)
	require.NoError(t, err)

	// 6. CleanupTick with 1h retention → row purged + PURGED event emitted internally
	purgedCount, err := CleanupTick(ctx, db, time.Hour)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, purgedCount, 1)

	// Row should be gone
	_, err = GetByID(ctx, db, id4)
	assert.Error(t, err, "purged row must not be retrievable")

	// PURGED event must have been emitted by CleanupTick
	assertEventEmitted(t, db, id4, repository.EventTypeExternalIdentityPurged)
}

// TestExternalIdentityConflict ensures Upsert refuses to attach an
// external_id that already maps to a different collaborator.
func TestExternalIdentityConflict(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		t.Skip("DB_URL not set; skipping conflict integration test")
	}
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabA := seedCollaborator(t, db)
	collabB := seedCollaborator(t, db)
	instanceID := uuid.New()
	extID := "U_CONFLICT_" + uuid.NewString()[:8]
	t.Cleanup(func() {
		db.Exec(`DELETE FROM collaborator_external_identities WHERE integration_instance_id = $1`, instanceID)
	})

	_, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabA, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{},
	})
	require.NoError(t, err)

	_, _, err = Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabB, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{},
	})
	require.Error(t, err)

	var conflict *ConflictError
	require.ErrorAs(t, err, &conflict, "second upsert must return ConflictError")
	assert.Equal(t, collabA, conflict.ExistingCollaboratorID)
	assert.Equal(t, collabB, conflict.IncomingCollaboratorID)
	assert.Equal(t, extID, conflict.ExternalID)
}

// TestAutoLinkExternalEmitsConflictDetected ensures the resync auto-linker,
// on hitting a pre-existing link owned by a DIFFERENT collaborator, emits a
// conflict_detected event — observability parity with the webhook linker
// (controllers/httpapi/integration_webhook.go) — and still returns true so the
// caller does not go on to re-flag the external_id as unknown_external.
func TestAutoLinkExternalEmitsConflictDetected(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		t.Skip("DB_URL not set; skipping resync auto-link conflict test")
	}
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	collabA := seedCollaborator(t, db)
	collabB := seedCollaborator(t, db)
	instanceID := uuid.New()
	extID := "U_AUTOLINK_CONFLICT_" + uuid.NewString()[:8]
	t.Cleanup(func() {
		db.Exec(`DELETE FROM collaborator_external_identities WHERE integration_instance_id = $1`, instanceID)
		db.Exec(`DELETE FROM event_log WHERE aggregate_id = $1`, instanceID.String())
	})

	// Pre-existing link: extID already belongs to collabA in this instance.
	_, _, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID: collabA, IntegrationInstanceID: instanceID,
		ExternalID: extID, ExternalMetadata: map[string]any{},
	})
	require.NoError(t, err)

	// Auto-link attempt for a DIFFERENT collaborator (collabB) → conflict.
	linked := autoLinkExternal(ctx, db, instanceID, collabB, extID, map[string]any{}, time.Now().UTC())
	assert.True(t, linked, "conflict must be treated as handled (skip), returning true")

	// Parity with the webhook linker: a conflict_detected event must be emitted,
	// aggregated on the integration_instance (as BuildConflictPayload records).
	assertEventEmitted(t, db, instanceID, repository.EventTypeExternalIdentityConflictDetected)
}

// assertEventEmitted checks that at least one event of the given type was
// written to event_log for the given aggregate ID.
func assertEventEmitted(t *testing.T, db *sql.DB, aggregateID uuid.UUID, eventType string) {
	t.Helper()
	var count int
	err := db.QueryRow(
		`SELECT count(*) FROM event_log WHERE aggregate_id = $1 AND type = $2`,
		aggregateID.String(), eventType,
	).Scan(&count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "expected at least one %s event for %s", eventType, aggregateID)
}
