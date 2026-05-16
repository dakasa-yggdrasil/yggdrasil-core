package externalidentity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildLinkedPayload(t *testing.T) {
	idID := uuid.New()
	collabID := uuid.New()
	instanceID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	p := BuildLinkedPayload(LinkedInputs{
		IdentityID: idID, CollaboratorID: collabID,
		IntegrationInstanceID: instanceID, ExternalID: "U_X",
		ReLinked: true, LinkedAt: now,
		ExternalMetadata: map[string]any{"k": "v"},
	})
	raw, _ := json.Marshal(p)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, idID.String(), got["identity_id"])
	assert.Equal(t, "U_X", got["external_id"])
	assert.Equal(t, true, got["re_linked"])
	assert.Equal(t, "2026-05-16T12:00:00Z", got["linked_at"])
}

func TestBuildConflictPayload(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	incoming := uuid.New()
	existing := uuid.New()
	instance := uuid.New()
	p := BuildConflictPayload(ConflictInputs{
		IntegrationInstanceID: instance, ExternalID: "U_C",
		IncomingCollaboratorID: incoming, ExistingCollaboratorID: existing,
		DetectedAt: now,
	})
	raw, _ := json.Marshal(p)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, "U_C", got["external_id"])
	assert.Equal(t, incoming.String(), got["incoming_collaborator_id"])
	assert.Equal(t, existing.String(), got["existing_collaborator_id"])
}

func TestBuildUnlinkedPayload(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	p := BuildUnlinkedPayload(UnlinkedInputs{
		IdentityID: uuid.New(), CollaboratorID: uuid.New(),
		IntegrationInstanceID: uuid.New(), ExternalID: "U_U",
		UnlinkedAt: now,
	})
	assert.Equal(t, "2026-05-16T12:00:00Z", p["unlinked_at"])
}

func TestBuildDriftPayload(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	p := BuildDriftPayload(DriftInputs{
		IdentityID: uuid.New(), CollaboratorID: uuid.New(),
		IntegrationInstanceID: uuid.New(), ExternalID: "U_D",
		DetectedAt: now,
	})
	assert.Equal(t, "2026-05-16T12:00:00Z", p["detected_at"])
}

func TestBuildUnknownExternalPayload_OmitsMetadataWhenNil(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	p := BuildUnknownExternalPayload(UnknownExternalInputs{
		IntegrationInstanceID: uuid.New(), ExternalID: "U_UE", DetectedAt: now,
	})
	_, hasMeta := p["external_metadata"]
	assert.False(t, hasMeta)
}

func TestBuildPurgedPayload(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	p := BuildPurgedPayload(PurgedInputs{
		IdentityID: uuid.New(), CollaboratorID: uuid.New(),
		IntegrationInstanceID: uuid.New(), ExternalID: "U_P", PurgedAt: now,
	})
	assert.Equal(t, "2026-05-16T12:00:00Z", p["purged_at"])
}
