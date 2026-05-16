package manifestsync

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSyncedPayload_ShapeMatchesSchema(t *testing.T) {
	typeID := uuid.New()
	srcID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	got := buildSyncedPayload(syncedInputs{
		TypeID:           typeID,
		TypeNamespace:    "global",
		TypeName:         "slack",
		FromVersion:      6,
		ToVersion:        7,
		Diff:             Diff{AddedActions: []string{"new_op"}, RemovedActions: []string{}, SchemaChanged: false, CapabilitiesChanged: false},
		SourceInstanceID: srcID,
		SyncedAt:         now,
	})

	raw, err := json.Marshal(got)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(raw, &parsed))

	assert.Equal(t, typeID.String(), parsed["type_id"])
	assert.Equal(t, "global", parsed["type_namespace"])
	assert.Equal(t, "slack", parsed["type_name"])
	assert.EqualValues(t, 6, parsed["from_version"])
	assert.EqualValues(t, 7, parsed["to_version"])
	assert.Equal(t, srcID.String(), parsed["source_instance_id"])
	assert.Equal(t, "2026-05-16T12:00:00Z", parsed["synced_at"])

	diff, ok := parsed["diff_summary"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, diff["added_actions"], "new_op")
	assert.Equal(t, false, diff["schema_changed"])
	assert.Equal(t, false, diff["capabilities_changed"])
}

func TestBuildSkippedPayload_ReasonRequired(t *testing.T) {
	typeID := uuid.New()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	got := buildSkippedPayload(skippedInputs{
		TypeID:        typeID,
		TypeNamespace: "global",
		TypeName:      "slack",
		Reason:        SkipReasonRPCFailed,
		Error:         "deadline exceeded",
		AttemptedAt:   now,
	})

	raw, _ := json.Marshal(got)
	var p map[string]any
	require.NoError(t, json.Unmarshal(raw, &p))
	assert.Equal(t, "rpc_failed", p["reason"])
	assert.Equal(t, "deadline exceeded", p["error"])
	assert.Equal(t, nil, p["attempted_instance_id"], "null when nil")
}

func TestSkipReasonConstants(t *testing.T) {
	// Must match the enum in docs/contracts/events/v1/integration_type/sync_skipped.json
	cases := []struct {
		got  SkipReason
		want string
	}{
		{SkipReasonTypeNotFound, "type_not_found"},
		{SkipReasonNoInstances, "no_instances"},
		{SkipReasonNoDescribableInstance, "no_describable_instance"},
		{SkipReasonRPCFailed, "rpc_failed"},
		{SkipReasonInvalidDescribe, "invalid_describe"},
		{SkipReasonApplyFailed, "apply_failed"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, string(c.got))
	}
}
