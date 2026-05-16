package manifestsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDeps struct {
	typeManifest model.Manifest
	typeSpec     model.IntegrationTypeManifestSpec
	typeErr      error

	instances     []model.Manifest
	instanceSpecs []model.IntegrationInstanceManifestSpec
	instanceErr   error

	describeSpec model.IntegrationTypeManifestSpec
	describeErr  error

	appliedDoc *model.ManifestDocument
	applyErr   error

	emittedType    string
	emittedPayload map[string]any
	emitErr        error

	now time.Time
}

func (f *fakeDeps) GetIntegrationType(_ context.Context, _ uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	return f.typeManifest, f.typeSpec, f.typeErr
}
func (f *fakeDeps) ListInstances(_ context.Context, _ uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	return f.instances, f.instanceSpecs, f.instanceErr
}
func (f *fakeDeps) InvokeDescribe(_ context.Context, _ model.Manifest, _ model.Manifest, _ model.IntegrationInstanceManifestSpec, _ model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error) {
	return f.describeSpec, f.describeErr
}
func (f *fakeDeps) ApplyManifestVersion(_ context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	f.appliedDoc = &doc
	if f.applyErr != nil {
		return model.Manifest{}, f.applyErr
	}
	return model.Manifest{Version: f.typeManifest.Version + 1, Metadata: f.typeManifest.Metadata}, nil
}
func (f *fakeDeps) EmitEvent(_ context.Context, eventType string, _ uuid.UUID, payload map[string]any) error {
	f.emittedType = eventType
	f.emittedPayload = payload
	return f.emitErr
}
func (f *fakeDeps) Now() time.Time { return f.now }

func validLiveSpec() model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		ActionCatalog:    []model.IntegrationActionDefinition{{Name: "new_op"}},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
		Adapter:          model.IntegrationAdapterSpec{Version: "1.2.0"},
	}
}

func newFakeWithHappyPath() *fakeDeps {
	typeID := uuid.New()
	return &fakeDeps{
		typeManifest: model.Manifest{
			ID:      typeID,
			Version: 7,
			Metadata: model.ManifestMetadata{
				Name:        "slack",
				Namespace:   "global",
				Description: "Slack integration",
				Active:      true,
			},
		},
		typeSpec: model.IntegrationTypeManifestSpec{
			ActionCatalog:    []model.IntegrationActionDefinition{{Name: "old_op"}},
			Reactors:         []model.IntegrationTypeReactor{{EventType: "collaborator.created", Capability: "on_collaborator_created"}},
			Adapter:          model.IntegrationAdapterSpec{Version: "1.1.0"},
			CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
		},
		instances:     []model.Manifest{{ID: uuid.New()}},
		instanceSpecs: []model.IntegrationInstanceManifestSpec{{}},
		describeSpec:  validLiveSpec(),
		now:           time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC),
	}
}

func TestSyncIntegrationType_HappyPath_AppliesAndEmitsSynced(t *testing.T) {
	f := newFakeWithHappyPath()
	typeID := f.typeManifest.ID

	err := SyncIntegrationType(context.Background(), f, typeID)
	require.NoError(t, err)

	require.NotNil(t, f.appliedDoc, "expected new manifest version applied")
	assert.Equal(t, "slack", f.appliedDoc.Metadata.Name)
	assert.Equal(t, "Slack integration", f.appliedDoc.Metadata.Description, "description preserved")
	assert.Equal(t, "integration_type.synced", f.emittedType)
	assert.EqualValues(t, 7, f.emittedPayload["from_version"])
	assert.EqualValues(t, 8, f.emittedPayload["to_version"])
}

func TestSyncIntegrationType_NoInstances_EmitsSkippedNoInstances(t *testing.T) {
	f := newFakeWithHappyPath()
	f.instances = nil
	f.instanceSpecs = nil

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "no_instances", f.emittedPayload["reason"])
	assert.Nil(t, f.appliedDoc)
}

func TestSyncIntegrationType_DescribeRPCFailed_EmitsSkippedRPCFailed(t *testing.T) {
	f := newFakeWithHappyPath()
	f.describeErr = errors.New("amqp: deadline exceeded")

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "rpc_failed", f.emittedPayload["reason"])
	assert.Contains(t, f.emittedPayload["error"], "deadline exceeded")
}

func TestSyncIntegrationType_DescribeEmpty_EmitsSkippedInvalidDescribe(t *testing.T) {
	f := newFakeWithHappyPath()
	f.describeSpec = model.IntegrationTypeManifestSpec{} // no action_catalog, no schema, no adapter version

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "invalid_describe", f.emittedPayload["reason"])
}

func TestSyncIntegrationType_NoDiff_EmitsNoOp_DefaultSuppressed(t *testing.T) {
	f := newFakeWithHappyPath()
	// Make describe equal to current spec (after merge — reactors preserved).
	f.describeSpec = f.typeSpec
	f.describeSpec.Reactors = nil // describe never carries reactors

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Nil(t, f.appliedDoc, "no apply on no-op")
	// Default suppressed → no event emitted.
	assert.Empty(t, f.emittedType, "no_op default-suppressed; set DEBUG_SYNC_NO_OP=true to emit")
}

func TestSyncIntegrationType_NoOpEmittedWhenDebugFlagSet(t *testing.T) {
	t.Setenv("DEBUG_SYNC_NO_OP", "true")

	f := newFakeWithHappyPath()
	f.describeSpec = f.typeSpec
	f.describeSpec.Reactors = nil

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_no_op", f.emittedType)
}

func TestSyncIntegrationType_ApplyFails_EmitsSkippedApplyFailed(t *testing.T) {
	f := newFakeWithHappyPath()
	f.applyErr = errors.New("validation: action_catalog[3].name duplicate")

	err := SyncIntegrationType(context.Background(), f, f.typeManifest.ID)
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "apply_failed", f.emittedPayload["reason"])
}

func TestSyncIntegrationType_TypeNotFound_EmitsSkippedTypeNotFound(t *testing.T) {
	f := newFakeWithHappyPath()
	f.typeErr = errors.New("sql: no rows in result set")

	err := SyncIntegrationType(context.Background(), f, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, "integration_type.sync_skipped", f.emittedType)
	assert.Equal(t, "type_not_found", f.emittedPayload["reason"])
}
