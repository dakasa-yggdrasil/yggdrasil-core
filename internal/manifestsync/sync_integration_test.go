package manifestsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openSyncIntegrationTestDB opens a *sql.DB from the DB_URL env var.
// Skips the test gracefully when the envvar is absent — matching the convention
// used by repository/, internal/bootstrap/, and other integration tests in this
// repo.
func openSyncIntegrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping manifestsync integration test")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	return db
}

// TestSyncIntegrationType_BootstrapDriftFix replicates the 2026-05-15
// integration-github bootstrap end-to-end: seed an integration_type with an
// out-of-date v1 spec (1 action, basic credential schema), seed one
// integration_instance pointing at it, then run SyncIntegrationType with a
// stubbed InvokeDescribe that returns a "v2" contract (3 actions, updated
// adapter version).
//
// Assertions:
//  1. A new v2 manifest version is created in DB with 3 actions.
//  2. Operator-managed Reactors from v1 are preserved verbatim.
//  3. An integration_type.synced event row is persisted in event_log.
//  4. Re-running sync is a no-op — no v3 created (idempotency).
func TestSyncIntegrationType_BootstrapDriftFix(t *testing.T) {
	ctx := context.Background()
	db := openSyncIntegrationTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	// Use unique names per test run to avoid cross-run collisions.
	suffix := uuid.NewString()[:8]
	typeName := "test-type-" + suffix
	instanceName := "test-instance-" + suffix
	namespace := "test"

	// --- Seed integration_type v1 -----------------------------------------

	v1Doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_type",
		Metadata: model.ManifestMetadataInput{
			Namespace:   namespace,
			Name:        typeName,
			Description: "integration test fixture",
			Active:      boolPtrSync(true),
		},
		Spec: mustMarshalSpec(t, model.IntegrationTypeManifestSpec{
			ActionCatalog:    []model.IntegrationActionDefinition{{Name: "old_op"}},
			Adapter:          model.IntegrationAdapterSpec{Version: "0.1.0"},
			CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
			// Operator-managed reactors: must survive the sync.
			Reactors: []model.IntegrationTypeReactor{
				{EventType: "collaborator.created", Capability: "on_collaborator_created"},
			},
		}),
	}
	v1Checksum, err := manifestengine.Checksum(v1Doc)
	require.NoError(t, err)

	v1, err := repository.CreateManifestVersion(ctx, db, v1Doc, v1Checksum)
	require.NoError(t, err)
	t.Cleanup(func() { cleanupSyncTestManifest(t, db, "integration_type", namespace, typeName) })

	// --- Seed integration_instance pointing at the type -------------------

	instanceDoc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Namespace: namespace,
			Name:      instanceName,
			Active:    boolPtrSync(true),
		},
		Spec: mustMarshalSpec(t, model.IntegrationInstanceManifestSpec{
			TypeRef: model.ManifestSelector{Namespace: namespace, Name: typeName},
		}),
	}
	instanceChecksum, err := manifestengine.Checksum(instanceDoc)
	require.NoError(t, err)

	_, err = repository.CreateManifestVersion(ctx, db, instanceDoc, instanceChecksum)
	require.NoError(t, err)
	t.Cleanup(func() { cleanupSyncTestManifest(t, db, "integration_instance", namespace, instanceName) })

	// --- Build deps with stubbed InvokeDescribe ---------------------------

	// The stub returns a "v2" contract: 3 actions, updated adapter version, no
	// reactors (adapters never describe reactors; they're operator-managed).
	stubLive := model.IntegrationTypeManifestSpec{
		ActionCatalog: []model.IntegrationActionDefinition{
			{Name: "old_op"},
			{Name: "new_op_a"},
			{Name: "new_op_b"},
		},
		Adapter:          model.IntegrationAdapterSpec{Version: "0.2.0"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
	}
	deps := newSyncIntegrationTestDeps(db, stubLive)

	// --- First sync: expect v2 to be created ------------------------------

	require.NoError(t, SyncIntegrationType(ctx, deps, v1.ID))

	v2, err := repository.ResolveManifest(ctx, db, "integration_type", namespace, typeName, nil, true)
	require.NoError(t, err)
	assert.Equal(t, 2, v2.Version, "first sync must create v2")

	var newSpec model.IntegrationTypeManifestSpec
	require.NoError(t, json.Unmarshal(v2.Spec, &newSpec))
	assert.Len(t, newSpec.ActionCatalog, 3, "v2 must contain 3 actions from live spec")
	assert.Equal(t, "0.2.0", newSpec.Adapter.Version, "adapter version updated to live spec")
	require.Len(t, newSpec.Reactors, 1, "operator-managed reactors must survive sync")
	assert.Equal(t, "on_collaborator_created", newSpec.Reactors[0].Capability)

	// --- Verify integration_type.synced event persisted -------------------

	syncedCount := countSyncEventsByType(t, db, "integration_type.synced", v1.ID)
	assert.GreaterOrEqual(t, syncedCount, 1, "integration_type.synced event must be in event_log")

	// --- Idempotency: re-run must produce no v3 ---------------------------

	require.NoError(t, SyncIntegrationType(ctx, deps, v1.ID))

	// After the first sync, v1.ID is the original type manifest ID. The
	// GetIntegrationType dep looks up by ID — so we need to fetch the
	// active v2 manifest ID and sync against that to test idempotency of
	// the live spec (no diff between v2 and the same stub live spec).
	// Alternatively: the stub returns the same spec; if we pass v1.ID, the
	// syncer re-reads the active manifest for the (namespace,name) — but
	// actually GetManifestByID fetches by UUID, which is the v1 row UUID,
	// not the v2 row UUID. Re-sync via v2.ID to test idempotency properly.
	require.NoError(t, SyncIntegrationType(ctx, deps, v2.ID))

	v2Again, err := repository.ResolveManifest(ctx, db, "integration_type", namespace, typeName, nil, true)
	require.NoError(t, err)
	assert.Equal(t, 2, v2Again.Version, "second sync on v2.ID must not create v3 — no diff")
}

// ---------------------------------------------------------------------------
// integrationTestDeps: implements manifestsync.Deps with real Postgres for
// all methods except InvokeDescribe, which returns a canned stub response.
// ---------------------------------------------------------------------------

type syncIntegrationTestDeps struct {
	db       *sql.DB
	stubLive model.IntegrationTypeManifestSpec
}

func newSyncIntegrationTestDeps(db *sql.DB, stub model.IntegrationTypeManifestSpec) *syncIntegrationTestDeps {
	return &syncIntegrationTestDeps{db: db, stubLive: stub}
}

func (d *syncIntegrationTestDeps) Now() time.Time { return time.Now().UTC() }

func (d *syncIntegrationTestDeps) GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	m, err := repository.GetManifestByID(ctx, d.db, typeID)
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	var spec model.IntegrationTypeManifestSpec
	if err := json.Unmarshal(m.Spec, &spec); err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	return m, spec, nil
}

func (d *syncIntegrationTestDeps) ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	typeManifest, err := repository.GetManifestByID(ctx, d.db, typeID)
	if err != nil {
		return nil, nil, err
	}

	all, err := repository.ListManifests(ctx, d.db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, nil, err
	}

	var manifests []model.Manifest
	var specs []model.IntegrationInstanceManifestSpec
	for _, m := range all {
		var s model.IntegrationInstanceManifestSpec
		if err := json.Unmarshal(m.Spec, &s); err != nil {
			continue
		}
		if strings.EqualFold(s.TypeRef.Namespace, typeManifest.Metadata.Namespace) &&
			strings.EqualFold(s.TypeRef.Name, typeManifest.Metadata.Name) {
			manifests = append(manifests, m)
			specs = append(specs, s)
		}
	}
	return manifests, specs, nil
}

// InvokeDescribe ignores the real RPC and returns the canned stub response.
// This removes the RabbitMQ dependency from the integration test.
func (d *syncIntegrationTestDeps) InvokeDescribe(
	_ context.Context,
	_ model.Manifest,
	_ model.Manifest,
	_ model.IntegrationInstanceManifestSpec,
	_ model.IntegrationTypeManifestSpec,
) (model.IntegrationTypeManifestSpec, error) {
	return d.stubLive, nil
}

func (d *syncIntegrationTestDeps) ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, err
	}
	return repository.CreateManifestVersion(ctx, d.db, doc, checksum)
}

func (d *syncIntegrationTestDeps) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	aggType := aggregateTypeFor(eventType)
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID.String(),
		Payload:       payload,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

func boolPtrSync(b bool) *bool { return &b }

func mustMarshalSpec(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

// cleanupSyncTestManifest deletes all manifest rows for a given (kind, namespace, name).
// Registered via t.Cleanup so each test run is self-contained.
func cleanupSyncTestManifest(t *testing.T, db *sql.DB, kind, namespace, name string) {
	t.Helper()
	_, _ = db.Exec(
		`DELETE FROM public.manifests WHERE kind = $1 AND namespace = $2 AND name = $3`,
		kind, namespace, name,
	)
}

// countSyncEventsByType returns the number of event_log rows for a given
// event type and aggregate_id. aggregate_id is stored as a UUID string.
func countSyncEventsByType(t *testing.T, db *sql.DB, eventType string, aggregateID uuid.UUID) int {
	t.Helper()
	row := db.QueryRow(
		`SELECT COUNT(*) FROM public.event_log WHERE type = $1 AND aggregate_id = $2`,
		eventType, aggregateID.String(),
	)
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count events type=%q agg=%s: %v", eventType, aggregateID, err)
	}
	return n
}
