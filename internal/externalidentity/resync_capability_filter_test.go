package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListResyncInstances_FiltersByListIdentitiesCapability asserts the external-identity
// resync only selects instances whose integration_type actually declares list_identities.
// A non-identity adapter (e.g. the ai-guardian fleet, whose type declares no
// list_identities) must NOT be probed — dispatching list_identities to it is rejected with
// unsupported_capability, which the adapter logs at error level and Heimdall surfaces as a
// spurious "adapter contract mismatch". Requires DB_URL; skipped otherwise.
func TestListResyncInstances_FiltersByListIdentitiesCapability(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		t.Skip("DB_URL not set; skipping (needs real postgres)")
	}
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	ns := "resync-cap-" + uuid.NewString()[:8]

	// Identity source: type declares list_identities (in action_catalog) → probe it.
	seedResyncType(t, db, ns, "src-with-cap",
		`{"action_catalog":[{"name":"list_identities","description":"x"},{"name":"discover"}],"capabilities":["describe"]}`)
	withID := seedResyncInstance(t, db, ns, "inst-with-cap", ns, "src-with-cap")

	// Identity source declaring the capability only in the capabilities[] list → also probe.
	seedResyncType(t, db, ns, "src-caps-only",
		`{"action_catalog":[{"name":"discover"}],"capabilities":["describe","list_identities"]}`)
	capsOnlyID := seedResyncInstance(t, db, ns, "inst-caps-only", ns, "src-caps-only")

	// Non-identity adapter (ai-guardian-like): no list_identities anywhere → skip it.
	seedResyncType(t, db, ns, "guardian-no-cap",
		`{"action_catalog":[{"name":"observe_manifests"}],"capabilities":["describe","execute"]}`)
	withoutID := seedResyncInstance(t, db, ns, "inst-without-cap", ns, "guardian-no-cap")

	ids, err := listResyncInstances(ctx, db)
	require.NoError(t, err)

	got := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		got[id] = true
	}
	assert.True(t, got[withID], "instance whose type declares list_identities (action_catalog) must be probed")
	assert.True(t, got[capsOnlyID], "instance whose type declares list_identities (capabilities) must be probed")
	assert.False(t, got[withoutID], "instance whose type lacks list_identities must be skipped")
}

func seedResyncType(t *testing.T, db *sql.DB, namespace, name, spec string) {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	_, err = repository.CreateManifestVersionTx(context.Background(), tx, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_type",
		Metadata:   model.ManifestMetadataInput{Name: name, Namespace: namespace},
		Spec:       json.RawMessage(spec),
	}, "sha256:test")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM manifests WHERE kind='integration_type' AND namespace=$1 AND name=$2`, namespace, name)
	})
}

func seedResyncInstance(t *testing.T, db *sql.DB, namespace, name, typeNS, typeName string) uuid.UUID {
	t.Helper()
	spec := fmt.Sprintf(`{"type_ref":{"namespace":%q,"name":%q}}`, typeNS, typeName)
	tx, err := db.Begin()
	require.NoError(t, err)
	m, err := repository.CreateManifestVersionTx(context.Background(), tx, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_instance",
		Metadata:   model.ManifestMetadataInput{Name: name, Namespace: namespace},
		Spec:       json.RawMessage(spec),
	}, "sha256:test")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM manifests WHERE id=$1`, m.ID)
	})
	return m.ID
}
