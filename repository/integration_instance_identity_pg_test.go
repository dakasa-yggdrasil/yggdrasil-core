package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// requireInstanceIdentityDBEnv turns the DB_URL skip into a failure where CI
// promises a PostgreSQL (the native-oidc-postgres job), so the semantics
// below can never silently stop being proven there.
const requireInstanceIdentityDBEnv = "REQUIRE_INSTANCE_IDENTITY_DB_TEST"

// openInstanceIdentityTestDB follows the DB_URL-gated convention of the other
// real-PostgreSQL repository tests. sqlmock cannot prove what these tests
// prove: the self-join from any version onto the active one, and the
// candidate join onto the active integration_type (ADR-0021).
func openInstanceIdentityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv(requireInstanceIdentityDBEnv) == "true" {
			t.Fatalf("%s=true but DB_URL is not set", requireInstanceIdentityDBEnv)
		}
		t.Skip("DB_URL not set; skipping integration instance identity PostgreSQL test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedIdentityManifest writes one manifest version the way manifest writes
// do (the previous active version of the same kind/namespace/name is
// deactivated; active=false writes a tombstone) and removes every row of the
// logical manifest after the test.
func seedIdentityManifest(t *testing.T, db *sql.DB, kind, namespace, name string, active bool, spec any) model.Manifest {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal %s spec: %v", kind, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	manifest, err := CreateManifestVersionTx(context.Background(), tx, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       kind,
		Metadata:   model.ManifestMetadataInput{Name: name, Namespace: namespace, Active: &active},
		Spec:       raw,
	}, "sha256:instance-identity-test")
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed %s %s/%s: %v", kind, namespace, name, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit %s seed: %v", kind, err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.manifests WHERE kind = $1 AND namespace = $2 AND name = $3`, kind, namespace, name)
	})
	return manifest
}

func typeSpec(provider string) map[string]any {
	return map[string]any{"provider": provider}
}

func instanceSpec(typeRef map[string]any) map[string]any {
	return map[string]any{"type_ref": typeRef, "status": "active"}
}

func requireIdentity(t *testing.T, got IntegrationInstanceIdentity, err error, want model.Manifest, provider string) {
	t.Helper()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	expected := IntegrationInstanceIdentity{
		Namespace:        want.Metadata.Namespace,
		Name:             want.Metadata.Name,
		ActiveManifestID: want.ID,
		ActiveVersion:    want.Version,
		TypeProvider:     provider,
	}
	if got != expected {
		t.Fatalf("identity=%+v, want %+v", got, expected)
	}
}

func requireNotResolvable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrIntegrationInstanceNotResolvable) {
		t.Fatalf("err=%v, want ErrIntegrationInstanceNotResolvable", err)
	}
}

func TestIntegrationInstanceIdentityAgainstPostgres(t *testing.T) {
	db := openInstanceIdentityTestDB(t)
	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	namespace := "adr0021-" + suffix
	typeNamespace := "adr0021-types-" + suffix
	typeName := "kube-" + suffix

	// The integration_type: v1 superseded by v2, which is active.
	typeV1 := seedIdentityManifest(t, db, "integration_type", typeNamespace, typeName, true, typeSpec("kubernetes"))
	typeV2 := seedIdentityManifest(t, db, "integration_type", typeNamespace, typeName, true, typeSpec("kubernetes"))
	byName := map[string]any{"namespace": typeNamespace, "name": typeName}

	t.Run("an old version resolves to the active one", func(t *testing.T) {
		v1 := seedIdentityManifest(t, db, "integration_instance", namespace, "reapplied", true, instanceSpec(byName))
		v2 := seedIdentityManifest(t, db, "integration_instance", namespace, "reapplied", true, instanceSpec(byName))
		v3 := seedIdentityManifest(t, db, "integration_instance", namespace, "reapplied", true, instanceSpec(byName))
		for _, wire := range []uuid.UUID{v1.ID, v2.ID, v3.ID} {
			got, err := ResolveIntegrationInstanceByManifestID(ctx, db, wire)
			requireIdentity(t, got, err, v3, "kubernetes")
		}
		got, err := ResolveIntegrationInstanceByName(ctx, db, namespace, "reapplied")
		requireIdentity(t, got, err, v3, "kubernetes")
	})

	t.Run("a tombstone has no active version", func(t *testing.T) {
		v1 := seedIdentityManifest(t, db, "integration_instance", namespace, "tombstoned", true, instanceSpec(byName))
		v2 := seedIdentityManifest(t, db, "integration_instance", namespace, "tombstoned", false, instanceSpec(byName))
		for _, wire := range []uuid.UUID{v1.ID, v2.ID} {
			_, err := ResolveIntegrationInstanceByManifestID(ctx, db, wire)
			requireNotResolvable(t, err)
		}
		_, err := ResolveIntegrationInstanceByName(ctx, db, namespace, "tombstoned")
		requireNotResolvable(t, err)
	})

	t.Run("a hard delete leaves nothing to resolve", func(t *testing.T) {
		v1 := seedIdentityManifest(t, db, "integration_instance", namespace, "deleted", true, instanceSpec(byName))
		if _, err := ResolveIntegrationInstanceByManifestID(ctx, db, v1.ID); err != nil {
			t.Fatalf("resolve before delete: %v", err)
		}
		if _, err := HardDeleteManifestByID(ctx, db, v1.ID); err != nil {
			t.Fatalf("hard delete: %v", err)
		}
		_, err := ResolveIntegrationInstanceByManifestID(ctx, db, v1.ID)
		requireNotResolvable(t, err)
		_, err = ResolveIntegrationInstanceByName(ctx, db, namespace, "deleted")
		requireNotResolvable(t, err)
	})

	t.Run("another kind never resolves as an instance", func(t *testing.T) {
		// A workflow shares the namespace/name of an active instance: the
		// workflow's id must not resolve, and the instance must not borrow the
		// workflow's row.
		instance := seedIdentityManifest(t, db, "integration_instance", namespace, "shared-name", true, instanceSpec(byName))
		workflow := seedIdentityManifest(t, db, "workflow", namespace, "shared-name", true, map[string]any{"steps": []any{}})
		_, err := ResolveIntegrationInstanceByManifestID(ctx, db, workflow.ID)
		requireNotResolvable(t, err)
		_, err = ResolveIntegrationInstanceByManifestID(ctx, db, typeV2.ID)
		requireNotResolvable(t, err)
		got, err := ResolveIntegrationInstanceByManifestID(ctx, db, instance.ID)
		requireIdentity(t, got, err, instance, "kubernetes")

		// An old instance version whose logical name now only has an active
		// row of another kind does not resolve through that row.
		retired := seedIdentityManifest(t, db, "integration_instance", namespace, "kind-swap", true, instanceSpec(byName))
		seedIdentityManifest(t, db, "integration_instance", namespace, "kind-swap", false, instanceSpec(byName))
		seedIdentityManifest(t, db, "workflow", namespace, "kind-swap", true, map[string]any{"steps": []any{}})
		_, err = ResolveIntegrationInstanceByManifestID(ctx, db, retired.ID)
		requireNotResolvable(t, err)
	})

	t.Run("the type must be the active version", func(t *testing.T) {
		pinnedActive := seedIdentityManifest(t, db, "integration_instance", namespace, "pinned-active", true,
			instanceSpec(map[string]any{"namespace": typeNamespace, "name": typeName, "version": typeV2.Version}))
		got, err := ResolveIntegrationInstanceByManifestID(ctx, db, pinnedActive.ID)
		requireIdentity(t, got, err, pinnedActive, "kubernetes")

		pinnedInactive := seedIdentityManifest(t, db, "integration_instance", namespace, "pinned-inactive", true,
			instanceSpec(map[string]any{"namespace": typeNamespace, "name": typeName, "version": typeV1.Version}))
		_, err = ResolveIntegrationInstanceByManifestID(ctx, db, pinnedInactive.ID)
		requireNotResolvable(t, err)

		byActiveID := seedIdentityManifest(t, db, "integration_instance", namespace, "type-by-active-id", true,
			instanceSpec(map[string]any{"manifest_id": typeV2.ID.String()}))
		got, err = ResolveIntegrationInstanceByManifestID(ctx, db, byActiveID.ID)
		requireIdentity(t, got, err, byActiveID, "kubernetes")

		byInactiveID := seedIdentityManifest(t, db, "integration_instance", namespace, "type-by-inactive-id", true,
			instanceSpec(map[string]any{"manifest_id": typeV1.ID.String()}))
		_, err = ResolveIntegrationInstanceByManifestID(ctx, db, byInactiveID.ID)
		requireNotResolvable(t, err)

		wrongNamespace := seedIdentityManifest(t, db, "integration_instance", namespace, "type-in-default-namespace", true,
			instanceSpec(map[string]any{"name": typeName}))
		_, err = ResolveIntegrationInstanceByManifestID(ctx, db, wrongNamespace.ID)
		requireNotResolvable(t, err)
	})

	t.Run("a type without a provider does not resolve", func(t *testing.T) {
		providerless := "providerless-" + suffix
		seedIdentityManifest(t, db, "integration_type", typeNamespace, providerless, true, map[string]any{"transport": "http_json"})
		instance := seedIdentityManifest(t, db, "integration_instance", namespace, "providerless", true,
			instanceSpec(map[string]any{"namespace": typeNamespace, "name": providerless}))
		_, err := ResolveIntegrationInstanceByManifestID(ctx, db, instance.ID)
		requireNotResolvable(t, err)
	})

	t.Run("an unknown id resolves nothing", func(t *testing.T) {
		_, err := ResolveIntegrationInstanceByManifestID(ctx, db, uuid.New())
		requireNotResolvable(t, err)
		_, err = ResolveIntegrationInstanceByName(ctx, db, namespace, "never-written")
		requireNotResolvable(t, err)
	})
}
