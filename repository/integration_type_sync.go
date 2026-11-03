package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A notification may contain an immutable historical type ID. Reconcile the
// active logical type so an old instance cannot keep cloning a healed catalog
// or overwrite current operator-owned fields with its historical values.
func CurrentIntegrationTypeForSync(ctx context.Context, db *sql.DB, requested uuid.UUID) (model.Manifest, error) {
	old, err := GetManifestByID(ctx, db, requested)
	if err != nil {
		return model.Manifest{}, err
	}
	if old.Kind != "integration_type" {
		return model.Manifest{}, fmt.Errorf("sync target is not integration_type")
	}
	return ResolveManifest(ctx, db, old.Kind, old.Metadata.Namespace, old.Metadata.Name, nil, true)
}

// Only automatic integration-type synchronization uses this conditional write.
// Explicit manifest creation keeps its existing version-creation semantics.
func ApplyIntegrationTypeSyncVersion(ctx context.Context, db *sql.DB, expected model.Manifest, doc model.ManifestDocument, checksum string) (model.Manifest, error) {
	if expected.ID == uuid.Nil || expected.Kind != "integration_type" || doc.Kind != expected.Kind || doc.Metadata.Namespace != expected.Metadata.Namespace || doc.Metadata.Name != expected.Metadata.Name || !documentActive(doc) {
		return model.Manifest{}, fmt.Errorf("matching active integration type required")
	}
	actual, err := manifestengine.Checksum(doc)
	if err != nil || actual != checksum {
		return model.Manifest{}, fmt.Errorf("integration type sync checksum refused")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Manifest{}, err
	}
	defer tx.Rollback()
	key, _ := json.Marshal([]string{"integration-type-sync", doc.Metadata.Namespace, doc.Metadata.Name})
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, string(key)).Scan(&locked); err != nil || !locked {
		return model.Manifest{}, fmt.Errorf("integration type sync already in progress")
	}
	current, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE kind=$1 AND namespace=$2 AND name=$3 AND active=TRUE ORDER BY version DESC LIMIT 1 FOR UPDATE`, doc.Kind, doc.Metadata.Namespace, doc.Metadata.Name))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Manifest{}, ErrManifestNotFound
	}
	if err != nil {
		return model.Manifest{}, err
	}
	var oldSpec, newSpec any
	if json.Unmarshal(current.Spec, &oldSpec) != nil || json.Unmarshal(doc.Spec, &newSpec) != nil {
		return model.Manifest{}, fmt.Errorf("integration type sync spec invalid")
	}
	if current.Checksum == checksum && current.APIVersion == doc.APIVersion && strings.TrimSpace(current.Metadata.Description) == strings.TrimSpace(doc.Metadata.Description) && maps.Equal(current.Metadata.Labels, doc.Metadata.Labels) && reflect.DeepEqual(oldSpec, newSpec) {
		if err = tx.Commit(); err != nil {
			return model.Manifest{}, err
		}
		return current, nil
	}
	if current.ID != expected.ID || current.Checksum != expected.Checksum {
		return model.Manifest{}, fmt.Errorf("integration type changed during describe; sync held")
	}
	result, err := CreateManifestVersionTx(ctx, tx, doc, checksum)
	if err != nil {
		return model.Manifest{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.Manifest{}, err
	}
	return result, nil
}
