package bootstrap

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Canonical identity of the self-management integration. team_grants
// reference (YggdrasilSelfNamespace, YggdrasilSelfName) and
// repository.ResolveYggdrasilPermissions joins the integration_instance
// with these exact namespace/name columns, so the type, the instance and
// every grant MUST agree on this single pair. Historically the platform
// disagreed (yggdrasil-self/global vs yggdrasil-self-dakasa-validation/dakasa),
// which left non-admin collaborators with zero resolved permissions.
const (
	YggdrasilSelfNamespace = "global"
	YggdrasilSelfName      = "yggdrasil-self"
)

//go:embed seeds/yggdrasil-self/yggdrasil-self-integration-type.json
var yggdrasilSelfTypeSeed []byte

//go:embed seeds/yggdrasil-self/yggdrasil-self-integration-instance.json
var yggdrasilSelfInstanceSeed []byte

// ensureYggdrasilSelf provisions the canonical yggdrasil-self
// integration_type and its integration_instance so that a fresh install
// (and every reconcile) has an instance for team_grants to reference. It
// reuses the same validate + checksum-dedup persistence path as the
// baseline catalog seeds (importManifestsFromDir), so it is idempotent:
// running it on a database that already has the current version is a
// no-op. The type is created before the instance because the instance
// spec.type_ref points at the type by (namespace, name).
func ensureYggdrasilSelf(ctx context.Context, db *sql.DB) error {
	// Type first: the instance references it by (namespace, name).
	for _, seed := range []struct {
		label   string
		payload []byte
	}{
		{"integration_type", yggdrasilSelfTypeSeed},
		{"integration_instance", yggdrasilSelfInstanceSeed},
	} {
		var doc model.ManifestDocument
		if err := json.Unmarshal(seed.payload, &doc); err != nil {
			return fmt.Errorf("parse embedded yggdrasil-self %s seed: %w", seed.label, err)
		}

		doc = manifestengine.NormalizeDocument(doc)
		if err := manifestengine.ValidateDocument(doc); err != nil {
			return fmt.Errorf("validate embedded yggdrasil-self %s seed: %w", seed.label, err)
		}

		if _, err := upsertManifestVersion(ctx, db, doc); err != nil {
			return fmt.Errorf("persist yggdrasil-self %s: %w", seed.label, err)
		}
	}

	return nil
}
