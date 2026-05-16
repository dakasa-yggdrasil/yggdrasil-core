package manifestsync

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Deps is the interface the syncer requires from its runtime environment.
// The production implementation lives in addons/manifest_sync.go (Task 9).
// Tests use a fake.
type Deps interface {
	GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error)
	ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error)
	InvokeDescribe(ctx context.Context, instanceManifest model.Manifest, typeManifest model.Manifest, instanceSpec model.IntegrationInstanceManifestSpec, typeSpec model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error)
	ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error)
	EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error
	Now() time.Time
}

// SyncIntegrationType auto-heals one integration_type manifest from its adapter's live
// describe response. It returns a non-nil error only when EmitEvent itself fails;
// all sync outcomes (success, skip, no-op) are encoded as emitted events.
func SyncIntegrationType(ctx context.Context, d Deps, typeID uuid.UUID) error {
	now := d.Now()

	// Step 1: Resolve the integration_type manifest.
	typeManifest, currentSpec, err := d.GetIntegrationType(ctx, typeID)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:      typeID,
			Reason:      SkipReasonTypeNotFound,
			Error:       err.Error(),
			AttemptedAt: now,
		}))
	}

	// Step 2: List instances for this integration_type.
	instances, instanceSpecs, err := d.ListInstances(ctx, typeID)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:        typeID,
			TypeNamespace: typeManifest.Metadata.Namespace,
			TypeName:      typeManifest.Metadata.Name,
			Reason:        SkipReasonNoDescribableInstance,
			Error:         err.Error(),
			AttemptedAt:   now,
		}))
	}
	if len(instances) == 0 {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:        typeID,
			TypeNamespace: typeManifest.Metadata.Namespace,
			TypeName:      typeManifest.Metadata.Name,
			Reason:        SkipReasonNoInstances,
			AttemptedAt:   now,
		}))
	}

	// Step 3: Pick first instance.
	srcManifest := instances[0]
	srcSpec := instanceSpecs[0]
	srcID := srcManifest.ID

	// Step 4: Invoke describe via the selected instance.
	liveSpec, err := d.InvokeDescribe(ctx, srcManifest, typeManifest, srcSpec, currentSpec)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       typeManifest.Metadata.Namespace,
			TypeName:            typeManifest.Metadata.Name,
			Reason:              SkipReasonRPCFailed,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 5: Validate live spec.
	if err := validateLiveSpec(liveSpec); err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       typeManifest.Metadata.Namespace,
			TypeName:            typeManifest.Metadata.Name,
			Reason:              SkipReasonInvalidDescribe,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 6: Merge live spec with current (preserving operator-managed fields).
	newSpec, diff := MergeSpec(currentSpec, liveSpec)

	// Step 7: No-op check.
	if reflect.DeepEqual(currentSpec, newSpec) {
		if os.Getenv("DEBUG_SYNC_NO_OP") == "true" {
			return d.EmitEvent(ctx, "integration_type.sync_no_op", typeID, buildNoOpPayload(noOpInputs{
				TypeID:           typeID,
				TypeNamespace:    typeManifest.Metadata.Namespace,
				TypeName:         typeManifest.Metadata.Name,
				SourceInstanceID: srcID,
				CheckedAt:        now,
			}))
		}
		return nil
	}

	// Step 8: Apply new manifest version.
	specJSON, err := json.Marshal(newSpec)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       typeManifest.Metadata.Namespace,
			TypeName:            typeManifest.Metadata.Name,
			Reason:              SkipReasonApplyFailed,
			Error:               fmt.Sprintf("marshal spec: %s", err.Error()),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	active := true
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1",
		Kind:       "integration_type",
		Metadata: model.ManifestMetadataInput{
			Namespace:   typeManifest.Metadata.Namespace,
			Name:        typeManifest.Metadata.Name,
			Description: typeManifest.Metadata.Description,
			Active:      &active,
		},
		Spec: json.RawMessage(specJSON),
	}

	applied, err := d.ApplyManifestVersion(ctx, doc)
	if err != nil {
		return d.EmitEvent(ctx, "integration_type.sync_skipped", typeID, buildSkippedPayload(skippedInputs{
			TypeID:              typeID,
			TypeNamespace:       typeManifest.Metadata.Namespace,
			TypeName:            typeManifest.Metadata.Name,
			Reason:              SkipReasonApplyFailed,
			Error:               err.Error(),
			AttemptedInstanceID: &srcID,
			AttemptedAt:         now,
		}))
	}

	// Step 9: Emit synced event.
	return d.EmitEvent(ctx, "integration_type.synced", typeID, buildSyncedPayload(syncedInputs{
		TypeID:           typeID,
		TypeNamespace:    typeManifest.Metadata.Namespace,
		TypeName:         typeManifest.Metadata.Name,
		FromVersion:      typeManifest.Version,
		ToVersion:        applied.Version,
		Diff:             diff,
		SourceInstanceID: srcID,
		SyncedAt:         now,
	}))
}

// validateLiveSpec rejects describe responses that are structurally incomplete.
// A valid live spec must have at least one action_catalog entry, a non-empty
// adapter version, and a non-empty credential_schema mode.
func validateLiveSpec(s model.IntegrationTypeManifestSpec) error {
	if len(s.ActionCatalog) == 0 {
		return fmt.Errorf("live spec has empty action_catalog")
	}
	if strings.TrimSpace(s.Adapter.Version) == "" {
		return fmt.Errorf("live spec has empty adapter.version")
	}
	if strings.TrimSpace(s.CredentialSchema.Mode) == "" {
		return fmt.Errorf("live spec has empty credential_schema.mode")
	}
	return nil
}
