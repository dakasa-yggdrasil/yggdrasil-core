package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// ResyncTick runs ONE pass of the external identity re-sync over every
// active integration_instance that declares the list_identities capability.
//
// Logic per instance:
//
//  1. Ask the adapter (capability: list_identities) for {external_id, external_metadata}[]
//  2. Load active local rows for that instance.
//  3. For each external row → if no matching local row, emit unknown_external.
//  4. For each local row → if external_id missing from adapter response, emit drift_detected.
//  5. Metadata divergence is a future extension; the current drift_detected schema
//     does not carry observed/stored metadata fields (additionalProperties: false).
//
// Returns the number of instances processed (for tests/telemetry). Errors
// processing one instance are logged-and-skipped; the tick keeps going.
func ResyncTick(ctx context.Context, db *sql.DB, conn *amqp.Connection) (int, error) {
	instances, err := listResyncInstances(ctx, db)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, id := range instances {
		if err := resyncInstance(ctx, db, conn, id); err != nil {
			// Per-instance errors are swallowed so one bad adapter doesn't
			// block the rest of the tick.
			continue
		}
		processed++
	}
	return processed, nil
}

// listResyncInstances returns the IDs of active integration_instance manifests whose
// integration_type actually declares the list_identities capability — in its
// action_catalog or its capabilities list. This honors ResyncTick's contract (only
// identity-source instances are probed) and, critically, avoids dispatching
// list_identities to adapters that don't support it: such a dispatch reaches the adapter
// and is rejected with unsupported_capability, which the adapter logs at error level and
// Heimdall then surfaces as a spurious "adapter contract mismatch" (observed for the
// ai-guardian fleet, whose type declares no list_identities). The JSONB containment uses
// `@>`, so action_catalog entries carrying extra fields (description, category, …) still
// match on name; type_ref is resolved by (namespace, name), the canonical instance→type
// linkage used throughout the manifest catalog.
func listResyncInstances(ctx context.Context, db *sql.DB) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT ii.id
		FROM manifests ii
		JOIN manifests it
		  ON it.kind = 'integration_type'
		 AND it.active = true
		 AND it.namespace = (ii.spec->'type_ref'->>'namespace')
		 AND it.name      = (ii.spec->'type_ref'->>'name')
		WHERE ii.kind = 'integration_instance'
		  AND ii.active = true
		  AND (
		        it.spec->'action_catalog' @> jsonb_build_array(jsonb_build_object('name', 'list_identities'))
		     OR it.spec->'capabilities'   @> '["list_identities"]'::jsonb
		      )
	`)
	if err != nil {
		return nil, fmt.Errorf("list integration_instance manifests: %w", err)
	}
	defer rows.Close()

	var instances []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		instances = append(instances, id)
	}
	return instances, rows.Err()
}

func resyncInstance(ctx context.Context, db *sql.DB, conn *amqp.Connection, instanceID uuid.UUID) error {
	resp, err := message.ExecuteIntegration(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{ManifestID: instanceID.String()},
		Operation:   "list_identities",
		Capability:  "list_identities",
		Input:       map[string]any{},
	})
	if err != nil {
		// Adapter probably doesn't support list_identities — skip silently.
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "unsupported") ||
			strings.Contains(errLower, "unknown") ||
			strings.Contains(errLower, "not found") {
			return nil
		}
		return err
	}

	out, _ := resp.Output.(map[string]any)
	if out == nil {
		return nil
	}
	identsRaw, _ := out["identities"].([]any)
	external := make(map[string]map[string]any, len(identsRaw))
	for _, raw := range identsRaw {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		extID, _ := m["external_id"].(string)
		if extID == "" {
			continue
		}
		meta, _ := m["external_metadata"].(map[string]any)
		external[extID] = meta
	}

	local, err := List(ctx, db, ListFilters{
		IntegrationInstanceID: &instanceID,
		ActiveOnly:            true,
		Limit:                 10000,
	})
	if err != nil {
		return err
	}
	localByExtID := make(map[string]Identity, len(local))
	for _, ident := range local {
		localByExtID[ident.ExternalID] = ident
	}

	now := time.Now().UTC()

	// External present but no local row → unknown_external.
	for extID, meta := range external {
		if _, ok := localByExtID[extID]; ok {
			continue
		}
		_ = EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnknownExternal, instanceID,
			BuildUnknownExternalPayload(UnknownExternalInputs{
				IntegrationInstanceID: instanceID,
				ExternalID:            extID,
				ExternalMetadata:      meta,
				DetectedAt:            now,
			}))
	}

	// Local present but external missing → drift_detected.
	for extID, ident := range localByExtID {
		if _, present := external[extID]; present {
			// Metadata divergence detection is deferred: the drift_detected
			// JSON schema uses additionalProperties:false and carries only
			// the five canonical fields. A schema extension can add
			// observed_metadata/stored_metadata in a future iteration.
			continue
		}
		_ = EmitEvent(ctx, db, repository.EventTypeExternalIdentityDriftDetected, ident.ID,
			BuildDriftPayload(DriftInputs{
				IdentityID:            ident.ID,
				CollaboratorID:        ident.CollaboratorID,
				IntegrationInstanceID: ident.IntegrationInstanceID,
				ExternalID:            ident.ExternalID,
				DetectedAt:            now,
			}))
	}
	return nil
}

// metadataEqual returns true when two metadata maps are JSON-equivalent.
// Cheap, order-independent equality based on canonical JSON marshalling.
// Exported for use in future metadata-drift detection when the event schema
// is extended to carry observed/stored metadata fields.
func metadataEqual(a, b map[string]any) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}
