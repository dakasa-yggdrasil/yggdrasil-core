package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
//  3. For each external row with no matching local row → attempt to auto-link it
//     on a deterministic match (unique collaborator by email or provider handle),
//     reusing Upsert + the linked event; if no unique match is found, emit
//     unknown_external as before.
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

	// Resolve the instance's provider (integration_type name, e.g. "github")
	// once, up front. Used to build the provider-handle match key
	// (<provider>_login). An empty provider just means handle matching by
	// convention is skipped; email matching still applies.
	provider := resolveInstanceProvider(ctx, db, instanceID)

	// External present but no local row → try to auto-link on a deterministic
	// (unique) match, else emit unknown_external.
	for extID, meta := range external {
		if _, ok := localByExtID[extID]; ok {
			continue
		}

		// Best-effort auto-link: if exactly one collaborator can be resolved
		// from the external metadata (email) or the provider handle, link it
		// instead of merely flagging it unknown. Any failure here is
		// non-fatal — we fall through to unknown_external.
		if collab, matched, err := findCollaboratorForExternal(ctx, db, provider, extID, meta); err == nil && matched {
			if autoLinkExternal(ctx, db, instanceID, collab, extID, meta, now) {
				continue
			}
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

// resolveInstanceProvider returns the integration_type name (e.g. "github")
// backing the given integration_instance, resolved through the manifest's
// type_ref — mirroring the (namespace, name) linkage used by
// listResyncInstances. Returns "" when it cannot be resolved (best-effort;
// the caller degrades to email-only matching).
func resolveInstanceProvider(ctx context.Context, db *sql.DB, instanceID uuid.UUID) string {
	var provider string
	err := db.QueryRowContext(ctx, `
		SELECT spec->'type_ref'->>'name'
		FROM manifests
		WHERE id = $1 AND kind = 'integration_instance'
	`, instanceID).Scan(&provider)
	if err != nil {
		return ""
	}
	return provider
}

// emailFromMeta pulls a usable email out of the external metadata, trying a
// few well-known keys in priority order. Returns "" when none is present.
func emailFromMeta(meta map[string]any) string {
	for _, k := range []string{"email", "primary_email", "work_email"} {
		if v, ok := meta[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// findCollaboratorForExternal attempts to resolve a UNIQUE local collaborator
// for an external identity that has no local link yet, using two deterministic
// signals:
//
//   - Email: an email read from meta (keys "email", "primary_email",
//     "work_email") matched case-insensitively against collaborators.primary_email.
//   - Handle: the external_id matched against a provider-handle trait/metadata
//     key, by convention "<provider>_login" (e.g. "github_login"), with the
//     bare provider name (e.g. "github") accepted as a fallback key.
//
// All distinct candidate collaborator IDs are unioned and de-duplicated. The
// match is returned ONLY when it is unambiguous: exactly one distinct
// collaborator. Zero matches or ambiguity (>1 distinct) returns (Nil, false,
// nil) — we never guess on ambiguity. Real DB errors are wrapped and returned.
func findCollaboratorForExternal(ctx context.Context, db *sql.DB, provider, extID string, meta map[string]any) (uuid.UUID, bool, error) {
	seen := make(map[uuid.UUID]struct{}, 2)

	collect := func(query string, args ...any) error {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			seen[id] = struct{}{}
		}
		return rows.Err()
	}

	// Email match.
	if email := emailFromMeta(meta); email != "" {
		if err := collect(
			`SELECT id FROM collaborators WHERE lower(primary_email) = lower($1)`,
			email,
		); err != nil {
			return uuid.Nil, false, fmt.Errorf("email match lookup: %w", err)
		}
	}

	// Handle match. Try the canonical "<provider>_login" key first, then the
	// bare provider name as a fallback. Both traits and metadata JSONB are
	// consulted. extID must be non-empty (callers already filter empties).
	if provider != "" && extID != "" {
		for _, key := range []string{provider + "_login", provider} {
			if err := collect(
				`SELECT id FROM collaborators WHERE traits->>($1) = $2 OR metadata->>($1) = $2`,
				key, extID,
			); err != nil {
				return uuid.Nil, false, fmt.Errorf("handle match lookup (%s): %w", key, err)
			}
		}
	}

	switch len(seen) {
	case 1:
		for id := range seen {
			return id, true, nil
		}
	}
	// 0 → no match; >1 → ambiguous, do not guess.
	return uuid.Nil, false, nil
}

// autoLinkExternal upserts the (collaborator, instance, external_id) link and,
// on success, emits the linked event — mirroring the webhook linker
// (controllers/httpapi/integration_webhook.go applyLinkAction) and the reactor
// dispatcher (addons/reactor_dispatcher.go persistExternalIdentity). It is
// best-effort: on an upsert error or a conflict (another collaborator already
// owns this external_id) it returns false so the caller can fall through to
// unknown_external (error) or simply skip (conflict). Returns true only when a
// link was actually established.
func autoLinkExternal(ctx context.Context, db *sql.DB, instanceID, collab uuid.UUID, extID string, meta map[string]any, now time.Time) bool {
	id, outcome, err := Upsert(ctx, db, UpsertInput{
		CollaboratorID:        collab,
		IntegrationInstanceID: instanceID,
		ExternalID:            extID,
		ExternalMetadata:      meta,
	})
	if err != nil {
		// Conflict: another collaborator owns this external_id — skip without
		// emitting unknown_external (do not claim it for a different collab).
		var cerr *ConflictError
		if errors.As(err, &cerr) {
			return true
		}
		// Real upsert failure → fall through to unknown_external (best-effort).
		return false
	}
	if outcome == OutcomeConflict {
		// Conflict surfaced via outcome (not error): skip, do not re-flag.
		return true
	}
	_ = EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, id,
		BuildLinkedPayload(LinkedInputs{
			IdentityID:            id,
			CollaboratorID:        collab,
			IntegrationInstanceID: instanceID,
			ExternalID:            extID,
			ReLinked:              outcome == OutcomeReLinked,
			LinkedAt:              now,
			ExternalMetadata:      meta,
		}))
	return true
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
