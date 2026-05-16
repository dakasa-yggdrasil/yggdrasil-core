package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleIntegrationWebhook accepts a provider webhook payload, verifies the
// HMAC against the integration_instance's stored secret, forwards to the
// adapter's on_webhook capability, and executes returned actions.
//
// Auth model: signature is the auth. No admin token required — the secret
// IS the proof-of-identity of the provider. Bad signature → 401 immediate.
func (s *Server) handleIntegrationWebhook(w http.ResponseWriter, r *http.Request) {
	rawInstanceID := strings.TrimSpace(r.PathValue("instance_id"))
	instanceID, err := uuid.Parse(rawInstanceID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid instance_id"})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "read body: " + err.Error()})
		return
	}

	// Resolve instance via the existing ExecuteIntegration path's prerequisites.
	// The simplest "have an instance spec with config" lookup is via repository:
	manifest, err := repository.GetManifestByID(r.Context(), s.db, instanceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "instance not found"})
		return
	}
	if manifest.Kind != "integration_instance" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "not an integration_instance"})
		return
	}

	// Parse instance spec to read config (webhook_secret, signature_scheme).
	var instanceSpec model.IntegrationInstanceManifestSpec
	if err := json.Unmarshal(manifest.Spec, &instanceSpec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "parse instance spec: " + err.Error()})
		return
	}
	// Hydrate credentials (so webhook_secret stored via secret://… resolves).
	if err := messagecontroller.HydrateIntegrationInstanceSecrets(r.Context(), s.db, &instanceSpec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "hydrate creds: " + err.Error()})
		return
	}

	scheme, _ := instanceSpec.Config["webhook_signature_scheme"].(string)
	secret, _ := instanceSpec.Config["webhook_secret"].(string)
	if scheme == "" || secret == "" {
		// Try credentials map as fallback
		if v, ok := instanceSpec.Credentials["webhook_secret"].(string); ok && secret == "" {
			secret = v
		}
	}
	if scheme == "" || secret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "instance has no webhook configuration (need webhook_secret + webhook_signature_scheme)"})
		return
	}
	if err := externalidentity.VerifySignature(scheme, secret, r.Header, body); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "signature verification failed: " + err.Error()})
		return
	}

	// Parse body as JSON (best-effort)
	var bodyJSON map[string]any
	_ = json.Unmarshal(body, &bodyJSON)

	headers := map[string]any{}
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp, err := messagecontroller.ExecuteIntegration(r.Context(), s.rabbitmq, s.db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{ManifestID: instanceID.String()},
		Operation:   "on_webhook",
		Capability:  "on_webhook",
		Input: map[string]any{
			"headers":   headers,
			"body_raw":  string(body),
			"body_json": bodyJSON,
		},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "adapter on_webhook failed: " + err.Error()})
		return
	}

	respOutput, _ := resp.Output.(map[string]any)
	if respOutput == nil {
		respOutput = map[string]any{}
	}
	actions, _ := respOutput["actions"].([]any)
	results := make([]map[string]any, 0, len(actions))
	for _, raw := range actions {
		act, _ := raw.(map[string]any)
		if act == nil {
			results = append(results, map[string]any{"status": "skipped_invalid_action"})
			continue
		}
		kind, _ := act["kind"].(string)
		switch kind {
		case "link_identity":
			results = append(results, applyLinkAction(r.Context(), s.db, instanceID, act))
		case "unlink_identity":
			results = append(results, applyUnlinkAction(r.Context(), s.db, instanceID, act))
		case "emit_event":
			results = append(results, applyEmitAction(r.Context(), s.db, act))
		default:
			results = append(results, map[string]any{"kind": kind, "status": "skipped_unknown_kind"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": results})
}

func applyLinkAction(ctx context.Context, db *sql.DB, instanceID uuid.UUID, act map[string]any) map[string]any {
	externalID, _ := act["external_id"].(string)
	if externalID == "" {
		return map[string]any{"kind": "link_identity", "status": "skipped_missing_external_id"}
	}
	match, _ := act["collaborator_match"].(map[string]any)
	collabID, err := resolveCollaboratorMatch(ctx, db, match)
	if err != nil {
		meta, _ := act["external_metadata"].(map[string]any)
		_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnknownExternal, instanceID,
			externalidentity.BuildUnknownExternalPayload(externalidentity.UnknownExternalInputs{
				IntegrationInstanceID: instanceID, ExternalID: externalID,
				ExternalMetadata: meta, DetectedAt: time.Now().UTC(),
			}))
		return map[string]any{"kind": "link_identity", "status": "skipped_no_collaborator", "error": err.Error()}
	}
	meta, _ := act["external_metadata"].(map[string]any)
	id, outcome, err := externalidentity.Upsert(ctx, db, externalidentity.UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            externalID,
		ExternalMetadata:      meta,
	})
	if err != nil {
		var cerr *externalidentity.ConflictError
		if errors.As(err, &cerr) {
			_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityConflictDetected, instanceID,
				externalidentity.BuildConflictPayload(externalidentity.ConflictInputs{
					IntegrationInstanceID:  cerr.IntegrationInstanceID,
					ExternalID:             cerr.ExternalID,
					IncomingCollaboratorID: cerr.IncomingCollaboratorID,
					ExistingCollaboratorID: cerr.ExistingCollaboratorID,
					DetectedAt:             time.Now().UTC(),
				}))
			return map[string]any{"kind": "link_identity", "status": "conflict"}
		}
		return map[string]any{"kind": "link_identity", "status": "error", "error": err.Error()}
	}
	if outcome != externalidentity.OutcomeConflict {
		_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, id,
			externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
				IdentityID: id, CollaboratorID: collabID,
				IntegrationInstanceID: instanceID, ExternalID: externalID,
				ReLinked: outcome == externalidentity.OutcomeReLinked,
				LinkedAt: time.Now().UTC(), ExternalMetadata: meta,
			}))
	}
	return map[string]any{"kind": "link_identity", "status": string(outcome), "identity_id": id.String()}
}

func applyUnlinkAction(ctx context.Context, db *sql.DB, instanceID uuid.UUID, act map[string]any) map[string]any {
	externalID, _ := act["external_id"].(string)
	if externalID == "" {
		return map[string]any{"kind": "unlink_identity", "status": "skipped_missing_external_id"}
	}
	rows, err := externalidentity.List(ctx, db, externalidentity.ListFilters{
		IntegrationInstanceID: &instanceID,
		ActiveOnly:            true,
		Limit:                 500,
	})
	if err != nil {
		return map[string]any{"kind": "unlink_identity", "status": "error", "error": err.Error()}
	}
	for _, ident := range rows {
		if ident.ExternalID == externalID {
			deleted, err := externalidentity.SoftDelete(ctx, db, ident.ID)
			if err != nil {
				return map[string]any{"kind": "unlink_identity", "status": "error", "error": err.Error()}
			}
			_ = externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityUnlinked, deleted.ID,
				externalidentity.BuildUnlinkedPayload(externalidentity.UnlinkedInputs{
					IdentityID: deleted.ID, CollaboratorID: deleted.CollaboratorID,
					IntegrationInstanceID: deleted.IntegrationInstanceID,
					ExternalID:            deleted.ExternalID,
					UnlinkedAt:            time.Now().UTC(),
				}))
			return map[string]any{"kind": "unlink_identity", "status": "unlinked", "identity_id": deleted.ID.String()}
		}
	}
	return map[string]any{"kind": "unlink_identity", "status": "not_found"}
}

func applyEmitAction(ctx context.Context, db *sql.DB, act map[string]any) map[string]any {
	eventType, _ := act["event_type"].(string)
	payload, _ := act["payload"].(map[string]any)
	aggregateIDStr, _ := act["aggregate_id"].(string)
	aggregateID, err := uuid.Parse(aggregateIDStr)
	if err != nil {
		return map[string]any{"kind": "emit_event", "status": "skipped_invalid_aggregate_id"}
	}
	if err := externalidentity.EmitEvent(ctx, db, eventType, aggregateID, payload); err != nil {
		return map[string]any{"kind": "emit_event", "status": "error", "error": err.Error()}
	}
	return map[string]any{"kind": "emit_event", "status": "emitted"}
}

// resolveCollaboratorMatch resolves a collaborator_match block to a collaborator_id.
func resolveCollaboratorMatch(ctx context.Context, db *sql.DB, match map[string]any) (uuid.UUID, error) {
	if match == nil {
		return uuid.Nil, errors.New("missing collaborator_match")
	}
	by, _ := match["by"].(string)
	value, _ := match["value"].(string)
	switch by {
	case "primary_email":
		var id uuid.UUID
		err := db.QueryRowContext(ctx, `SELECT id FROM collaborators WHERE primary_email = $1`, value).Scan(&id)
		return id, err
	case "collaborator_id":
		return uuid.Parse(value)
	case "external_id_lookup":
		var id uuid.UUID
		err := db.QueryRowContext(ctx, `
			SELECT collaborator_id FROM collaborator_external_identities
			WHERE external_id = $1 AND unlinked_at IS NULL LIMIT 1
		`, value).Scan(&id)
		return id, err
	default:
		return uuid.Nil, errors.New("unsupported collaborator_match.by")
	}
}
