package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// handleIntegrationTypeSync runs a manual sync for one integration_type.
// Uses the same admin auth as POST /api/v1/manifests.
//
// Returns:
//
//	200 {status: "synced"|"no_op", from_version, to_version, diff_summary, source_instance_id}
//	400 {error: "invalid uuid"}
//	401 if not authorized
//	404 {error: "type not found"}
//	422 {status: "skipped", reason, error}
//	500 {error: ...} on internal failure
func (s *Server) handleIntegrationTypeSync(deps manifestsync.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := authorizeAuthAdminRequest(r); err != nil {
			writeMappedError(w, err)
			return
		}

		raw := strings.TrimSpace(r.PathValue("id"))
		typeID, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uuid"})
			return
		}

		cap := &captureEmitter{Deps: deps}
		if syncErr := manifestsync.SyncIntegrationType(r.Context(), cap, typeID); syncErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": syncErr.Error()})
			return
		}

		switch cap.lastEventType {
		case "integration_type.synced":
			writeJSON(w, http.StatusOK, map[string]any{
				"status":             "synced",
				"from_version":       cap.lastPayload["from_version"],
				"to_version":         cap.lastPayload["to_version"],
				"diff_summary":       cap.lastPayload["diff_summary"],
				"source_instance_id": cap.lastPayload["source_instance_id"],
			})
		case "integration_type.sync_no_op", "":
			writeJSON(w, http.StatusOK, map[string]any{"status": "no_op"})
		case "integration_type.sync_skipped":
			reason, _ := cap.lastPayload["reason"].(string)
			if reason == string(manifestsync.SkipReasonTypeNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "type not found"})
				return
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"status": "skipped",
				"reason": reason,
				"error":  cap.lastPayload["error"],
			})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "unknown outcome"})
		}
	}
}

// captureEmitter wraps manifestsync.Deps, delegating all methods to the inner
// Deps but capturing the last EmitEvent call so the HTTP handler can echo the
// outcome back to the operator synchronously.
type captureEmitter struct {
	manifestsync.Deps                   // embeds interface; all 6 methods delegate automatically
	lastEventType string
	lastPayload   map[string]any
}

// EmitEvent overrides the embedded Deps.EmitEvent to capture the outcome before
// forwarding to the real implementation.
func (c *captureEmitter) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	c.lastEventType = eventType
	c.lastPayload = payload
	return c.Deps.EmitEvent(ctx, eventType, aggregateID, payload)
}

// buildManifestSyncDeps constructs a production manifestsync.Deps from the
// Server's existing db and rabbitmq fields. This avoids importing the addons
// package (which already imports httpapi — circular) by duplicating only the
// thin wiring logic, not the business logic which lives in internal/manifestsync.
func (s *Server) buildManifestSyncDeps() manifestsync.Deps {
	return &httpManifestSyncDeps{
		db:              s.db,
		conn:            s.rabbitmq,
		describeTimeout: 10 * time.Second,
	}
}

// httpManifestSyncDeps is a local production implementation of manifestsync.Deps
// using the Server's existing db + rabbitmq connection. Mirrors addons.productionDeps
// but lives here to avoid the httpapi→addons circular import (addons imports httpapi).
type httpManifestSyncDeps struct {
	db              *sql.DB
	conn            *amqp.Connection
	describeTimeout time.Duration
}

func (p *httpManifestSyncDeps) Now() time.Time { return time.Now().UTC() }

func (p *httpManifestSyncDeps) GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	m, err := repository.GetManifestByID(ctx, p.db, typeID)
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("get integration_type %s: %w", typeID, err)
	}
	if m.Kind != "integration_type" {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("manifest %s is not integration_type (kind=%s)", typeID, m.Kind)
	}
	var spec model.IntegrationTypeManifestSpec
	if err := json.Unmarshal(m.Spec, &spec); err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("unmarshal type spec: %w", err)
	}
	return m, spec, nil
}

func (p *httpManifestSyncDeps) ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
	t, err := repository.GetManifestByID(ctx, p.db, typeID)
	if err != nil {
		return nil, nil, fmt.Errorf("get integration_type for listing instances: %w", err)
	}

	all, err := repository.ListManifests(ctx, p.db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list integration_instance manifests: %w", err)
	}

	var instances []model.Manifest
	var specs []model.IntegrationInstanceManifestSpec
	for _, m := range all {
		var spec model.IntegrationInstanceManifestSpec
		if ierr := json.Unmarshal(m.Spec, &spec); ierr != nil {
			continue
		}
		if !strings.EqualFold(spec.TypeRef.Namespace, t.Metadata.Namespace) ||
			!strings.EqualFold(spec.TypeRef.Name, t.Metadata.Name) {
			continue
		}
		instances = append(instances, m)
		specs = append(specs, spec)
	}
	return instances, specs, nil
}

func (p *httpManifestSyncDeps) InvokeDescribe(
	ctx context.Context,
	instanceManifest model.Manifest,
	typeManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeSpec model.IntegrationTypeManifestSpec,
) (model.IntegrationTypeManifestSpec, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, p.describeTimeout)
	defer cancel()
	return messagecontroller.DescribeIntegrationType(rpcCtx, p.conn, instanceManifest, typeManifest, instanceSpec, typeSpec)
}

func (p *httpManifestSyncDeps) ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("compute manifest checksum: %w", err)
	}
	return repository.CreateManifestVersion(ctx, p.db, doc, checksum)
}

func (p *httpManifestSyncDeps) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction for emit event: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	aggType := eventType
	if idx := strings.IndexByte(eventType, '.'); idx > 0 {
		aggType = eventType[:idx]
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit event %q: %w", eventType, err)
	}
	return tx.Commit()
}
