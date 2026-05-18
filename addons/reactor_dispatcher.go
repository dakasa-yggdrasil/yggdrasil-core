package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reactors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/teamprovisioning"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("reactor-dispatcher", bootstrapReactorDispatcher, 70)
}

// bootstrapReactorDispatcher starts the reactor Runner that claims pending
// reactions and dispatches them to integration adapters via RabbitMQ.
//
// Controlled by:
//
//	REACTOR_RUNNER_INTERVAL     — poll cadence (e.g. "5s"). Default 5s.
//	REACTOR_RUNNER_BATCH_SIZE   — rows claimed per tick. Default 50.
//	REACTOR_RUNNER_PARALLELISM  — concurrent dispatches per tick. Default 10.
//	REACTOR_STUCK_THRESHOLD     — in-progress age before re-queuing. Default 10m.
func bootstrapReactorDispatcher(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres addon not enabled — nothing to do.
		return nil
	}

	conn, ok := RabbitMQ(app)
	if !ok {
		// RabbitMQ addon not enabled — skip silently; the runner only makes
		// sense when there is a broker to dispatch through.
		return nil
	}

	logger, _ := Logger(app)

	runner := &reactors.Runner{
		DB:             db,
		Logger:         logger,
		Caller:         &rabbitmqReactorCaller{conn: conn, db: db, logger: logger},
		Interval:       envDurOrDefault("REACTOR_RUNNER_INTERVAL", 5*time.Second),
		BatchSize:      envIntOrDefault("REACTOR_RUNNER_BATCH_SIZE", 50),
		Parallelism:    envIntOrDefault("REACTOR_RUNNER_PARALLELISM", 10),
		StuckThreshold: envDurOrDefault("REACTOR_STUCK_THRESHOLD", 10*time.Minute),
	}

	go func() {
		if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("reactor runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	if logger != nil {
		logger.Info("reactor dispatcher addon started",
			zap.Duration("interval", runner.Interval),
			zap.Int("batch_size", runner.BatchSize),
			zap.Int("parallelism", runner.Parallelism),
			zap.Duration("stuck_threshold", runner.StuckThreshold),
		)
	}
	return nil
}

// rabbitmqReactorCaller implements reactors.Caller by resolving the
// integration_instance manifest from DB and dispatching via the canonical
// message.ExecuteIntegration path (resolve → hydrate secrets → adapter RPC).
type rabbitmqReactorCaller struct {
	conn   *amqp.Connection
	db     *sql.DB
	logger *zap.Logger
}

// Call implements reactors.Caller.
//
// The payload produced by reactors.BuildReactorPayload is a JSON blob that the
// integration adapter expects as its execute "input".  We unmarshal it into a
// map so the existing AdapterExecuteIntegrationRequest.Input field carries it
// unmodified, then delegate to message.ExecuteIntegration which handles the
// full resolve → hydrate-secrets → transport-call chain.
//
// Pre-call (read side): if the reactor payload carries a collaborator_id, we
// look up the active external identity for (collaborator, integration_instance)
// and embed it under input._context.external_identity before dispatch.
//
// Post-success (write side): if the adapter response output carries
// output._yggdrasil.external_identity we upsert the identity and emit a linked
// event.  Both side-effects are best-effort — failures are logged but never
// surfaced as Call errors, so the reaction's core outcome is never affected.
func (c *rabbitmqReactorCaller) Call(
	ctx context.Context,
	integrationInstanceID string,
	capability string,
	payload []byte,
) error {
	var input map[string]any
	if err := json.Unmarshal(payload, &input); err != nil {
		return fmt.Errorf("decode reactor payload: %w", err)
	}

	// Read-side embed: pre-populate _context.external_identity when we can
	// resolve (collaborator, integration_instance) → active identity.
	collabID, instanceID, havePair := parseReactorIDs(input, integrationInstanceID)
	if havePair && c.db != nil {
		if ident, err := externalidentity.ActiveFor(ctx, c.db, collabID, instanceID); err == nil && ident != nil {
			externalidentity.EmbedIntoInput(input, externalidentity.EmbeddedIdentity{
				ExternalID:       ident.ExternalID,
				ExternalMetadata: ident.ExternalMetadata,
				LinkedAt:         ident.LinkedAt.UTC().Format(time.RFC3339),
				LastSeenAt:       ident.LastSeenAt.UTC().Format(time.RFC3339),
			})
		} else if err != nil && c.logger != nil {
			c.logger.Warn("reactor: external identity lookup failed (non-fatal)",
				zap.String("collaborator_id", collabID.String()),
				zap.String("integration_instance_id", integrationInstanceID),
				zap.Error(err),
			)
		}
	}

	// Read-side embed: pre-populate _context.team_provisioned when dispatching
	// a team.* reaction so adapters can target the right external resource
	// without a fresh list call.
	c.embedTeamProvisioned(ctx, capability, integrationInstanceID, input)

	req := model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			ManifestID: integrationInstanceID,
		},
		Operation:  capability,
		Capability: capability,
		Input:      input,
	}

	resp, err := message.ExecuteIntegration(ctx, c.conn, c.db, req)
	if err != nil {
		return err
	}

	// Write-side extract: if the adapter signalled an external identity in its
	// response, persist it.  This is entirely best-effort.
	if havePair && c.db != nil {
		if outputMap, ok := resp.Output.(map[string]any); ok {
			if ext, ok := externalidentity.ExtractFromOutput(outputMap); ok {
				c.persistExternalIdentity(ctx, collabID, instanceID, ext)
			}
		}
	}

	// Team provisioning envelope: when on_team_created / on_team_updated
	// returns `_yggdrasil.team_provisioned`, upsert team_provisioning_log so
	// the reconcile cron skips this pair and /provisioning-status shows it.
	if c.db != nil {
		if outputMap, ok := resp.Output.(map[string]any); ok {
			if ext, ok := teamprovisioning.ExtractFromOutput(outputMap); ok {
				c.persistTeamProvisioning(ctx, integrationInstanceID, input, ext, capability)
			}
		}
	}

	return nil
}

// parseReactorIDs extracts (collaborator_id, integration_instance_id) from the
// reactor input map and the already-known integrationInstanceID string.
// Returns (zero, zero, false) when either UUID is absent or malformed.
func parseReactorIDs(input map[string]any, integrationInstanceID string) (uuid.UUID, uuid.UUID, bool) {
	collabIDStr, _ := input["collaborator_id"].(string)
	if strings.TrimSpace(collabIDStr) == "" {
		return uuid.Nil, uuid.Nil, false
	}
	collabID, err := uuid.Parse(collabIDStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	instanceID, err := uuid.Parse(integrationInstanceID)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return collabID, instanceID, true
}

// persistExternalIdentity upserts the extracted identity and, when not a
// conflict, emits the appropriate linked event.  All errors are logged and
// swallowed — the reaction has already succeeded.
func (c *rabbitmqReactorCaller) persistExternalIdentity(
	ctx context.Context,
	collabID uuid.UUID,
	instanceID uuid.UUID,
	ext externalidentity.Extracted,
) {
	id, outcome, err := externalidentity.Upsert(ctx, c.db, externalidentity.UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            ext.ExternalID,
		ExternalMetadata:      ext.ExternalMetadata,
	})
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("reactor: external identity upsert failed (non-fatal)",
				zap.String("collaborator_id", collabID.String()),
				zap.String("integration_instance_id", instanceID.String()),
				zap.String("external_id", ext.ExternalID),
				zap.Error(err),
			)
		}
		return
	}
	if outcome == externalidentity.OutcomeConflict {
		// Conflict: another collaborator already owns this external_id.
		// Logged at warn; the reactor's own outcome is unaffected.
		if c.logger != nil {
			c.logger.Warn("reactor: external identity conflict detected (non-fatal)",
				zap.String("collaborator_id", collabID.String()),
				zap.String("integration_instance_id", instanceID.String()),
				zap.String("external_id", ext.ExternalID),
			)
		}
		return
	}
	// Emit linked event (best-effort).
	if err := externalidentity.EmitEvent(ctx, c.db, repository.EventTypeExternalIdentityLinked, id,
		externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
			IdentityID:            id,
			CollaboratorID:        collabID,
			IntegrationInstanceID: instanceID,
			ExternalID:            ext.ExternalID,
			ReLinked:              outcome == externalidentity.OutcomeReLinked,
			LinkedAt:              time.Now().UTC(),
			ExternalMetadata:      ext.ExternalMetadata,
		})); err != nil && c.logger != nil {
		c.logger.Warn("reactor: external identity emit event failed (non-fatal)",
			zap.String("identity_id", id.String()),
			zap.Error(err),
		)
	}
}

// persistTeamProvisioning upserts the extracted team mirror metadata.
// All errors are logged and swallowed — the reaction has already
// succeeded; failing to write the log row would not undo the external
// resource. The reconcile cron will pick the gap up next tick if needed.
func (c *rabbitmqReactorCaller) persistTeamProvisioning(
	ctx context.Context,
	integrationInstanceID string,
	input map[string]any,
	ext teamprovisioning.Extracted,
	eventType string,
) {
	teamIDStr, _ := input["id"].(string)
	if strings.TrimSpace(teamIDStr) == "" {
		return
	}
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return
	}
	instanceID, err := uuid.Parse(integrationInstanceID)
	if err != nil {
		return
	}
	if _, err := repository.UpsertTeamProvisioningLog(ctx, c.db, model.UpsertTeamProvisioningLogRequest{
		TeamID:                teamID,
		IntegrationInstanceID: instanceID,
		ExternalID:            ext.ExternalID,
		ExternalMetadata:      ext.ExternalMetadata,
		LastEventType:         eventType,
	}); err != nil {
		if c.logger != nil {
			c.logger.Warn("reactor: persist team_provisioning_log failed (non-fatal)",
				zap.String("team_id", teamIDStr),
				zap.String("integration_instance_id", integrationInstanceID),
				zap.Error(err))
		}
	}
}

// embedTeamProvisioned reads team_provisioning_log for the (team, instance)
// pair the reaction targets, and injects the row under
// input._context.team_provisioned. Mirror of EmbedIntoInput from
// externalidentity. No-op when the reaction is not a team.* event, or
// when no log row exists yet (first-time team.created).
//
// Note: this dispatcher only sees `capability` (e.g. on_team_updated), not
// the raw event_type. We treat the on_team_* prefix as the team-family
// marker.
func (c *rabbitmqReactorCaller) embedTeamProvisioned(
	ctx context.Context,
	capability string,
	integrationInstanceID string,
	input map[string]any,
) {
	if !strings.HasPrefix(capability, "on_team_") {
		return
	}
	teamIDStr, _ := input["id"].(string)
	if strings.TrimSpace(teamIDStr) == "" {
		return
	}
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return
	}
	instanceID, err := uuid.Parse(integrationInstanceID)
	if err != nil {
		return
	}

	row, err := repository.GetTeamProvisioningLog(ctx, c.db, teamID, instanceID)
	if err != nil || row.ExternalID == "" {
		return // no log row yet — adapter will create from scratch
	}

	ctxBlock, _ := input["_context"].(map[string]any)
	if ctxBlock == nil {
		ctxBlock = map[string]any{}
		input["_context"] = ctxBlock
	}
	tp := map[string]any{
		"external_id": row.ExternalID,
	}
	if len(row.ExternalMetadata) > 0 && string(row.ExternalMetadata) != "null" {
		var meta map[string]any
		if json.Unmarshal(row.ExternalMetadata, &meta) == nil && meta != nil {
			tp["external_metadata"] = meta
		}
	}
	ctxBlock["team_provisioned"] = tp
}

func envDurOrDefault(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func envIntOrDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
