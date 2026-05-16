package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/manifestsync"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("manifest-sync", bootstrapManifestSync, 75)
}

// bootstrapManifestSync starts the manifest_sync.Runner: event-driven
// (in-process Notify channel) + cron safety-net.
//
// Controlled by:
//
//	MANIFEST_SYNC_ENABLED          — "true" (default) or "false" to disable
//	MANIFEST_SYNC_INTERVAL         — cron cadence (e.g. "1h"). Default 1h
//	MANIFEST_SYNC_DESCRIBE_TIMEOUT — per-RPC timeout (e.g. "10s"). Default 10s
func bootstrapManifestSync(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	conn, ok := RabbitMQ(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	deps := &productionDeps{
		db:              db,
		conn:            conn,
		describeTimeout: envDurOrDefault("MANIFEST_SYNC_DESCRIBE_TIMEOUT", 10*time.Second),
	}

	r := &manifestsync.Runner{
		Deps:             deps,
		CronInterval:     envDurOrDefault("MANIFEST_SYNC_INTERVAL", 1*time.Hour),
		EnumerateTypeIDs: deps.enumerateAllIntegrationTypeIDs,
	}

	go func() {
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("manifest_sync runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	if logger != nil {
		logger.Info("manifest sync addon started",
			zap.Duration("cron_interval", r.CronInterval),
			zap.Duration("describe_timeout", deps.describeTimeout),
		)
	}
	return nil
}

// productionDeps wires manifestsync.Deps to real Postgres + the existing
// describe transport in controllers/message.
type productionDeps struct {
	db              *sql.DB
	conn            *amqp.Connection
	describeTimeout time.Duration
}

func (p *productionDeps) Now() time.Time { return time.Now().UTC() }

func (p *productionDeps) GetIntegrationType(ctx context.Context, typeID uuid.UUID) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
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

func (p *productionDeps) ListInstances(ctx context.Context, typeID uuid.UUID) ([]model.Manifest, []model.IntegrationInstanceManifestSpec, error) {
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

func (p *productionDeps) InvokeDescribe(
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

func (p *productionDeps) ApplyManifestVersion(ctx context.Context, doc model.ManifestDocument) (model.Manifest, error) {
	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("compute manifest checksum: %w", err)
	}
	return repository.CreateManifestVersion(ctx, p.db, doc, checksum)
}

func (p *productionDeps) EmitEvent(ctx context.Context, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction for emit event: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// AggregateType derived from eventType prefix (everything before the first ".")
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

func (p *productionDeps) enumerateAllIntegrationTypeIDs(ctx context.Context) ([]uuid.UUID, error) {
	all, err := repository.ListManifests(ctx, p.db, model.ListManifestFilters{
		Kind:       "integration_type",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list integration_type manifests: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(all))
	for _, m := range all {
		ids = append(ids, m.ID)
	}
	return ids, nil
}
