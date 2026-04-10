package message

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const defaultIntegrationRuntimeMonitorInterval = 60 * time.Second

// StartIntegrationRuntimeMonitor runs a background sweep that refreshes integration type handshake state.
func StartIntegrationRuntimeMonitor(
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
) context.CancelFunc {
	if interval <= 0 {
		interval = defaultIntegrationRuntimeMonitorInterval
	}

	ctx, cancel := context.WithCancel(context.Background())
	go runIntegrationRuntimeMonitor(ctx, conn, db, logger, interval)
	return cancel
}

func runIntegrationRuntimeMonitor(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
) {
	runIntegrationRuntimeMonitorSweep(ctx, conn, db, logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runIntegrationRuntimeMonitorSweep(ctx, conn, db, logger)
		}
	}
}

func runIntegrationRuntimeMonitorSweep(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		if logger != nil {
			logger.Warn("integration runtime monitor failed to list integration instances", zap.Error(err))
		}
		return
	}

	for _, manifestRecord := range manifests {
		instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(manifestRecord.Spec)
		if err != nil {
			recordErr := fmt.Errorf(
				"parse integration_instance %s/%s for runtime monitor: %w",
				manifestRecord.Metadata.Namespace,
				manifestRecord.Metadata.Name,
				err,
			)
			if logger != nil {
				logger.Warn("integration runtime monitor found invalid integration_instance manifest", zap.Error(recordErr))
			}
			continue
		}

		if err := hydrateIntegrationInstanceSecrets(ctx, db, &instanceSpec); err != nil {
			if logger != nil {
				logger.Warn(
					"integration runtime monitor failed to hydrate integration instance secrets",
					zap.String("namespace", manifestRecord.Metadata.Namespace),
					zap.String("name", manifestRecord.Metadata.Name),
					zap.Error(err),
				)
			}
			continue
		}

		typeManifest, err := resolveManifestForKind(
			ctx,
			db,
			"integration_type",
			instanceSpec.TypeRef.ManifestID,
			instanceSpec.TypeRef.Namespace,
			instanceSpec.TypeRef.Name,
			instanceSpec.TypeRef.Version,
		)
		if err != nil {
			if logger != nil {
				logger.Warn(
					"integration runtime monitor failed to resolve integration type",
					zap.String("namespace", manifestRecord.Metadata.Namespace),
					zap.String("name", manifestRecord.Metadata.Name),
					zap.Error(err),
				)
			}
			continue
		}

		typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
		if err != nil {
			if logger != nil {
				logger.Warn(
					"integration runtime monitor found invalid integration_type manifest",
					zap.String("type_namespace", typeManifest.Metadata.Namespace),
					zap.String("type_name", typeManifest.Metadata.Name),
					zap.Error(err),
				)
			}
			continue
		}
		if err := manifestengine.ValidateHydratedIntegrationInstanceInputs(instanceSpec, typeSpec); err != nil {
			if logger != nil {
				logger.Warn(
					"integration runtime monitor found invalid hydrated integration inputs",
					zap.String("namespace", manifestRecord.Metadata.Namespace),
					zap.String("name", manifestRecord.Metadata.Name),
					zap.Error(err),
				)
			}
			continue
		}

		if err := verifyResolvedIntegrationType(
			ctx,
			conn,
			db,
			manifestRecord,
			typeManifest,
			instanceSpec,
			typeSpec,
		); err != nil && logger != nil {
			logger.Warn(
				"integration runtime monitor handshake failed",
				zap.String("namespace", manifestRecord.Metadata.Namespace),
				zap.String("name", manifestRecord.Metadata.Name),
				zap.Error(err),
			)
		}
	}
}
